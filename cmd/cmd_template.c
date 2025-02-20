#include "cmd_template.h"

#include <sys/stat.h>
#include <dirent.h>
#include <string.h>

#include "../tengine/tengine.h"
#include <alloc.h>
#include <log.h>
#include "cmd.h"

static const char* search_folders[] = {"/usr/local/share/bhex/templates",
                                       "../templates", "."};

typedef struct TemplateCtx {
    map* templates;
} TemplateCtx;

static void templatecmd_dispose(TemplateCtx* ctx)
{
    map_destroy(ctx->templates);
    bhex_free(ctx);
    return;
}

static void templatecmd_help(void* obj)
{
    printf("\ntemplate: parse the file at current offset using a 'bhe' "
           "template file\n"
           "\n"
           "  t[/l/ls] <name>\n"
           "     l:  list available templates\n"
           "     ls: list available structs\n"
           "\n"
           "  name: the name of the pre-loaded template/struct to use, of a "
           "path to a template file\n"
           "\n");
}

static int file_exists(const char* path)
{
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISREG(path_stat.st_mode);
}

static int templatecmd_exec(TemplateCtx* ctx, FileBuffer* fb, ParsedCommand* pc)
{
    int listed_templates = 0;
    int listed_structs   = 0;

    LLNode* curr = pc->cmd_modifiers.head;
    while (curr) {
        const char* mod = (const char*)curr->data;
        if (strcmp(mod, "l") == 0) {
            if (listed_templates) {
                error("l modifier is specified two times");
                return 1;
            }
            printf("\nAvailable templates:\n");
            for (const char* key = map_first(ctx->templates); key != NULL;
                 key             = map_next(ctx->templates, key))
                printf("  %s\n", key);
            listed_templates = 1;
        } else if (strcmp(mod, "ls") == 0) {
            if (listed_structs) {
                error("lh modifier is specified two times");
                return 1;
            }
            printf("\nAvailable template structs:\n");
            for (const char* key = map_first(ctx->templates); key != NULL;
                 key             = map_next(ctx->templates, key)) {
                ASTCtx* ast = map_get(ctx->templates, key);
                for (const char* str = map_first(ast->structs); str != NULL;
                     str             = map_next(ast->structs, str)) {
                    printf("  %s.%s\n", key, str);
                }
            }
            listed_structs = 1;
        }
        curr = curr->next;
    }
    if (listed_templates || listed_structs) {
        if (pc->args.size != 0)
            return COMMAND_INVALID_ARG;
        printf("\n");
        return COMMAND_OK;
    }

    if (pc->args.size != 1)
        return COMMAND_INVALID_ARG;

    u64_t initial_off = fb->off;
    char* bhe         = (char*)pc->args.head->data;
    int   r           = COMMAND_INVALID_ARG;

    if (file_exists(bhe)) {
        // Template file
        if (TEngine_process_filename(fb, bhe) != 0) {
            error("template execution failed");
            goto end;
        }
        printf("\n");
        r = COMMAND_OK;
        goto end;
    }
    if (map_contains(ctx->templates, bhe)) {
        // Pre-loaded template
        printf("\n");
        ASTCtx* ast = map_get(ctx->templates, bhe);
        if (TEngine_process_ast(fb, ast) == 0) {
            printf("\n");
            r = COMMAND_OK;
        }
        goto end;
    }
    // Pre-loaded struct
    char* tname = strtok(bhe, ".");
    if (tname == NULL)
        goto err;

    if (!map_contains(ctx->templates, tname))
        goto err;

    char* sname = strtok(NULL, ".");
    if (sname == NULL)
        goto err;

    if (strtok(NULL, ".") != NULL)
        goto err;

    printf("\n");
    ASTCtx* ast = map_get(ctx->templates, tname);
    if (TEngine_process_ast_struct(fb, ast, sname) != 0)
        goto err;
    printf("\n");

    r = COMMAND_OK;

end:
    fb_seek(fb, initial_off);
    return r;

err:
    error("'%s' is not a valid template/struct name or filename", bhe);
    goto end;
}

Cmd* templatecmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    TemplateCtx* ctx = bhex_calloc(sizeof(TemplateCtx));
    ctx->templates   = map_create();
    map_set_dispose(ctx->templates, (void (*)(void*))ASTCtx_delete);

    char tmp[1024];

    // Iterate over the default templates directories
    for (u64_t i = 0; i < sizeof(search_folders) / sizeof(const char*); ++i) {
        const char* dirpath = search_folders[i];
        DIR*        dir     = opendir(dirpath);
        if (dir == NULL)
            continue;

        struct dirent* entry;
        while ((entry = readdir(dir)) != NULL) {
            // look for "*.bhe" files
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0)
                continue;
            size_t d_namelen = strlen(entry->d_name);
            if (d_namelen < 4 ||
                strcmp(entry->d_name + (d_namelen - 4), ".bhe") != 0)
                continue;

            memset(tmp, 0, sizeof(tmp));
            snprintf(tmp, sizeof(tmp) - 1, "%s/%s", dirpath, entry->d_name);

            // Remove extension
            entry->d_name[d_namelen - 4] = '\0';
            if (map_contains(ctx->templates, entry->d_name)) {
                warning("template '%s' already loaded, skipping file '%s'",
                        entry->d_name, tmp);
                continue;
            }

            ASTCtx* ast = TEngine_parse_filename(tmp);
            if (ast == NULL)
                // Invalid bhe file
                continue;

            // Remove extension
            entry->d_name[d_namelen - 4] = '\0';
            map_set(ctx->templates, entry->d_name, ast);
            // info("loaded template '%s' from '%s'", entry->d_name, tmp);
        }
        closedir(dir);
    }

    cmd->obj   = ctx;
    cmd->name  = "template";
    cmd->alias = "t";
    cmd->hint  = "[/l/ls] <name or file>";

    cmd->dispose = (void (*)(void*))templatecmd_dispose;
    cmd->help    = templatecmd_help;
    cmd->exec = (int (*)(void*, FileBuffer*, ParsedCommand*))templatecmd_exec;

    return cmd;
}
