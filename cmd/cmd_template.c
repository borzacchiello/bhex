#include "cmd_arg_handler.h"
#include "cmd_template.h"
#include "../tengine/tengine.h"

#include <sys/stat.h>
#include <display.h>
#include <dirent.h>
#include <string.h>
#include <alloc.h>
#include <log.h>
#include "cmd.h"

#define HINT_STR "[/l] <name or file>"
#define LIST_SET 0

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
    display_printf(
        "\ntemplate: parse the file at current offset using a 'bhe' "
        "template file\n"
        "\n"
        "  t" HINT_STR "\n"
        "     l: list available templates and structs\n"
        "\n"
        "  name: the name of the pre-loaded template/struct to use, or a "
        "path to a template file, or a filter if in list mode\n"
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
    char* arg_str = NULL;
    if (handle_args(pc, 1, 0, &arg_str) != 0)
        return COMMAND_INVALID_ARG;

    int list = -1;
    if (handle_mods(pc, "l", &list) != 0)
        return COMMAND_INVALID_MOD;

    if (list == LIST_SET) {
        if (arg_str)
            display_printf("\n > Filtering using '%s' <\n", arg_str);

        display_printf("\nAvailable templates:\n");
        for (const char* key = map_first(ctx->templates); key != NULL;
             key             = map_next(ctx->templates, key)) {
            if (!arg_str || strstr(key, arg_str) != NULL) {
                display_printf("  %s\n", key);
            }
        }

        display_printf("\nAvailable template structs:\n");
        for (const char* key = map_first(ctx->templates); key != NULL;
             key             = map_next(ctx->templates, key)) {
            ASTCtx* ast = map_get(ctx->templates, key);
            for (const char* str = map_first(ast->structs); str != NULL;
                 str             = map_next(ast->structs, str)) {
                if (!arg_str || strstr(key, arg_str) != NULL ||
                    strstr(str, arg_str) != NULL) {
                    display_printf("  %s.%s\n", key, str);
                }
            }
        }
        display_printf("\n");
        return COMMAND_OK;
    }

    if (arg_str == NULL)
        return COMMAND_INVALID_ARG;

    u64_t initial_off = fb->off;
    char* bhe         = arg_str;
    int   r           = COMMAND_INVALID_ARG;

    if (file_exists(bhe)) {
        // Template file
        if (TEngine_process_filename(fb, bhe) != 0) {
            error("template execution failed");
            goto end;
        }
        display_printf("\n");
        r = COMMAND_OK;
        goto end;
    }
    if (map_contains(ctx->templates, bhe)) {
        // Pre-loaded template
        display_printf("\n");
        ASTCtx* ast = map_get(ctx->templates, bhe);
        if (TEngine_process_ast(fb, ast) == 0) {
            display_printf("\n");
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

    display_printf("\n");
    ASTCtx* ast = map_get(ctx->templates, tname);
    if (TEngine_process_ast_struct(fb, ast, sname) != 0)
        goto err;
    display_printf("\n");

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
    cmd->hint  = HINT_STR;

    cmd->dispose = (void (*)(void*))templatecmd_dispose;
    cmd->help    = templatecmd_help;
    cmd->exec = (int (*)(void*, FileBuffer*, ParsedCommand*))templatecmd_exec;

    return cmd;
}
