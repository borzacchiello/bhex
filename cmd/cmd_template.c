#include "cmd_template.h"

#include <sys/stat.h>
#include <dirent.h>
#include <string.h>

#include "../tengine/tengine.h"
#include "../alloc.h"
#include "../log.h"
#include "cmd.h"

static const char* search_folders[] = {"/usr/local/share/bhex/templates",
                                       "../templates", "./templates"};

typedef struct TemplateCtx {
    map* templates;
} TemplateCtx;

static void templatecmd_dispose(TemplateCtx* ctx)
{
    map_destroy(ctx->templates);
    return;
}

static void templatecmd_help(void* obj)
{
    printf("\ntemplate: parse the file at current offset using a 'bhe' "
           "template file\n"
           "\n"
           "  t[/l] <template>\n"
           "     l:  list available templates\n"
           "\n"
           "  template: the name of the template to use or a path to a "
           "template file\n"
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
    if (pc->cmd_modifiers.size > 1)
        return COMMAND_UNSUPPORTED_MOD;

    if (pc->cmd_modifiers.size == 1 &&
        strcmp((char*)pc->cmd_modifiers.head->data, "l") == 0) {
        if (pc->args.size != 0)
            return COMMAND_INVALID_ARG;

        printf("\nAvailable templates:\n");
        for (const char* key = map_first(ctx->templates); key != NULL;
             key             = map_next(ctx->templates, key))
            printf("  %s\n", key);
        printf("\n");
        return COMMAND_OK;
    }

    if (pc->args.size != 1)
        return COMMAND_INVALID_ARG;

    u64_t initial_off = fb->off;
    char* bhe         = (char*)pc->args.head->data;
    int   r           = COMMAND_INVALID_ARG;

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

    if (!file_exists(bhe)) {
        error("'%s' is not a valid template name or filename", bhe);
        goto end;
    }

    if (TEngine_process_filename(fb, bhe) != 0) {
        error("template execution failed");
        goto end;
    }
    printf("\n");
    r = COMMAND_OK;

end:
    fb_seek(fb, initial_off);
    return r;
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
            if (entry->d_namlen < 4 ||
                strcmp(entry->d_name + (entry->d_namlen - 4), ".bhe") != 0)
                continue;

            memset(tmp, 0, sizeof(tmp));
            snprintf(tmp, sizeof(tmp) - 1, "%s/%s", dirpath, entry->d_name);

            // Remove extension
            entry->d_name[entry->d_namlen - 4] = '\0';
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
            entry->d_name[entry->d_namlen - 4] = '\0';
            map_set(ctx->templates, entry->d_name, ast);
            info("loaded template '%s' from '%s'", entry->d_name, tmp);
        }
        closedir(dir);
    }

    cmd->obj   = ctx;
    cmd->name  = "template";
    cmd->alias = "t";

    cmd->dispose = (void (*)(void*))templatecmd_dispose;
    cmd->help    = templatecmd_help;
    cmd->exec = (int (*)(void*, FileBuffer*, ParsedCommand*))templatecmd_exec;

    return cmd;
}
