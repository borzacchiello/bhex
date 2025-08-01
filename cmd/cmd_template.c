#include "cmd_arg_handler.h"
#include "cmd_template.h"
#include "../tengine/vm.h"

#include <sys/stat.h>
#include <display.h>
#include <dirent.h>
#include <string.h>
#include <alloc.h>
#include <log.h>
#include "cmd.h"

#define HINT_STR       "[/l/i/x] <name or file>"
#define MODE_LIST      0
#define MODE_INTERPRET 1
#define XML_SET        0

static const char* search_folders[]       = {"/usr/local/share/bhex/templates",
                                             "../templates", ".", NULL};
static const char* search_folders_empty[] = {NULL};

// just for testing purposes
int template_skip_search = 0;

typedef struct TemplateCtx {
    TEngineVM* vm;
} TemplateCtx;

static void templatecmd_help(void* obj)
{
    display_printf(
        "\ntemplate: parse the file at current offset using a 'bhe' "
        "template file\n"
        "\n"
        "  t" HINT_STR "\n"
        "     l: list available templates and structs\n"
        "     x: output in XML\n"
        "     i: interpret inline code\n"
        "\n"
        "  arg: its meaning depends on the mode. It could be\n"
        "       - the name of the pre-loaded template/struct/proc to use\n"
        "       - a path to a template file\n"
        "       - a filter (if in list mode)\n"
        "       - inline bhex code (if in interpret mode)\n"
        "\n");
}

static void templatecmd_dispose(TemplateCtx* ctx)
{
    tengine_vm_destroy(ctx->vm);
    bhex_free(ctx);
    return;
}

static int file_exists(const char* path)
{
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISREG(path_stat.st_mode);
}

static const char* print_filter = NULL;
static void        templates_print_cb(const char* name, ASTCtx* ast)
{
    if (ast->proc != NULL &&
        (!print_filter || strstr(name, print_filter) != NULL)) {
        display_printf("  %s\n", name);
    }
}

static void composite_print_cb(const char* name, const char* elname,
                               ASTCtx* ast)
{
    if (!print_filter || strstr(name, print_filter) != NULL ||
        strstr(elname, print_filter) != NULL) {
        display_printf("  %s.%s\n", name, elname);
    }
}

static int templatecmd_exec(TemplateCtx* ctx, FileBuffer* fb, ParsedCommand* pc)
{
    char* arg_str = NULL;
    if (handle_args(pc, 1, 0, &arg_str) != 0)
        return COMMAND_INVALID_ARG;

    int mode = -1;
    int xml  = -1;
    if (handle_mods(pc, "l,i|x", &mode, &xml) != 0)
        return COMMAND_INVALID_MOD;

    if (mode == MODE_LIST) {
        print_filter = arg_str;
        if (print_filter)
            display_printf("\n > Filtering using '%s' <\n", arg_str);

        display_printf("\nAvailable templates:\n");
        tengine_vm_iter_templates(ctx->vm, templates_print_cb);
        display_printf("\nAvailable template structs:\n");
        tengine_vm_iter_structs(ctx->vm, composite_print_cb);
        display_printf("\nAvailable template named procs:\n");
        tengine_vm_iter_named_procs(ctx->vm, composite_print_cb);

        display_printf("\n");
        return COMMAND_OK;
    }

    if (arg_str == NULL)
        return COMMAND_INVALID_ARG;

    if (xml == XML_SET)
        tengine_vm_set_fmt_type(FMT_XML);

    u64_t initial_off = fb->off;
    char* bhe         = arg_str;
    int   r           = COMMAND_SILENT_ERROR;

    if (mode == MODE_INTERPRET) {
        if (tengine_vm_process_string(ctx->vm, fb, arg_str) != 0) {
            goto end;
        }
        r = COMMAND_OK;
        goto end;
    }

    if (file_exists(bhe)) {
        // Template file
        if (tengine_vm_process_file(ctx->vm, fb, bhe) != 0) {
            goto end;
        }
        r = COMMAND_OK;
        goto end;
    }

    if (tengine_vm_has_template(ctx->vm, bhe)) {
        // Template name
        if (tengine_vm_process_bhe(ctx->vm, fb, bhe) != 0) {
            goto end;
        }
        r = COMMAND_OK;
        goto end;
    }

    // Pre-loaded struct or named proc
    char* tname = strtok(bhe, ".");
    if (tname == NULL)
        goto err;

    char* sname = strtok(NULL, ".");
    if (sname == NULL)
        goto err;

    if (tengine_vm_has_bhe_struct(ctx->vm, tname, sname)) {
        if (tengine_vm_process_bhe_struct(ctx->vm, fb, tname, sname) != 0) {
            goto end;
        }
        display_printf("\n");
    } else if (tengine_vm_has_bhe_proc(ctx->vm, tname, sname)) {
        display_printf("\n");
        if (tengine_vm_process_bhe_proc(ctx->vm, fb, tname, sname) != 0) {
            goto end;
        }
    } else {
        goto err;
    }

    r = COMMAND_OK;
end:
    display_printf("\n");
    fb_seek(fb, initial_off);
    tengine_vm_set_fmt_type(FMT_TERM);
    return r;

err:
    error("'%s' is not a valid template/struct/proc name or filename", bhe);
    goto end;
}

Cmd* templatecmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    TemplateCtx* ctx = bhex_calloc(sizeof(TemplateCtx));
    ctx->vm    = tengine_vm_create(template_skip_search ? search_folders_empty
                                                        : search_folders);
    cmd->obj   = ctx;
    cmd->name  = "template";
    cmd->alias = "t";
    cmd->hint  = HINT_STR;

    cmd->dispose = (void (*)(void*))templatecmd_dispose;
    cmd->help    = templatecmd_help;
    cmd->exec = (int (*)(void*, FileBuffer*, ParsedCommand*))templatecmd_exec;

    return cmd;
}
