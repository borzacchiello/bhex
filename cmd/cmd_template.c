#include "cmd_template.h"

#include <sys/stat.h>
#include <string.h>

#include "../tengine/tengine.h"
#include "../alloc.h"
#include "../log.h"

static void templatecmd_dispose(void* obj) { return; }

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

static int templatecmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    if (pc->cmd_modifiers.size > 1)
        return COMMAND_UNSUPPORTED_MOD;

    if (pc->cmd_modifiers.size == 1 &&
        strcmp((char*)pc->cmd_modifiers.head->data, "l") == 0) {
        if (pc->args.size != 0)
            return COMMAND_INVALID_ARG;

        // list the templates
        printf("\nAvailable templates:\n");
        // TODO: implement it
        printf("\n");
        return COMMAND_OK;
    }

    if (pc->args.size != 1)
        return COMMAND_INVALID_ARG;

    u64_t initial_off = fb->off;
    char* bhe         = (char*)pc->args.head->data;
    int   r           = COMMAND_INVALID_ARG;

    TEngine e;
    TEngine_init(&e);

    if (!file_exists(bhe)) {
        error("'%s' is not a valid filename", bhe);
        goto end;
    }

    printf("\n");
    if (TEngine_process_filename(&e, fb, bhe) != 0) {
        error("template execution failed");
        goto end;
    }
    printf("\n");
    r = COMMAND_OK;

end:
    fb_seek(fb, initial_off);
    TEngine_deinit(&e);
    return r;
}

Cmd* templatecmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "template";
    cmd->alias = "t";

    cmd->dispose = templatecmd_dispose;
    cmd->help    = templatecmd_help;
    cmd->exec    = templatecmd_exec;

    return cmd;
}
