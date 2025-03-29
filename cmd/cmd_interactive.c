#include "cmd_interactive.h"
#include "cmd.h"
#include "tui.h"

#include <util/byte_to_str.h>
#include <util/math.h>
#include <hash/md5.h>
#include <display.h>
#include <string.h>
#include <alloc.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

static void interactivecmd_dispose(void* obj) {}

static void interactivecmd_help(void* obj)
{
    display_printf("\ninteractive: run an interactive session\n");
}

static int interactivecmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    if (pc->args.size != 0)
        return COMMAND_UNSUPPORTED_ARG;
    if (pc->cmd_modifiers.size != 0)
        return COMMAND_UNSUPPORTED_MOD;

    tui_enter_loop(fb);
    puts("");
    return COMMAND_OK;
}

Cmd* interactivecmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "interactive";
    cmd->alias = "int";
    cmd->hint  = NULL;

    cmd->dispose = interactivecmd_dispose;
    cmd->help    = interactivecmd_help;
    cmd->exec    = interactivecmd_exec;

    return cmd;
}
