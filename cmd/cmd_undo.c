#include "cmd_undo.h"

#include "../alloc.h"
#include "../log.h"

static void undocmd_dispose(void* obj) { return; }

static void undocmd_help(void* obj) { printf("undo the last write\n\n"); }

static int undocmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    if (pc->args.size != 0)
        return COMMAND_UNSUPPORTED_ARG;
    if (pc->cmd_modifiers.size != 0)
        return COMMAND_UNSUPPORTED_MOD;

    if (!fb_undo_last(fb))
        warning("nothing to remove");
    return COMMAND_OK;
}

Cmd* undocmd_create()
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "undo";
    cmd->alias = "u";

    cmd->dispose = undocmd_dispose;
    cmd->help    = undocmd_help;
    cmd->exec    = undocmd_exec;

    return cmd;
}
