#include "cmd_commit.h"

#include <alloc.h>

static void commitcmd_dispose(void* obj) { return; }

static void commitcmd_help(void* obj)
{
    printf("commit all the writes to file\n\n");
}

static int commitcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    if (pc->args.size != 0)
        return COMMAND_UNSUPPORTED_ARG;
    if (pc->cmd_modifiers.size != 0)
        return COMMAND_UNSUPPORTED_MOD;

    fb_commit(fb);
    return COMMAND_OK;
}

Cmd* commitcmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "commit";
    cmd->alias = "c";
    cmd->hint  = NULL;

    cmd->dispose = commitcmd_dispose;
    cmd->help    = commitcmd_help;
    cmd->exec    = commitcmd_exec;

    return cmd;
}
