#include "cmd_delete.h"

#include <util/byte_to_num.h>
#include <alloc.h>

static void deletecmd_dispose(void* obj) { return; }

static void deletecmd_help(void* obj)
{
    printf("\ndelete: delete bytes at current offset\n"
           "\n"
           "  d <len>\n"
           "\n");
}

static int deletecmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    if (pc->args.size != 1)
        return COMMAND_UNSUPPORTED_ARG;
    if (pc->cmd_modifiers.size != 0)
        return COMMAND_UNSUPPORTED_MOD;

    char* len_str = (char*)pc->args.head->data;
    u64_t len;
    if (!str_to_uint64(len_str, &len))
        return COMMAND_INVALID_ARG;

    if (!fb_delete(fb, len))
        return COMMAND_INVALID_ARG;
    return COMMAND_OK;
}

Cmd* deletecmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "delete";
    cmd->alias = "d";
    cmd->hint  = NULL;

    cmd->dispose = deletecmd_dispose;
    cmd->help    = deletecmd_help;
    cmd->exec    = deletecmd_exec;

    return cmd;
}
