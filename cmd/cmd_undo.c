#include "cmd.h"
#include "cmd_arg_handler.h"
#include "filebuffer.h"
#include "cmd_undo.h"

#include <display.h>
#include <alloc.h>
#include <log.h>

#define HINT_STR "[/a]"
#define ALL_SET  0

static void undocmd_dispose(void* obj) { return; }

static void undocmd_help(void* obj)
{
    display_printf("undo: undo the last write\n"
                   "\n"
                   "  u" HINT_STR "\n"
                   "     a: undo all\n");
}

static int undocmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    if (handle_args(pc, 0, 0) != 0)
        return COMMAND_INVALID_ARG;

    int all = -1;
    if (handle_mods(pc, "a", &all) != 0)
        return COMMAND_INVALID_MOD;

    if (fb->modifications.size == 0) {
        warning("nothing to remove");
        return COMMAND_OK;
    }

    if (all == ALL_SET) {
        fb_undo_all(fb);
        return COMMAND_OK;
    }

    if (!fb_undo_last(fb))
        warning("undo failed");
    return COMMAND_OK;
}

Cmd* undocmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "undo";
    cmd->alias = "u";
    cmd->hint  = NULL;

    cmd->dispose = undocmd_dispose;
    cmd->help    = undocmd_help;
    cmd->exec    = undocmd_exec;

    return cmd;
}
