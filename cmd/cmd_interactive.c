// Copyright (c) 2022-2026, bageyelet

#include "cmd_interactive.h"
#include "cmd.h"
#include "cmd_arg_handler.h"
#include "tui.h"

#include <display.h>
#include <alloc.h>

#define HINT_STR      "[/n]"
#define NO_COLORS_SET 0

static void interactivecmd_dispose(void* obj) {}

static void interactivecmd_help(void* obj)
{
    display_printf("interactive: run an interactive session\n"
                   "\n"
                   "  tui" HINT_STR "\n"
                   "     n: do not use colors\n"
                   "\n"
                   "  press CTRL-H in the editor to list the key bindings\n");
}

static int interactivecmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    if (pc->args.size != 0)
        return COMMAND_UNSUPPORTED_ARG;

    int no_colors = -1;
    if (handle_mods(pc, "n", &no_colors) != 0)
        return COMMAND_INVALID_MOD;

    tui_enter_loop(fb, no_colors == NO_COLORS_SET);
    puts("");
    return COMMAND_OK;
}

Cmd* interactivecmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "interactive";
    cmd->alias = "tui";
    cmd->hint  = HINT_STR;

    cmd->dispose = interactivecmd_dispose;
    cmd->help    = interactivecmd_help;
    cmd->exec    = interactivecmd_exec;

    return cmd;
}
