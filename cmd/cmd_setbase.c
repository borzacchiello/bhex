// Copyright (c) 2022-2026, bageyelet

#include "cmd_setbase.h"

#include <util/byte_to_num.h>
#include <display.h>
#include <alloc.h>

#define HINT_STR " <base>"

static void setbasecmd_dispose(void* obj) { (void)obj; }

static void setbasecmd_help(void* obj)
{
    display_printf(
        "setbase: set or display the base address\n"
        "\n"
        "  sb" HINT_STR "\n"
        "\n"
        "  base: the new base address (if omitted, display current base)\n"
        "\n");
}

static int setbasecmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    (void)obj;

    if (pc->cmd_modifiers.size != 0)
        return COMMAND_UNSUPPORTED_MOD;

    if (pc->args.size == 0) {
        display_printf("0x%llx\n", fb->base_addr);
        return COMMAND_OK;
    }

    if (pc->args.size != 1)
        return COMMAND_UNSUPPORTED_ARG;

    const char* arg = (const char*)pc->args.head->data;
    u64_t       base;
    if (!str_to_uint64(arg, &base))
        return COMMAND_INVALID_ARG;

    fb->base_addr = base;
    return COMMAND_OK;
}

Cmd* setbasecmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "setbase";
    cmd->alias = "sb";
    cmd->hint  = HINT_STR;

    cmd->dispose = setbasecmd_dispose;
    cmd->help    = setbasecmd_help;
    cmd->exec    = setbasecmd_exec;

    return cmd;
}
