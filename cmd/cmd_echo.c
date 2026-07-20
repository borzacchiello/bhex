// Copyright (c) 2022-2026, bageyelet

#include "cmd_echo.h"
#include "cmd_arg_handler.h"

#include <display.h>
#include <string.h>
#include <alloc.h>
#include <util/byte_to_num.h>

#define FMT_DEFAULT 0
#define FMT_HEX     1
#define FMT_DEC     2

static void echocmd_dispose(void* obj) { (void)obj; }

static void echocmd_help(void* obj)
{
    display_printf(
        "echo: print arguments to stdout\n"
        "  echo [/x|/d] <arg1> [arg2] ...\n"
        "    /x: force hexadecimal output for numbers (default)\n"
        "    /d: force decimal output for numbers\n"
        "  Expressions in backticks are evaluated before printing.\n");
}

static int echocmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    (void)obj;
    (void)fb;

    int fmt = FMT_DEFAULT;
    if (handle_mods(pc, "x,d", &fmt) != 0)
        return COMMAND_INVALID_MOD;
    int use_hex = (fmt != 1); // default or /x -> hex; /d -> dec

    ll_node_t* node  = pc->args.head;
    int        first = 1;
    while (node) {
        const char* arg = (const char*)node->data;
        if (!first)
            display_printf(" ");

        u64_t num;
        if (str_to_uint64(arg, &num)) {
            // Numeric argument, print in the requested format
            if (use_hex)
                display_printf("0x%llx", num);
            else
                display_printf("%llu", num);
        } else {
            // Non-numeric, print as-is
            display_printf("%s", arg);
        }

        first = 0;
        node  = node->next;
    }
    display_printf("\n");
    return COMMAND_OK;
}

Cmd* echocmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "echo";
    cmd->alias = "ec";
    cmd->hint  = "[/x|/d] <args...>";

    cmd->dispose = echocmd_dispose;
    cmd->help    = echocmd_help;
    cmd->exec    = echocmd_exec;

    return cmd;
}
