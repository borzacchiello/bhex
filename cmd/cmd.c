// Copyright (c) 2022-2026, bageyelet

#include "cmd.h"

#include <display.h>
#include <string.h>
#include <alloc.h>
#include <color.h>

#include "cmd_assemble.h"
#include "cmd_checksum.h"
#include "cmd_commit.h"
#include "cmd_crc.h"
#include "cmd_delete.h"
#include "cmd_diff.h"
#include "cmd_disas.h"
#include "cmd_echo.h"
#include "cmd_entropy.h"
#include "cmd_export.h"
#include "cmd_findbase.h"
#include "cmd_hash.h"
#include "cmd_identify.h"
#include "cmd_import.h"
#include "cmd_info.h"
#include "cmd_interactive.h"
#include "cmd_isa_identify.h"
#include "cmd_print.h"
#include "cmd_search.h"
#include "cmd_seek.h"
#include "cmd_setbase.h"
#include "cmd_strings.h"
#include "cmd_template.h"
#include "cmd_transform.h"
#include "cmd_undo.h"
#include "cmd_write.h"

const char* cmdctx_err_to_string(int err)
{
    switch (err) {
        case COMMAND_OK:
            return "no error";
        case COMMAND_ERR_NO_SUCH_COMMAND:
            return "no such command";
        case COMMAND_INVALID_HELP_COMMAND:
            return "invalid help command";
        case COMMAND_UNSUPPORTED_MOD:
            return "unsupported cmd modifier";
        case COMMAND_UNSUPPORTED_ARG:
            return "unsupported cmd argument";
        case COMMAND_INVALID_MOD:
            return "invalid cmd modifier";
        case COMMAND_INVALID_ARG:
            return "invalid arg";
        case COMMAND_INTERNAL_ERROR:
            return "internal error";
        case COMMAND_FILE_WRITE_ERROR:
            return "file write error";
        case COMMAND_SILENT_ERROR:
            return "silent error";
        default:
            break;
    }
    return "unknown";
}

CmdContext* cmdctx_init(void)
{
    CmdContext* cc = bhex_malloc(sizeof(CmdContext));
    cc->commands   = ll_create();

    // Registered by name, in alphabetical order, and appended rather than
    // prepended: the list is walked as it is by 'help', by the completion and
    // by the hints, so keeping it sorted here is what keeps all three sorted.
    // A new command goes in its alphabetical place.
#ifndef DISABLE_KEYSTONE
    ll_add_tail(&cc->commands, (uptr_t)assemblecmd_create());
#endif
    ll_add_tail(&cc->commands, (uptr_t)checksumcmd_create());
    ll_add_tail(&cc->commands, (uptr_t)commitcmd_create());
    ll_add_tail(&cc->commands, (uptr_t)crccmd_create());
    ll_add_tail(&cc->commands, (uptr_t)deletecmd_create());
    ll_add_tail(&cc->commands, (uptr_t)diffcmd_create());
#ifndef DISABLE_CAPSTONE
    ll_add_tail(&cc->commands, (uptr_t)disascmd_create());
#endif
    ll_add_tail(&cc->commands, (uptr_t)echocmd_create());
    ll_add_tail(&cc->commands, (uptr_t)entropycmd_create());
    ll_add_tail(&cc->commands, (uptr_t)exportcmd_create());
    ll_add_tail(&cc->commands, (uptr_t)findbasecmd_create());
    ll_add_tail(&cc->commands, (uptr_t)hashcmd_create());
    ll_add_tail(&cc->commands, (uptr_t)identifycmd_create());
    ll_add_tail(&cc->commands, (uptr_t)importcmd_create());
    ll_add_tail(&cc->commands, (uptr_t)infocmd_create());
    ll_add_tail(&cc->commands, (uptr_t)interactivecmd_create());
    ll_add_tail(&cc->commands, (uptr_t)isa_identifycmd_create());
    ll_add_tail(&cc->commands, (uptr_t)printcmd_create());
    ll_add_tail(&cc->commands, (uptr_t)searchcmd_create());
    ll_add_tail(&cc->commands, (uptr_t)seekcmd_create());
    ll_add_tail(&cc->commands, (uptr_t)setbasecmd_create());
    ll_add_tail(&cc->commands, (uptr_t)stringscmd_create());
    ll_add_tail(&cc->commands, (uptr_t)templatecmd_create());
    ll_add_tail(&cc->commands, (uptr_t)transformcmd_create());
    ll_add_tail(&cc->commands, (uptr_t)undocmd_create());
    ll_add_tail(&cc->commands, (uptr_t)writecmd_create());
    return cc;
}

static void cmd_dispose(uptr_t o)
{
    Cmd* cmd = (Cmd*)o;
    cmd->dispose(cmd->obj);
    bhex_free(cmd);
}

void cmdctx_destroy(CmdContext* cmd)
{
    ll_clear(&cmd->commands, cmd_dispose);
    bhex_free(cmd);
}

static void print_cmd_entry(const char* name, const char* alias)
{
    display_printf("    %s%s%s %s[%s]%s\n", color_str(COLOR_CMD), name,
                   color_str(COLOR_RESET), color_str(COLOR_ALIAS), alias,
                   color_str(COLOR_RESET));
}

int cmd_help(CmdContext* cc)
{
    display_printf("\nAvailable commands:\n");

    // 'help' is answered by cmdctx_run() before the lookup, so it is not in
    // the list: it is printed where its name falls among the others
    int        help_printed = 0;
    ll_node_t* curr         = cc->commands.head;
    while (curr) {
        Cmd* cmd = (Cmd*)curr->data;
        if (!help_printed && strcmp(cmd->name, "help") > 0) {
            print_cmd_entry("help", "h");
            help_printed = 1;
        }
        print_cmd_entry(cmd->name, cmd->alias);
        curr = curr->next;
    }
    if (!help_printed)
        print_cmd_entry("help", "h");

    display_printf("\n");
    return COMMAND_OK;
}

int cmdctx_run(CmdContext* cc, ParsedCommand* pc, FileBuffer* fb)
{
    if (strcmp(pc->cmd, "help") == 0 || strcmp(pc->cmd, "h") == 0) {
        if (pc->print_help || pc->args.size != 0 || pc->cmd_modifiers.size != 0)
            return COMMAND_INVALID_HELP_COMMAND;
        return cmd_help(cc);
    }

    ll_node_t* curr = cc->commands.head;
    while (curr) {
        Cmd* cmd = (Cmd*)curr->data;
        if (strcmp(pc->cmd, cmd->name) == 0 ||
            strcmp(pc->cmd, cmd->alias) == 0) {
            if (pc->print_help) {
                cmd->help(cmd->obj);
                return COMMAND_OK;
            }
            return cmd->exec(cmd->obj, fb, pc);
        }
        curr = curr->next;
    }
    return COMMAND_ERR_NO_SUCH_COMMAND;
}
