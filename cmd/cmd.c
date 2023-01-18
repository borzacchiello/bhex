#include <string.h>

#include "cmd.h"
#include "../alloc.h"

#include "cmd_info.h"
#include "cmd_print.h"
#include "cmd_seek.h"
#include "cmd_write.h"
#include "cmd_undo.h"
#include "cmd_commit.h"
#include "cmd_template.h"
#include "cmd_search.h"
#include "cmd_strings.h"

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
        case COMMAND_INVALID_MODE:
            return "invalid cmd modifier";
        case COMMAND_INVALID_ARG:
            return "invalid arg";
        default:
            break;
    }
    return "unknown";
}

CmdContext* cmdctx_init()
{
    CmdContext* cc = bhex_malloc(sizeof(CmdContext));
    cc->commands   = ll_create();

    ll_add(&cc->commands, (uptr_t)commitcmd_create());
    ll_add(&cc->commands, (uptr_t)undocmd_create());
    ll_add(&cc->commands, (uptr_t)writecmd_create());
    ll_add(&cc->commands, (uptr_t)printcmd_create());
    ll_add(&cc->commands, (uptr_t)seekcmd_create());
    ll_add(&cc->commands, (uptr_t)templatecmd_create());
    ll_add(&cc->commands, (uptr_t)stringscmd_create());
    ll_add(&cc->commands, (uptr_t)searchcmd_create());
    ll_add(&cc->commands, (uptr_t)infocmd_create());
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
    ll_foreach(&cmd->commands, cmd_dispose);
    ll_clear(&cmd->commands, NULL);
}

static int cmd_help(CmdContext* cc, ParsedCommand* pc)
{
    if (pc->print_help || pc->args.size != 0 || pc->cmd_modifiers.size != 0)
        return COMMAND_INVALID_HELP_COMMAND;

    printf("\nAvailable commands:\n");
    printf("    help [h]\n");
    LLNode* curr = cc->commands.head;
    while (curr) {
        Cmd* cmd = (Cmd*)curr->data;
        printf("    %s [%s]\n", cmd->name, cmd->alias);
        curr = curr->next;
    }
    printf("\n");
    return COMMAND_OK;
}

int cmdctx_run(CmdContext* cc, ParsedCommand* pc, FileBuffer* fb)
{
    if (strcmp(pc->cmd, "help") == 0 || strcmp(pc->cmd, "h") == 0)
        return cmd_help(cc, pc);

    LLNode* curr = cc->commands.head;
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
