#include "cmd_seek.h"
#include "util/byte_to_num.h"

#include <string.h>

#include "../alloc.h"
#include "../log.h"

typedef struct SeekState {
    u64_t prev_off;
} SeekState;

typedef struct SeekArg {
    u64_t off;
} SeekArg;

static int parse_seek_arg(SeekState* state, ParsedCommand* pc, SeekArg* o_arg)
{
    LLNode* node;
    node = pc->cmd_modifiers.head;
    if (node != NULL)
        return COMMAND_UNSUPPORTED_MOD;

    node = pc->args.head;
    if (pc->args.size != 1)
        return COMMAND_UNSUPPORTED_ARG;

    const char* p = (const char*)node->data;
    if (strcmp(p, "-") == 0) {
        o_arg->off = state->prev_off;
        return COMMAND_OK;
    }

    u64_t off;
    if (!str_to_uint64(p, &off))
        return COMMAND_INVALID_ARG;

    o_arg->off = off;
    return COMMAND_OK;
}

static void seekcmd_dispose(void* obj)
{
    bhex_free(obj);
    return;
}

static void seekcmd_help(void* obj)
{
    printf(
        "\nseek: change current offset\n"
        "  s <off>\n"
        "\n"
        "  off: can be either a number or the character '-'.\n"
        "       In the latter case seek to the offset before the last seek.\n"
        "\n");
}

static int seekcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    SeekState* state = (SeekState*)obj;

    SeekArg a;
    int     r = parse_seek_arg(state, pc, &a);
    if (r != COMMAND_OK)
        return r;

    if (a.off >= fb->size) {
        warning("trying to seek (%llu) after the size of the file (%llu)\n",
                a.off, fb->size);
        return COMMAND_INVALID_ARG;
    }

    state->prev_off = fb->off;

    fb_seek(fb, a.off);
    return COMMAND_OK;
}

Cmd* seekcmd_create()
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    SeekState* state = bhex_malloc(sizeof(SeekState));
    state->prev_off  = 0;

    cmd->obj   = state;
    cmd->name  = "seek";
    cmd->alias = "s";

    cmd->dispose = seekcmd_dispose;
    cmd->help    = seekcmd_help;
    cmd->exec    = seekcmd_exec;

    return cmd;
}
