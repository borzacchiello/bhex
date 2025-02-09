#include "cmd_seek.h"
#include <util/byte_to_num.h>

#include <string.h>

#include <alloc.h>
#include <log.h>

#define OFF_ABSOLUTE 0
#define OFF_SUM      1
#define OFF_SUB      2

#define min(x, y) ((x) < (y) ? (x) : (y))

typedef struct SeekState {
    u64_t prev_off;
} SeekState;

typedef struct SeekArg {
    int   print_off;
    int   off_mode;
    u64_t off;
} SeekArg;

static int parse_seek_arg(SeekState* state, ParsedCommand* pc, SeekArg* o_arg)
{
    if (pc->args.size == 0) {
        if (pc->cmd_modifiers.size != 0)
            return COMMAND_UNSUPPORTED_MOD;
        o_arg->print_off = 1;
        return COMMAND_OK;
    }

    int off_mode = OFF_ABSOLUTE;
    if (pc->cmd_modifiers.size > 1)
        return COMMAND_UNSUPPORTED_MOD;

    if (pc->cmd_modifiers.size == 1) {
        char* mod = (char*)pc->cmd_modifiers.head->data;
        if (strcmp(mod, "+") == 0)
            off_mode = OFF_SUM;
        else if (strcmp(mod, "-") == 0)
            off_mode = OFF_SUB;
        else
            return COMMAND_UNSUPPORTED_MOD;
    }

    LLNode* node = pc->args.head;
    if (pc->args.size != 1)
        return COMMAND_UNSUPPORTED_ARG;

    const char* p = (const char*)node->data;
    if (strcmp(p, "-") == 0) {
        if (off_mode != OFF_ABSOLUTE)
            return COMMAND_INVALID_MOD;
        o_arg->off = state->prev_off;
        return COMMAND_OK;
    }

    u64_t off;
    if (!str_to_uint64(p, &off))
        return COMMAND_INVALID_ARG;

    o_arg->off      = off;
    o_arg->off_mode = off_mode;
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
        "  s[/{+,-}] <off>\n"
        "    +: sum 'off' to current offset (wrap if greater than filesize)\n"
        "    -: subtract 'off' to current offset (wrap if lower than zero)\n"
        "\n"
        "  off: can be either a number or the character '-'.\n"
        "       In the latter case seek to the offset before the last seek.\n"
        "\n"
        "  NOTE: if called without arguments, print current offset\n"
        "\n");
}

static int seekcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    SeekState* state = (SeekState*)obj;

    SeekArg a = {0};
    int     r = parse_seek_arg(state, pc, &a);
    if (r != COMMAND_OK)
        return r;

    if (a.print_off) {
        printf("0x%llx\n", fb->off);
        return COMMAND_OK;
    }

    if (a.off_mode == OFF_SUM)
        a.off = (a.off + fb->off) % (fb->size + 1);
    else if (a.off_mode == OFF_SUB) {
        if (a.off > fb->off)
            a.off = fb->size + 1 - min(fb->size, a.off);
        else
            a.off = (fb->off - a.off) % (fb->size + 1);
    }

    if (a.off > fb->size) {
        error("trying to seek (%llu) after the size of the file (%llu)\n",
              a.off, fb->size);
        return COMMAND_INVALID_ARG;
    }

    state->prev_off = fb->off;

    fb_seek(fb, a.off);
    return COMMAND_OK;
}

Cmd* seekcmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    SeekState* state = bhex_malloc(sizeof(SeekState));
    state->prev_off  = 0;

    cmd->obj   = state;
    cmd->name  = "seek";
    cmd->alias = "s";
    cmd->hint  = " [/{+,-}] <addr>";

    cmd->dispose = seekcmd_dispose;
    cmd->help    = seekcmd_help;
    cmd->exec    = seekcmd_exec;

    return cmd;
}
