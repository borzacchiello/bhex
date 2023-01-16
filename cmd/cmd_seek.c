#include "cmd_seek.h"
#include "util/byte_to_num.h"

#include "../alloc.h"
#include "../log.h"

typedef struct SeekArg {
    u64_t off;
} SeekArg;

static int parse_seek_arg(ParsedCommand* pc, SeekArg* o_arg)
{
    LLNode* node;
    node = pc->cmd_modifiers.head;
    if (node != NULL)
        return COMMAND_UNSUPPORTED_MOD;

    node = pc->args.head;
    if (pc->args.size != 1)
        return COMMAND_UNSUPPORTED_ARG;

    const char* p = (const char*)node->data;
    u64_t       off;
    if (!str_to_uint64(p, &off))
        return COMMAND_INVALID_ARG;

    o_arg->off = off;
    return COMMAND_OK;
}

static void seekcmd_dispose(void* obj) { return; }

static void seekcmd_help(void* obj)
{
    printf("\nseek: change current offset\n"
           "  s <off>\n\n");
}

static int seekcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    SeekArg a;
    int     r = parse_seek_arg(pc, &a);
    if (r != COMMAND_OK)
        return r;

    if (a.off >= fb->size) {
        warning("trying to seek (%llu) after the size of the file (%llu)\n",
                a.off, fb->size);
        return COMMAND_INVALID_ARG;
    }

    fb_seek(fb, a.off);
    return COMMAND_OK;
}

Cmd* seekcmd_create()
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "seek";
    cmd->alias = "s";

    cmd->dispose = seekcmd_dispose;
    cmd->help    = seekcmd_help;
    cmd->exec    = seekcmd_exec;

    return cmd;
}
