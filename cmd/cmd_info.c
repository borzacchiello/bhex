#include "cmd_info.h"
#include "hash/md5.h"
#include "util/byte_to_str.h"

#include "../alloc.h"

static void infocmd_dispose(void* obj) { return; }

static void infocmd_help(void* obj)
{
    printf("\ninfo: prints information about the opened binary\n\n");
}

static char* calc_md5(FileBuffer* fb)
{
    uint64_t orig_off = fb->off;

    MD5_CTX ctx;
    MD5Init(&ctx);

    uint64_t curr_off = 0;
    while (curr_off + fb_block_size < fb->size) {
        fb_seek(fb, curr_off);
        MD5Update(&ctx, fb_read(fb, fb_block_size), fb_block_size);
        curr_off += fb_block_size;
    }

    if (curr_off < fb->size) {
        fb_seek(fb, curr_off);
        MD5Update(&ctx, fb_read(fb, fb->size - curr_off), fb->size - curr_off);
    }

    uint8_t digest[16];
    MD5Final(digest, &ctx);
    fb_seek(fb, orig_off);

    return bytes_to_hex(digest, sizeof(digest));
}

static int infocmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    if (pc->args.size != 0)
        return COMMAND_UNSUPPORTED_ARG;
    if (pc->cmd_modifiers.size != 0)
        return COMMAND_UNSUPPORTED_MOD;

    char* md5 = calc_md5(fb);

    printf("\n"
           "  path: %s\n"
           "  size: %llu bytes\n"
           "  md5:  %s\n"
           "\n",
           fb->path, fb->size, md5);

    bhex_free(md5);
    return COMMAND_OK;
}

Cmd* infocmd_create()
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "info";
    cmd->alias = "i";

    cmd->dispose = infocmd_dispose;
    cmd->help    = infocmd_help;
    cmd->exec    = infocmd_exec;

    return cmd;
}
