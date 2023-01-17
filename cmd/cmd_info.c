#include "cmd_info.h"
#include "hash/md5.h"
#include "util/byte_to_str.h"

#include <string.h>

#include "../alloc.h"

#define min(x, y) ((x) < (y) ? (x) : (y))

static void infocmd_dispose(void* obj) { return; }

static void infocmd_help(void* obj)
{
    printf("\ninfo: prints information about the opened binary\n\n");
}

static float _log2(float val)
{
    union {
        float val;
        s32_t x;
    } u                  = {val};
    register float log_2 = (float)(((u.x >> 23) & 255) - 128);
    u.x &= ~(255 << 23);
    u.x += 127 << 23;
    log_2 += ((-0.3358287811f) * u.val + 2.0f) * u.val - 0.65871759316667f;
    return (log_2);
}

static void calc_values(FileBuffer* fb, char** md5, float* entropy)
{
    u64_t orig_off = fb->off;

    MD5_CTX ctx;
    MD5Init(&ctx);

    static u32_t counts[256];
    memset(counts, 0, sizeof(counts));

    u64_t curr_off = 0;
    while (curr_off < fb->size) {
        fb_seek(fb, curr_off);

        size_t      len = min(fb_block_size, fb->size - curr_off);
        const u8_t* buf = fb_read(fb, len);

        // MD5
        MD5Update(&ctx, buf, len);

        // Entropy
        size_t i;
        for (i = 0; i < len; ++i) {
            counts[buf[i]] += 1;
        }

        curr_off += len;
    }

    // MD5
    u8_t digest[16];
    MD5Final(digest, &ctx);
    *md5 = bytes_to_hex(digest, sizeof(digest));

    // Entropy
    *entropy = 0;
    u32_t i;
    for (i = 0; i < 256; ++i) {
        float px = (float)counts[i] / fb->size;
        if (px > 0) {
            *entropy += -px * _log2(px);
        }
    }

    fb_seek(fb, orig_off);
}

static int infocmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    if (pc->args.size != 0)
        return COMMAND_UNSUPPORTED_ARG;
    if (pc->cmd_modifiers.size != 0)
        return COMMAND_UNSUPPORTED_MOD;

    char* md5;
    float entropy;
    calc_values(fb, &md5, &entropy);

    printf("\n"
           "  path:    %s\n"
           "  size:    %llu bytes\n"
           "  entropy: %.03f / 8.0\n"
           "  md5:     %s\n"
           "\n",
           fb->path, fb->size, entropy, md5);

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
