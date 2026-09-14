// Copyright (c) 2022-2026, bageyelet

#include "cmd_info.h"

#include <util/byte_to_str.h>
#include <util/math.h>
#include <entropy.h>
#include <hash/md5.h>
#include <display.h>
#include <color.h>
#include <string.h>
#include <alloc.h>
#include <log.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

typedef struct {
    u64_t version;
    float entropy;
    char* md5;
} InfoCtx;

static void infocmd_dispose(void* obj)
{
    InfoCtx* ctx = (InfoCtx*)obj;
    bhex_free(ctx->md5);
    bhex_free(ctx);
}

static void infocmd_help(void* obj)
{
    display_printf("info: prints information about the opened binary\n");
}

static void calc_values(FileBuffer* fb, char** md5, float* entropy)
{
    if (fb->size == 0) {
        *md5     = strdup("");
        *entropy = 0;
        return;
    }

    u64_t orig_off = fb->off;

    MD5_CTX ctx;
    MD5Init(&ctx);

    // 64 bit: a byte value occurs more than 2^32 times in a file bigger than
    // 4 GB, and a counter that wraps there reports a plausible wrong entropy
    // rather than an error
    u64_t counts[256] = {0};
    u64_t total       = 0;

    u64_t curr_off = 0;
    while (curr_off < fb->size) {
        fb_seek(fb, curr_off);

        size_t      len = min(fb_block_size, fb->size - curr_off);
        const u8_t* buf = fb_read(fb, len);
        if (buf == NULL) {
            // the file shrank under us: report what we have so far
            error("unable to read the file at offset %llu", curr_off);
            break;
        }

        // MD5
        MD5Update(&ctx, buf, len);

        // Entropy
        size_t i;
        for (i = 0; i < len; ++i) {
            counts[buf[i]] += 1;
        }
        total += len;

        curr_off += len;
    }

    // MD5
    u8_t digest[16];
    MD5Final(digest, &ctx);
    *md5 = bytes_to_hex(digest, sizeof(digest));

    // Entropy: counted over the bytes actually read, which is the whole file
    // unless it shrank under us
    *entropy = entropy_from_counts(counts, total);

    fb_seek(fb, orig_off);
}

static const char* size_string(u64_t size)
{
    static char buf[512];
    if (size / (1024ull * 1024 * 1024 * 1024) > 0)
        snprintf((char*)buf, sizeof(buf) - 1, "%llu [ %.03Lf TiB ]", size,
                 (double)size / (1024.0l * 1024 * 1024 * 1024));
    else if (size / (1024ul * 1024 * 1024) > 0)
        snprintf((char*)buf, sizeof(buf) - 1, "%llu [ %.03Lf GiB ]", size,
                 (double)size / (1024.0l * 1024 * 1024));
    else if (size / (1024ul * 1024) > 0)
        snprintf((char*)buf, sizeof(buf) - 1, "%llu [ %.03Lf MiB ]", size,
                 (double)size / (1024.0l * 1024));
    else if (size / 1024ul > 0)
        snprintf((char*)buf, sizeof(buf) - 1, "%llu [ %.03Lf KiB ]", size,
                 (double)size / 1024.0l);
    else
        snprintf((char*)buf, sizeof(buf) - 1, "%llu Bytes", size);
    return (const char*)&buf;
}

static int infocmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    if (pc->args.size != 0)
        return COMMAND_UNSUPPORTED_ARG;
    if (pc->cmd_modifiers.size != 0)
        return COMMAND_UNSUPPORTED_MOD;

    InfoCtx* ctx = (InfoCtx*)obj;
    if (fb->version != ctx->version) {
        bhex_free(ctx->md5);
        calc_values(fb, &ctx->md5, &ctx->entropy);
        ctx->version = fb->version;
    }

    const char* label = color_str(COLOR_LABEL);
    const char* reset = color_str(COLOR_RESET);
    display_printf("  %spath:%s    %s\n"
                   "  %ssize:%s    %s\n"
                   "  %sentropy:%s %.03f / 8.000\n"
                   "  %smd5:%s     %s\n",
                   label, reset, fb->path, label, reset, size_string(fb->size),
                   label, reset, ctx->entropy, label, reset, ctx->md5);

    return COMMAND_OK;
}

Cmd* infocmd_create(void)
{
    Cmd*     cmd = bhex_malloc(sizeof(Cmd));
    InfoCtx* ctx = bhex_malloc(sizeof(InfoCtx));

    ctx->version = (u64_t)-1;
    ctx->entropy = 0.0f;
    ctx->md5     = NULL;

    cmd->obj   = ctx;
    cmd->name  = "info";
    cmd->alias = "i";
    cmd->hint  = NULL;

    cmd->dispose = infocmd_dispose;
    cmd->help    = infocmd_help;
    cmd->exec    = infocmd_exec;

    return cmd;
}
