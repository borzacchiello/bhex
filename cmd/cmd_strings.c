#include "cmd_strings.h"
#include "defs.h"
#include "filebuffer.h"

#include <util/byte_to_num.h>
#include <display.h>
#include <string.h>
#include <alloc.h>
#include <log.h>

#define HINT_STR "[/n] [<num>]"

#define min(x, y) ((x) < (y) ? (x) : (y))
#define le16(p, off)                                                           \
    (((u16_t)((u8_t*)(p))[off]) | ((u16_t)((u8_t*)(p))[off + 1] << 8))

typedef struct {
    size_t      min_length;
    int         null_terminated;
    u8_t*       app;
    size_t      app_capacity;
    FileBuffer* fb;
    const u8_t* buf;
    u64_t       buf_size;
    u64_t       addr;
} ProcessingCtx;

static void stringscmd_dispose(void* obj) { return; }

static void stringscmd_help(void* obj)
{
    display_printf(
        "enumerate the strings in the file (i.e., sequences of printable "
        "ascii characters, either ASCII or UTF-16-LE ASCII)\n"
        "\n"
        "  str" HINT_STR "\n"
        "     n: look for null-terminated strings\n"
        "\n"
        "  num: minimum length (default: 3)\n");
}

static int is_printable_ascii(u16_t v) { return v >= 0x20 && v <= 0x7e; }

#define enlarge_app_if_needed(ctx, needed)                                     \
    do {                                                                       \
        if ((ctx)->app_capacity - (needed) < 1) {                              \
            while ((ctx)->app_capacity - (needed) < 1)                         \
                (ctx)->app_capacity *= 2;                                      \
            (ctx)->app = bhex_realloc((ctx)->app, (ctx)->app_capacity);        \
        }                                                                      \
    } while (0)

#define seek_to_next_block_if_needed(ctx)                                      \
    do {                                                                       \
        if ((ctx)->addr % (ctx)->buf_size == 0) {                              \
            fb_seek((ctx)->fb, (ctx)->addr);                                   \
            (ctx)->buf_size =                                                  \
                min(fb_block_size, (ctx)->fb->size - (ctx)->fb->off);          \
            (ctx)->buf = fb_read((ctx)->fb, (ctx)->buf_size);                  \
        }                                                                      \
    } while (0)

static void print_ascii_string(ProcessingCtx* ctx)
{
    u64_t begin_addr = ctx->addr;
    u32_t app_off    = 0;
    while (ctx->addr < ctx->fb->size &&
           is_printable_ascii(ctx->buf[ctx->addr % ctx->buf_size])) {

        enlarge_app_if_needed(ctx, app_off + 1);
        ctx->app[app_off++] = ctx->buf[ctx->addr % ctx->buf_size];
        ctx->addr += 1;
        seek_to_next_block_if_needed(ctx);
    }
    if (app_off >= ctx->min_length) {
        ctx->app[app_off] = 0;
        if (!ctx->null_terminated ||
            (ctx->null_terminated && ctx->addr < ctx->fb->size &&
             ctx->buf[ctx->addr % ctx->buf_size] == 0)) {
            display_printf(" [A] 0x%07llX @ %s\n", begin_addr, (char*)ctx->app);
        }
    }
}

static void print_wide_ascii_string(ProcessingCtx* ctx)
{
    u64_t begin_addr = ctx->addr;
    u32_t app_off    = 0;
    while (ctx->addr + 1 < ctx->fb->size &&
           is_printable_ascii(le16(ctx->buf, ctx->addr % ctx->buf_size))) {
        enlarge_app_if_needed(ctx, app_off + 1);
        ctx->app[app_off++] = le16(ctx->buf, ctx->addr % ctx->buf_size) & 0xFF;
        ctx->addr += 2;
        seek_to_next_block_if_needed(ctx);
    }
    if (app_off >= ctx->min_length) {
        ctx->app[app_off] = 0;
        if (!ctx->null_terminated ||
            (ctx->null_terminated && ctx->addr + 1 < ctx->fb->size &&
             le16(ctx->buf, ctx->addr % ctx->buf_size) == 0)) {
            display_printf(" [W] 0x%07llX @ %s\n", begin_addr, (char*)ctx->app);
        }
    }
}

static void print_strings(FileBuffer* fb, size_t min_length,
                          int null_terminated)
{
    u64_t orig_off = fb->off;
    fb_seek(fb, 0);

    size_t        buf_size = min(fb_block_size, fb->size - fb->off);
    ProcessingCtx ctx      = {
             .min_length      = min_length,
             .null_terminated = null_terminated,
             .app             = bhex_malloc(min_length),
             .app_capacity    = min_length,
             .fb              = fb,
             .buf             = fb_read(fb, buf_size),
             .buf_size        = buf_size,
             .addr            = 0,
    };

    while (ctx.addr < fb->size) {
        if (is_printable_ascii(le16(ctx.buf, ctx.addr % ctx.buf_size))) {
            print_wide_ascii_string(&ctx);
            continue;
        }
        if (is_printable_ascii(ctx.buf[ctx.addr % ctx.buf_size])) {
            print_ascii_string(&ctx);
            continue;
        }

        ctx.addr += 1;
        if (ctx.addr % ctx.buf_size == 0) {
            fb_seek(fb, ctx.addr);
            ctx.buf_size = min(fb_block_size, fb->size - fb->off);
            ctx.buf      = fb_read(fb, ctx.buf_size);
        }
    }

    bhex_free(ctx.app);
    fb_seek(fb, orig_off);
}

static int stringscmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    if (pc->cmd_modifiers.size > 1)
        return COMMAND_UNSUPPORTED_MOD;
    if (pc->args.size > 1)
        return COMMAND_UNSUPPORTED_ARG;

    int null_terminated = 0;
    if (pc->cmd_modifiers.size == 1) {
        char* m = (char*)pc->cmd_modifiers.head->data;
        if (strcmp(m, "n") == 0)
            null_terminated = 1;
        else
            return COMMAND_UNSUPPORTED_MOD;
    }

    size_t min_length = 3;
    if (pc->args.size == 1) {
        char* arg = (char*)pc->args.head->data;
        u32_t s;
        if (!str_to_uint32(arg, &s) || s == 0)
            return COMMAND_INVALID_ARG;
        if (s >= 4096) {
            error("the minimum length is greater than the max value (4096)");
            return COMMAND_INVALID_ARG;
        }
        min_length = s;
    }

    print_strings(fb, min_length, null_terminated);
    return COMMAND_OK;
}

Cmd* stringscmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "strings";
    cmd->alias = "str";
    cmd->hint  = HINT_STR;

    cmd->dispose = stringscmd_dispose;
    cmd->help    = stringscmd_help;
    cmd->exec    = stringscmd_exec;

    return cmd;
}
