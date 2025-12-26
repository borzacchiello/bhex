#include "cmd_strings.h"
#include "cmd.h"
#include "cmd_arg_handler.h"

#include <util/byte_to_num.h>
#include <filebuffer.h>
#include <display.h>
#include <string.h>
#include <alloc.h>
#include <log.h>
#include <defs.h>

#define HINT_STR "[/n/{a,w}] [ <pattern> <num> ]"

#define min(x, y) ((x) < (y) ? (x) : (y))
#define le16(p, off)                                                           \
    (((u16_t)((u8_t*)(p))[off]) | ((u16_t)((u8_t*)(p))[off + 1] << 8))

#define MODE_SELECTOR_ALL   3
#define MODE_SELECTOR_ASCII 1
#define MODE_SELECTOR_WIDE  2

typedef struct {
    size_t      min_length;
    int         null_terminated;
    u8_t*       app;
    size_t      app_capacity;
    FileBuffer* fb;
    const u8_t* buf;
    u64_t       buf_size;
    u64_t       addr;
    char*       pattern;
} ProcessingCtx;

static void stringscmd_dispose(void* obj) { return; }

static void stringscmd_help(void* obj)
{
    display_printf(
        "enumerate the strings in the file (i.e., sequences of printable "
        "ascii characters with 8 or 16 bits)\n"
        "\n"
        "  str" HINT_STR "\n"
        "     n: look for null-terminated strings\n"
        "     a: 8-bit only\n"
        "     w: 16-bit only\n"
        "\n"
        "  pattern: print only strings that contains the pattern as "
        "substring (use * for any character)\n"
        "  num:     minimum length (default: 3)\n");
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
            if (ctx->pattern != NULL &&
                strstr((char*)ctx->app, ctx->pattern) == NULL) {
                return;
            }
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
            if (ctx->pattern != NULL &&
                strstr((char*)ctx->app, ctx->pattern) == NULL) {
                return;
            }
            display_printf(" [W] 0x%07llX @ %s\n", begin_addr, (char*)ctx->app);
        }
    }
}

static void print_strings(FileBuffer* fb, size_t min_length,
                          int null_terminated, int mode_selector, char* pattern)
{
    u64_t orig_off = fb->off;
    fb_seek(fb, 0);

    size_t        buf_size = min(fb_block_size, fb->size - fb->off);
    ProcessingCtx ctx      = {.min_length      = min_length,
                              .null_terminated = null_terminated,
                              .app             = bhex_malloc(min_length),
                              .app_capacity    = min_length,
                              .fb              = fb,
                              .buf             = fb_read(fb, buf_size),
                              .buf_size        = buf_size,
                              .addr            = 0,
                              .pattern         = pattern};

    while (ctx.addr < fb->size) {
        if (mode_selector & MODE_SELECTOR_WIDE &&
            is_printable_ascii(le16(ctx.buf, ctx.addr % ctx.buf_size))) {
            print_wide_ascii_string(&ctx);
            continue;
        }
        if (mode_selector & MODE_SELECTOR_ASCII &&
            is_printable_ascii(ctx.buf[ctx.addr % ctx.buf_size])) {
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
    int null_terminated = -1;
    int mode_selector   = -1; // -1: all, 0: ascii only, 1: wide only
    if (handle_mods(pc, "n|a,w", &null_terminated, &mode_selector) !=
        COMMAND_OK) {
        return COMMAND_INVALID_MOD;
    }
    null_terminated = (null_terminated == -1) ? 0 : 1;
    if (mode_selector == -1) {
        mode_selector = MODE_SELECTOR_ALL;
    } else if (mode_selector == 0) {
        mode_selector = MODE_SELECTOR_ASCII;
    } else if (mode_selector == 1) {
        mode_selector = MODE_SELECTOR_WIDE;
    }

    char* pattern    = NULL;
    char* minlen_str = NULL;
    if (handle_args(pc, 2, 0, &pattern, &minlen_str) != COMMAND_OK) {
        return COMMAND_INVALID_ARG;
    }
    if (pattern != NULL && strcmp(pattern, "*") == 0) {
        pattern = NULL;
    }

    size_t min_length = 3;
    if (minlen_str != NULL) {
        u32_t s;
        if (!str_to_uint32(minlen_str, &s) || s == 0)
            return COMMAND_INVALID_ARG;
        if (s >= 4096) {
            error("the minimum length is greater than the max value (4096)");
            return COMMAND_INVALID_ARG;
        }
        min_length = s;
    }

    print_strings(fb, min_length, null_terminated, mode_selector, pattern);
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
