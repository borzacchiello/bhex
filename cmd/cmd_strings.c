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
        if ((ctx)->app_capacity < (needed) + 1) {                              \
            while ((ctx)->app_capacity < (needed) + 1)                         \
                (ctx)->app_capacity *= 2;                                      \
            (ctx)->app = bhex_realloc((ctx)->app, (ctx)->app_capacity);        \
        }                                                                      \
    } while (0)

#define advance_by_one(ctx)                                                    \
    do {                                                                       \
        (ctx)->addr += 1;                                                      \
        if ((ctx)->addr % (ctx)->buf_size == 0) {                              \
            fb_seek((ctx)->fb, (ctx)->addr);                                   \
            (ctx)->buf_size =                                                  \
                min(fb_block_size, (ctx)->fb->size - (ctx)->fb->off);          \
            (ctx)->buf = fb_read((ctx)->fb, (ctx)->buf_size);                  \
        }                                                                      \
    } while (0)

#define retreat_by_one(ctx)                                                    \
    do {                                                                       \
        (ctx)->addr -= 1;                                                      \
        if (((ctx)->addr + 1) % (ctx)->buf_size == 0) {                        \
            fb_seek((ctx)->fb, (ctx)->addr);                                   \
            (ctx)->buf_size =                                                  \
                min(fb_block_size, (ctx)->fb->size - (ctx)->fb->off);          \
            (ctx)->buf = fb_read((ctx)->fb, (ctx)->buf_size);                  \
        }                                                                      \
    } while (0)

static int print_ascii_string(ProcessingCtx* ctx)
{
    u64_t begin_addr = ctx->addr;
    u32_t app_off    = 0;
    while (ctx->addr < ctx->fb->size &&
           is_printable_ascii(ctx->buf[ctx->addr % ctx->buf_size])) {

        enlarge_app_if_needed(ctx, app_off + 1);
        ctx->app[app_off++] = ctx->buf[ctx->addr % ctx->buf_size];

        advance_by_one(ctx);
    }
    if (app_off >= ctx->min_length) {
        ctx->app[app_off] = 0;
        if (!ctx->null_terminated ||
            (ctx->null_terminated && ctx->addr < ctx->fb->size &&
             ctx->buf[ctx->addr % ctx->buf_size] == 0)) {
            if (ctx->pattern != NULL &&
                strstr((char*)ctx->app, ctx->pattern) == NULL) {
                return 0;
            }
            display_printf(" [A] 0x%07llX @ %s\n", begin_addr, (char*)ctx->app);
            return 1;
        }
    }
    return 0;
}

static int print_wide_ascii_string(ProcessingCtx* ctx)
{
    u64_t begin_addr = ctx->addr;
    u32_t app_off    = 0;
    while (ctx->addr + 1 < ctx->fb->size) {
        u16_t v = ctx->buf[ctx->addr % ctx->buf_size];
        if (!is_printable_ascii(v)) {
            break;
        }

        advance_by_one(ctx);
        v |= ctx->buf[ctx->addr % ctx->buf_size] << 8;
        if (!is_printable_ascii(v)) {
            retreat_by_one(ctx);
            break;
        }

        enlarge_app_if_needed(ctx, app_off + 1);
        ctx->app[app_off++] = v & 0xFF;

        advance_by_one(ctx);
    }
    if (app_off >= ctx->min_length) {
        ctx->app[app_off] = 0;
        if (ctx->null_terminated) {
            u16_t v = 0;
            if (ctx->addr + 1 >= ctx->fb->size) {
                return 0;
            }
            v = ctx->buf[ctx->addr % ctx->buf_size];
            advance_by_one(ctx);
            v |= ctx->buf[ctx->addr % ctx->buf_size] << 8;
            retreat_by_one(ctx);
            if (v != 0) {
                return 0;
            }
        }
        if (ctx->pattern != NULL &&
            strstr((char*)ctx->app, ctx->pattern) == NULL) {
            return 0;
        }
        display_printf(" [W] 0x%07llX @ %s\n", begin_addr, (char*)ctx->app);
        return 1;
    }
    return 0;
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
                              .buf             = NULL,
                              .buf_size        = buf_size,
                              .addr            = 0,
                              .pattern         = pattern};

    ctx.buf = fb_read(fb, buf_size);
    if (ctx.buf == NULL) {
        bhex_free(ctx.app);
        fb_seek(fb, orig_off);
        return;
    }

    while (ctx.addr < fb->size) {
        if (mode_selector & MODE_SELECTOR_WIDE &&
            print_wide_ascii_string(&ctx)) {
            continue;
        }
        if (mode_selector & MODE_SELECTOR_ASCII && print_ascii_string(&ctx)) {
            continue;
        }

        advance_by_one(&ctx);
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
