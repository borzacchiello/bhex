// Copyright (c) 2022-2026, bageyelet

#include "cmd_arg_handler.h"
#include "cmd_search.h"
#include "cmd.h"

#include <util/byte_to_num.h>
#include <util/print.h>
#include <util/str.h>

#include <filebuffer.h>
#include <display.h>
#include <color.h>
#include <string.h>
#include <alloc.h>
#include <defs.h>
#include <log.h>
#include <unistd.h>

#define HINT_STR "[/{x, s}/sk/p/1] <what> [<len>]"

#define CONTEXT_PRINT_RANGE 16

#define DATA_TYPE_UNSET  -1
#define DATA_TYPE_STRING 0
#define DATA_TYPE_HEX    1

#define SEEK_TO_MATCH_UNSET -1
#define SEEK_TO_MATCH_SET   0

#define PRINT_CTX_UNSET -1
#define PRINT_CTX_SET   0

#define FIRST_ONLY_UNSET -1
#define FIRST_ONLY_SET   0

typedef struct {
    int   first_match;
    int   seek_to_match;
    int   print_context;
    int   first_only;
    u64_t seek_addr;
} SearchContext;

static void searchcmd_help(void* obj)
{
    display_printf(
        "search: search a string or a sequence of bytes in the file\n"
        "\n"
        "  src" HINT_STR "\n"
        "     x:  data is a hex string\n"
        "     s:  data is a string (default)\n"
        "     sk: seek to first match\n"
        "     p:  print context\n"
        "     1:  stop at the first match\n"
        "\n"
        "  what: either a string or a hex string. A hex string may carry '?'\n"
        "        in place of a digit, matching any value for that nibble\n"
        "        (e.g. \"e8 ?? ?? ?? ??\")\n"
        "  len:  number of bytes to search starting from the current offset\n"
        "        (if omitted, search the whole file)\n");
}

static int search_cb(FileBuffer* fb, u64_t match_addr, const u8_t* match,
                     size_t match_size, void* user_data)
{
    SearchContext* ctx = (SearchContext*)user_data;
    if (!ctx->first_match && ctx->print_context)
        display_printf("\n\n");
    else
        ctx->first_match = 0;
    display_printf(" >> Match @ %s0x%07llX%s\n", color_str(COLOR_ADDR),
                   match_addr + fb->base_addr, color_str(COLOR_RESET));
    if (ctx->seek_to_match) {
        ctx->seek_addr = match_addr;
    }
    if (ctx->print_context) {
        display_printf("\n");
        u64_t print_addr_begin = match_addr;
        u64_t print_addr_end   = match_addr + match_size;
        // if we have enough bytes, expand by PRINT_RANGE bytes before
        // and after
        print_addr_begin = print_addr_begin >= CONTEXT_PRINT_RANGE
                               ? print_addr_begin - CONTEXT_PRINT_RANGE
                               : 0;
        print_addr_end   = print_addr_end + CONTEXT_PRINT_RANGE >= fb->size
                               ? fb->size
                               : print_addr_end + CONTEXT_PRINT_RANGE;
        if ((print_addr_end - print_addr_begin + 1) % CONTEXT_PRINT_RANGE !=
            0) {
            u64_t rem      = CONTEXT_PRINT_RANGE -
                             ((print_addr_end - print_addr_begin + 1) %
                              CONTEXT_PRINT_RANGE) +
                             1;
            print_addr_end = print_addr_end + rem >= fb->size
                                 ? fb->size
                                 : print_addr_end + rem;
        }

        // the context window can be arbitrarily large (the match itself is
        // user-controlled), but fb_read() fails for requests bigger than a
        // block: clamp it, printing a truncated context is better than nothing
        u64_t to_print = print_addr_end - print_addr_begin;
        if (to_print > fb_block_size)
            to_print = fb_block_size;

        fb_seek(fb, print_addr_begin);
        const u8_t* data_to_print = fb_read(fb, to_print);
        if (data_to_print == NULL) {
            warning("unable to read the context of the match");
            return 1;
        }
        print_hex(data_to_print, to_print, 0, 1, 1, 16,
                  print_addr_begin + fb->base_addr);
    }
    return ctx->first_only ? 0 : 1;
}

static int searchcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    int data_type     = DATA_TYPE_STRING;
    int seek_to_match = SEEK_TO_MATCH_UNSET;
    int print_context = PRINT_CTX_UNSET;
    int first_only    = FIRST_ONLY_UNSET;
    if (handle_mods(pc, "s,x|sk|p|1", &data_type, &seek_to_match,
                    &print_context, &first_only) != 0)
        return COMMAND_INVALID_MOD;

    char* data_str = NULL;
    char* len_str  = NULL;
    if (handle_args(pc, 2, 1, &data_str, &len_str) != 0)
        return COMMAND_INVALID_ARG;

    // with no length the whole file is searched, whatever the current offset:
    // the range is counted from the cursor only when it is asked for
    u64_t start = 0;
    u64_t end   = UINT64_MAX;
    if (len_str != NULL) {
        u64_t len;
        if (!str_to_uint64(len_str, &len))
            return COMMAND_INVALID_ARG;
        start = fb->off;
        end   = len > fb->size - start ? fb->size : start + len;
    }

    u8_t*  data      = NULL;
    u8_t*  mask      = NULL;
    size_t data_size = 0;
    switch (data_type) {
        case DATA_TYPE_STRING:
            if (!unescape_ascii_string(data_str, &data, &data_size))
                return COMMAND_INVALID_ARG;
            break;
        case DATA_TYPE_HEX:
            if (!hex_to_bytes_masked(data_str, &data, &mask, &data_size))
                return COMMAND_INVALID_ARG;
            break;
    }

    SearchContext ctx = {
        .first_match   = 1,
        .seek_to_match = seek_to_match == SEEK_TO_MATCH_UNSET ? 0 : 1,
        .print_context = print_context == PRINT_CTX_UNSET ? 0 : 1,
        .first_only    = first_only == FIRST_ONLY_UNSET ? 0 : 1,
        .seek_addr     = 0,
    };

    long ncpu     = sysconf(_SC_NPROCESSORS_ONLN);
    int  nthreads = ncpu > 0 ? (int)ncpu : 1;
    // the workers report in whatever order they finish: "the first match" only
    // means anything when a single thread walks the file in order
    if (ctx.first_only)
        nthreads = 1;
    fb_search_ex(fb, data, mask, data_size, start, end, search_cb, &ctx,
                 nthreads);
    if (ctx.seek_to_match && fb->off != ctx.seek_addr)
        fb_seek(fb, ctx.seek_addr);

    bhex_free(data);
    bhex_free(mask);
    return COMMAND_OK;
}

static void searchcmd_dispose(void* obj) { (void)obj; }

Cmd* searchcmd_create(void)
{
    Cmd* cmd   = bhex_malloc(sizeof(Cmd));
    cmd->obj   = NULL;
    cmd->name  = "search";
    cmd->alias = "src";
    cmd->hint  = HINT_STR;

    cmd->dispose = searchcmd_dispose;
    cmd->help    = searchcmd_help;
    cmd->exec    = searchcmd_exec;

    return cmd;
}
