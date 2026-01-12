#include "cmd_arg_handler.h"
#include "cmd_search.h"
#include "cmd.h"
#include "defs.h"
#include "filebuffer.h"

#include <util/print.h>
#include <util/str.h>
#include <display.h>
#include <string.h>
#include <alloc.h>
#include <log.h>

#define HINT_STR "[/{x, s}/sk/p] <what>"

#define CONTEXT_PRINT_RANGE 16

#define DATA_TYPE_UNSET  -1
#define DATA_TYPE_STRING 0
#define DATA_TYPE_HEX    1

#define SEEK_TO_MATCH_UNSET -1
#define SEEK_TO_MATCH_SET   0

#define PRINT_CTX_UNSET -1
#define PRINT_CTX_SET   0

typedef struct {
    int   first_match;
    int   seek_to_match;
    int   print_context;
    u64_t seek_addr;
} SearchContext;

static void searchcmd_help(void* obj)
{
    display_printf(
        "search: search a string or a sequence of bytes in the file\n"
        "\n"
        "  src" HINT_STR "\n"
        "     x:  data is an hex string\n"
        "     s:  data is a string (default)\n"
        "     sk: seek to first match\n"
        "     c:  print context\n"
        "\n"
        "  what: either a string or an hex string\n");
}

static int search_cb(FileBuffer* fb, u64_t match_addr, const u8_t* match,
                     size_t match_size, void* user_data)
{
    SearchContext* ctx = (SearchContext*)user_data;
    if (!ctx->first_match && ctx->print_context)
        display_printf("\n\n");
    else
        ctx->first_match = 0;
    display_printf(" >> Match @ 0x%07llX\n", match_addr);
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

        fb_seek(fb, print_addr_begin);
        const u8_t* data_to_print =
            fb_read(fb, print_addr_end - print_addr_begin);
        print_hex(data_to_print, print_addr_end - print_addr_begin, 0, 1, 1, 16,
                  print_addr_begin);
    }
    return 1;
}

static int searchcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    int data_type     = DATA_TYPE_STRING;
    int seek_to_match = SEEK_TO_MATCH_UNSET;
    int print_context = PRINT_CTX_UNSET;
    if (handle_mods(pc, "s,x|sk|p", &data_type, &seek_to_match,
                    &print_context) != 0)
        return COMMAND_INVALID_MOD;

    char* data_str;
    if (handle_args(pc, 1, 1, &data_str) != 0)
        return COMMAND_INVALID_ARG;

    u8_t*  data      = NULL;
    size_t data_size = 0;
    switch (data_type) {
        case DATA_TYPE_STRING:
            if (!unescape_ascii_string(data_str, &data, &data_size))
                return COMMAND_INVALID_ARG;
            break;
        case DATA_TYPE_HEX:
            if (!hex_to_bytes(data_str, &data, &data_size))
                return COMMAND_INVALID_ARG;
            break;
    }

    SearchContext ctx = {
        .first_match = 1,
        .seek_to_match =
            seek_to_match == SEEK_TO_MATCH_UNSET ? 0 : 1,
        .print_context = print_context == PRINT_CTX_UNSET ? 0 : 1,
        .seek_addr     = 0,
    };

    fb_search(fb, data, data_size, search_cb, &ctx);
    if (ctx.seek_to_match && fb->off != ctx.seek_addr)
        fb_seek(fb, ctx.seek_addr);

    bhex_free(data);
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
