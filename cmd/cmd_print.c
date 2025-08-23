#include "cmd_arg_handler.h"
#include "cmd_print.h"
#include "cmd.h"
#include "filebuffer.h"

#include <util/byte_to_num.h>
#include <util/print.h>
#include <display.h>
#include <string.h>
#include <alloc.h>
#include <defs.h>

#define WIDTH_UNSET   -1
#define WIDTH_BYTE    0
#define WIDTH_WORD    1
#define WIDTH_DWORD   2
#define WIDTH_QWORD   3
#define WIDTH_ASCII   4
#define WIDTH_CBUFFER 5

#define ENDIANESS_UNSET  -1
#define ENDIANESS_LITTLE 0
#define ENDIANESS_BIG    1

#define SEEK_UNSET    -1
#define SEEK_FORWARD  0
#define SEEK_BACKWARD 1

#define RAW_UNSET -1
#define RAW_SET   0

#define HINT_CMDLINE "[/{x,w,d,q,a,C}/{le,be}/r/{+,-}] <nelements>"

// must be lower than fb_block_size
#define DEFAULT_PRINT_LEN 256

#define min(x, y) ((x) < (y) ? (x) : (y))

typedef struct PrintCmdArgs {
    int   width;
    int   endianess;
    int   raw_mode;
    int   seek;
    u64_t n_els;
} PrintCmdArgs;

static u32_t get_width_bytes(int w)
{
    switch (w) {
        case WIDTH_WORD:
            return 2;
        case WIDTH_DWORD:
            return 4;
        case WIDTH_QWORD:
            return 8;
    }
    return 1;
}

static void printcmd_dispose(void* obj) { return; }

static void printcmd_help(void* obj)
{
    display_printf(
        "print: display the data at current offset in various formats\n"
        "\n"
        "  p" HINT_CMDLINE "\n"
        "     x:  hex output (default)\n"
        "     w:  words\n"
        "     d:  dwords\n"
        "     q:  qwords\n"
        "     a:  as ascii\n"
        "     C:  as C buffer\n"
        "     le: little-endian (default)\n"
        "     be: big-endian\n"
        "     r:  raw mode (no ascii, no header and no addresses)\n"
        "     +:  seek forward after printing\n"
        "     -:  seek backwards after printing\n"
        "\n"
        "  nelements: the number of elements to display\n"
        "  (default: enough to display %d bytes, if '-' the whole file)\n",
        DEFAULT_PRINT_LEN);
}

static int printcmd_parse_args(ParsedCommand* pc, PrintCmdArgs* o_args,
                               u64_t total_size)
{
    o_args->width     = WIDTH_BYTE;
    o_args->endianess = ENDIANESS_LITTLE;
    o_args->raw_mode  = RAW_UNSET;
    o_args->seek      = SEEK_UNSET;
    o_args->n_els     = 0;
    if (handle_mods(pc, "x,w,d,q,a,C|le,be|r|+,-", &o_args->width,
                    &o_args->endianess, &o_args->raw_mode, &o_args->seek) != 0)
        return COMMAND_INVALID_MOD;
    o_args->raw_mode = o_args->raw_mode == RAW_UNSET ? 0 : 1;

    char* s = NULL;
    if (handle_args(pc, 1, 0, &s) != 0)
        return COMMAND_INVALID_ARG;
    if (s == NULL)
        o_args->n_els = DEFAULT_PRINT_LEN / get_width_bytes(o_args->width);
    else if (strcmp(s, "-") == 0)
        o_args->n_els = total_size / get_width_bytes(o_args->width);
    else if (!str_to_uint64(s, &o_args->n_els))
        return COMMAND_INVALID_ARG;
    return COMMAND_OK;
}

static int printcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    PrintCmdArgs args;
    int          r = printcmd_parse_args(pc, &args, fb->size);
    if (r != COMMAND_OK)
        return r;

    size_t size =
        min(args.n_els * get_width_bytes(args.width), fb->size - fb->off);

    u64_t  addr           = 0;
    size_t remaining_size = size;
    u64_t  orig_off       = fb->off;
    while (remaining_size != 0) {
        size_t      read_size = min(remaining_size, fb_block_size);
        const u8_t* bytes     = fb_read(fb, read_size);
        if (!bytes)
            return COMMAND_INVALID_ARG;

        int print_header = addr == 0;
        int print_footer = remaining_size == read_size;
        switch (args.width) {
            case WIDTH_UNSET:
            case WIDTH_BYTE:
                print_hex(bytes, read_size, args.raw_mode, print_header,
                          print_footer, addr);
                break;
            case WIDTH_WORD:
                print_words(bytes, read_size,
                            args.endianess == ENDIANESS_LITTLE, args.raw_mode,
                            print_header, print_footer, addr);
                break;
            case WIDTH_DWORD:
                print_dwords(bytes, read_size,
                             args.endianess == ENDIANESS_LITTLE, args.raw_mode,
                             print_header, print_footer, addr);
                break;
            case WIDTH_QWORD:
                print_qwords(bytes, read_size,
                             args.endianess == ENDIANESS_LITTLE, args.raw_mode,
                             print_header, print_footer, addr);
                break;
            case WIDTH_CBUFFER:
                print_c_buffer(bytes, read_size, print_header, print_footer);
                break;
            case WIDTH_ASCII:
                print_ascii(bytes, read_size, print_footer);
                break;
        }
        remaining_size -= read_size;
        addr += read_size;
        fb_seek(fb, fb->off + read_size);
    }
    fb_seek(fb, orig_off);
    if (args.seek == SEEK_FORWARD && fb->off + size < fb->size)
        fb_seek(fb, fb->off + size);
    else if (args.seek == SEEK_BACKWARD && size <= fb->off)
        fb_seek(fb, fb->off - size);

    return COMMAND_OK;
}

Cmd* printcmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "print";
    cmd->alias = "p";
    cmd->hint  = HINT_CMDLINE;

    cmd->dispose = printcmd_dispose;
    cmd->help    = printcmd_help;
    cmd->exec    = printcmd_exec;

    return cmd;
}
