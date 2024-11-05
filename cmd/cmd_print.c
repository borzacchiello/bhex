#include "cmd_print.h"
#include "util/byte_to_str.h"
#include "util/byte_to_num.h"
#include "util/endian.h"
#include "../alloc.h"

#include <string.h>

#define WIDTH_UNSET   0x0000
#define WIDTH_BYTE    0x0001
#define WIDTH_WORD    0x0002
#define WIDTH_DWORD   0x0004
#define WIDTH_QWORD   0x0008
#define WIDTH_ASCII   0x0101
#define WIDTH_CBUFFER 0x0201

#define ENDIANESS_UNSET  0
#define ENDIANESS_LITTLE 1
#define ENDIANESS_BIG    2

#define SEEK_UNSET    0
#define SEEK_FORWARD  1
#define SEEK_BACKWARD 2

// must be lower than fb_block_size
#define DEFAULT_PRINT_LEN 256

#define get_width_bytes(w) ((w) & 0xff)

#define min(x, y) ((x) < (y) ? (x) : (y))

typedef struct PrintCmdArgs {
    int   width;
    int   endianess;
    int   raw_mode;
    int   seek;
    u64_t n_els;
} PrintCmdArgs;

static void printcmd_dispose(void* obj) { return; }

static void printcmd_help(void* obj)
{
    printf("\nprint: display the data at current offset in various formats\n"
           "\n"
           "  p[/{x,w,d,q}/{le,be}/r/{+,-}] <nelements>\n"
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
           "  (default: enough to display %d bytes)\n\n",
           DEFAULT_PRINT_LEN);
}

int printcmd_parse_args(ParsedCommand* pc, PrintCmdArgs* o_args)
{
    o_args->width     = WIDTH_UNSET;
    o_args->endianess = ENDIANESS_UNSET;
    o_args->seek      = SEEK_UNSET;
    o_args->n_els     = 0;
    o_args->raw_mode  = 0;

    LLNode* curr = pc->cmd_modifiers.head;
    while (curr) {
        if (strcmp((char*)curr->data, "x") == 0) {
            if (o_args->width != WIDTH_UNSET)
                return COMMAND_INVALID_MOD;
            o_args->width = WIDTH_BYTE;
        } else if (strcmp((char*)curr->data, "w") == 0) {
            if (o_args->width != WIDTH_UNSET)
                return COMMAND_INVALID_MOD;
            o_args->width = WIDTH_WORD;
        } else if (strcmp((char*)curr->data, "d") == 0) {
            if (o_args->width != WIDTH_UNSET)
                return COMMAND_INVALID_MOD;
            o_args->width = WIDTH_DWORD;
        } else if (strcmp((char*)curr->data, "q") == 0) {
            if (o_args->width != WIDTH_UNSET)
                return COMMAND_INVALID_MOD;
            o_args->width = WIDTH_QWORD;
        } else if (strcmp((char*)curr->data, "a") == 0) {
            if (o_args->width != WIDTH_UNSET)
                return COMMAND_INVALID_MOD;
            o_args->width = WIDTH_ASCII;
        } else if (strcmp((char*)curr->data, "C") == 0) {
            if (o_args->width != WIDTH_UNSET)
                return COMMAND_INVALID_MOD;
            o_args->width = WIDTH_CBUFFER;
        } else if (strcmp((char*)curr->data, "le") == 0) {
            if (o_args->endianess != ENDIANESS_UNSET)
                return COMMAND_INVALID_MOD;
            o_args->endianess = ENDIANESS_LITTLE;
        } else if (strcmp((char*)curr->data, "be") == 0) {
            if (o_args->endianess != ENDIANESS_UNSET)
                return COMMAND_INVALID_MOD;
            o_args->endianess = ENDIANESS_BIG;
        } else if (strcmp((char*)curr->data, "r") == 0) {
            if (o_args->raw_mode)
                return COMMAND_INVALID_MOD;
            o_args->raw_mode = 1;
        } else if (strcmp((char*)curr->data, "+") == 0) {
            if (o_args->seek != SEEK_UNSET)
                return COMMAND_INVALID_MOD;
            o_args->seek = SEEK_FORWARD;
        } else if (strcmp((char*)curr->data, "-") == 0) {
            if (o_args->seek != SEEK_UNSET)
                return COMMAND_INVALID_MOD;
            o_args->seek = SEEK_BACKWARD;
        } else {
            return COMMAND_UNSUPPORTED_MOD;
        }
        curr = curr->next;
    }

    if (o_args->width == WIDTH_UNSET)
        o_args->width = WIDTH_BYTE;
    if (o_args->endianess == ENDIANESS_UNSET)
        o_args->endianess = ENDIANESS_LITTLE;

    if (pc->args.size > 1)
        return COMMAND_INVALID_ARG;

    if (o_args->n_els == 0)
        o_args->n_els = DEFAULT_PRINT_LEN / get_width_bytes(o_args->width);

    LLNode* arg = ll_getref(&pc->args, 0);
    if (!arg)
        return COMMAND_OK;

    char* s = (char*)arg->data;
    if (!str_to_uint64(s, &o_args->n_els))
        return COMMAND_INVALID_ARG;
    return COMMAND_OK;
}

static void print_ascii(const u8_t* bytes, size_t size, int print_header,
                        int print_footer)
{
    size_t last_newline_off = 0, off = 0, linenum = 0;
    for (off = 0; off < size; off++) {
        if (bytes[off] == '\n')
            last_newline_off = off;
    }

    if (print_header)
        puts("");
    printf("%03lu: ", ++linenum);
    off = 0;
    while (off < last_newline_off) {
        if (is_printable_ascii(bytes[off]) || bytes[off] == '\t' ||
            bytes[off] == '\n')
            printf("%c", bytes[off]);
        else
            printf(".");
        if (bytes[off] == '\n') {
            printf("%03lu: ", ++linenum);
        }
        off += 1;
    }
    if (print_footer)
        printf("\n\n");
}

static void print_c_buffer(const u8_t* bytes, size_t size, int print_header,
                           int print_footer)
{
    if (size == 0)
        return;

    size_t i = 0;
    if (print_header) {
        printf("{ 0x%02x", bytes[0]);
        i = 1;
    }
    for (; i < size; ++i)
        printf(", 0x%02x", bytes[i]);
    if (print_footer)
        printf(" }\n");
}

static void print_hex(const u8_t* bytes, size_t size, int raw_mode,
                      int print_header, int print_footer, u64_t addr)
{
    static int block_size = 16;
    size_t     off        = 0;

    if (!raw_mode && print_header)
        printf("\n"
               "       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
               "       -----------------------------------------------\n");
    while (off < size) {
        if (!raw_mode)
            printf(" %04llx: ", (u64_t)off + addr);
        int i;
        for (i = 0; i < block_size; ++i) {
            if (off + i >= size) {
                for (; i < block_size; ++i)
                    printf("   ");
                break;
            }
            if (!raw_mode)
                printf("%02X ", bytes[off + i]);
            else
                printf("0x%02X ", bytes[off + i]);
        }
        if (!raw_mode) {
            printf("  ");
            for (i = 0; i < block_size; ++i) {
                if (off + i >= size)
                    break;
                printf("%c", get_printable_ascii_or_dot((u8_t)bytes[off + i]));
            }
            printf("\n");
        }
        off += block_size;
    }
    if (print_footer)
        printf("\n");
}

static void print_words(const u8_t* bytes, size_t size, int little_endian,
                        int raw_mode, int print_header, int print_footer,
                        u64_t addr)
{
    static int block_size = 16;
    size_t     off        = 0;

    if (!raw_mode && print_header)
        printf("\n"
               "       00    02    04    06    08    0A    0C    0E   \n"
               "       -----------------------------------------------\n");
    while (off < size) {
        if (!raw_mode)
            printf(" %04llx: ", (u64_t)off + addr);
        int i;
        for (i = 0; i < block_size; i += 2) {
            if (off + i + 1 >= size)
                break;
            u16_t w = little_endian ? read_at_le16(bytes + off, i)
                                    : read_at_be16(bytes + off, i);
            if (!raw_mode)
                printf("%04Xh ", w);
            else
                printf("0x%04X ", w);
        }
        if (!raw_mode)
            printf("\n");
        off += block_size;
    }
    if (print_footer)
        printf("\n");
}

static void print_dwords(const u8_t* bytes, size_t size, int little_endian,
                         int raw_mode, int print_header, int print_footer,
                         u64_t addr)
{
    static int block_size = 16;
    size_t     off        = 0;

    if (!raw_mode && print_header)
        printf("\n"
               "       00        04        08        0C       \n"
               "       ---------------------------------------\n");
    while (off < size) {
        if (!raw_mode)
            printf(" %04llx: ", (u64_t)off + addr);
        int i;
        for (i = 0; i < block_size; i += 4) {
            if (off + i + 3 >= size)
                break;
            u32_t dw = little_endian ? read_at_le32(bytes + off, i)
                                     : read_at_be32(bytes + off, i);
            if (!raw_mode)
                printf("%08Xh ", dw);
            else
                printf("0x%08X ", dw);
        }
        if (!raw_mode)
            printf("\n");
        off += block_size;
    }
    if (print_footer)
        printf("\n");
}

static void print_qwords(const u8_t* bytes, size_t size, int little_endian,
                         int raw_mode, int print_header, int print_footer,
                         u64_t addr)
{
    static int block_size = 16;
    size_t     off        = 0;

    if (!raw_mode && print_header)
        printf("\n"
               "       00                08               \n"
               "       -----------------------------------\n");
    while (off < size) {
        if (!raw_mode)
            printf(" %04llx: ", (u64_t)off + addr);
        int i;
        for (i = 0; i < block_size; i += 8) {
            if (off + i + 7 >= size)
                break;
            u64_t dw = little_endian ? read_at_le64(bytes + off, i)
                                     : read_at_be64(bytes + off, i);
            if (!raw_mode)
                printf("%016llXh ", dw);
            else
                printf("0x%016llX ", dw);
        }
        if (!raw_mode)
            printf("\n");
        off += block_size;
    }
    if (print_footer)
        printf("\n");
}

static int printcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    PrintCmdArgs args;
    int          r = printcmd_parse_args(pc, &args);
    if (r != COMMAND_OK)
        return r;

    size_t size =
        min(args.n_els * get_width_bytes(args.width), fb->size - fb->off);
    if (args.width == WIDTH_ASCII)
        // FIXME: ASCII does not support the size argument
        //        but it should take the number of raws to be printed as
        //        parameter
        size = fb_block_size;

    u64_t  addr           = 0;
    size_t remaining_size = size;
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
                print_ascii(bytes, read_size, print_header, print_footer);
                break;
        }
        remaining_size -= read_size;
        addr += read_size;
    }
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

    cmd->dispose = printcmd_dispose;
    cmd->help    = printcmd_help;
    cmd->exec    = printcmd_exec;

    return cmd;
}
