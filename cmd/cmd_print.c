#include "cmd_print.h"
#include "util/byte_to_str.h"
#include "util/byte_to_num.h"
#include "util/endian.h"
#include "../alloc.h"

#include <string.h>

#define WIDTH_UNSET 0
#define WIDTH_BYTE  1
#define WIDTH_WORD  2
#define WIDTH_DWORD 4
#define WIDTH_QWORD 8

#define ENDIANESS_UNSET  0
#define ENDIANESS_LITTLE 1
#define ENDIANESS_BIG    2

#define min(x, y) ((x) < (y) ? (x) : (y))

typedef struct PrintCmdArgs {
    int   width;
    int   endianess;
    u64_t n_els;
} PrintCmdArgs;

static void printcmd_dispose(void* obj) { return; }

static void printcmd_help(void* obj)
{
    printf("\nprint: display the data at current offset in various formats\n"
           "\n"
           "  p[/{x,w,d,q}/{le,be}] <nelements>\n"
           "     x:  hex output (default)\n"
           "     w:  words\n"
           "     d:  dwords\n"
           "     q:  qwords\n"
           "     le: little-endian (default)\n"
           "     be: big-endian\n"
           "\n"
           "  nelements: the number of elements to display\n"
           "  (default: enough to display %d bytes)\n\n",
           fb_block_size);
}

int printcmd_parse_args(ParsedCommand* pc, PrintCmdArgs* o_args)
{
    o_args->width     = WIDTH_UNSET;
    o_args->endianess = ENDIANESS_UNSET;
    o_args->n_els     = 0;

    LLNode* curr = pc->cmd_modifiers.head;
    while (curr) {
        if (strcmp((char*)curr->data, "x") == 0) {
            if (o_args->width != WIDTH_UNSET)
                return COMMAND_INVALID_MODE;
            o_args->width = WIDTH_BYTE;
        } else if (strcmp((char*)curr->data, "w") == 0) {
            if (o_args->width != WIDTH_UNSET)
                return COMMAND_INVALID_MODE;
            o_args->width = WIDTH_WORD;
        } else if (strcmp((char*)curr->data, "d") == 0) {
            if (o_args->width != WIDTH_UNSET)
                return COMMAND_INVALID_MODE;
            o_args->width = WIDTH_DWORD;
        } else if (strcmp((char*)curr->data, "q") == 0) {
            if (o_args->width != WIDTH_UNSET)
                return COMMAND_INVALID_MODE;
            o_args->width = WIDTH_QWORD;
        } else if (strcmp((char*)curr->data, "le") == 0) {
            if (o_args->endianess != ENDIANESS_UNSET)
                return COMMAND_INVALID_MODE;
            o_args->endianess = ENDIANESS_LITTLE;
        } else if (strcmp((char*)curr->data, "be") == 0) {
            if (o_args->endianess != ENDIANESS_UNSET)
                return COMMAND_INVALID_MODE;
            o_args->endianess = ENDIANESS_BIG;
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
        o_args->n_els = fb_block_size / o_args->width;

    LLNode* arg = ll_getref(&pc->args, 0);
    if (!arg)
        return COMMAND_OK;

    char* s = (char*)arg->data;
    if (!str_to_uint64(s, &o_args->n_els))
        return COMMAND_INVALID_ARG;
    return COMMAND_OK;
}

static void print_hex(const u8_t* bytes, size_t size)
{
    static int block_size = 16;
    size_t     off        = 0;

    printf("\n"
           "       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
           "       -----------------------------------------------\n");
    while (off < size) {
        printf(" %04llx: ", (u64_t)off);
        int i;
        for (i = 0; i < block_size; ++i) {
            if (off + i >= size) {
                for (; i < block_size; ++i)
                    printf("   ");
                break;
            }
            printf("%02X ", bytes[off + i]);
        }
        printf("  ");
        for (i = 0; i < block_size; ++i) {
            if (off + i >= size)
                break;
            printf("%c", get_printable_ascii_or_dot((u8_t)bytes[off + i]));
        }
        printf("\n");
        off += block_size;
    }
    printf("\n");
}

static void print_words(const u8_t* bytes, size_t size, int little_endian)
{
    static int block_size = 16;
    size_t     off        = 0;

    printf("\n"
           "       00    02    04    06    08    0A    0C    0E   \n"
           "       -----------------------------------------------\n");
    while (off < size) {
        printf(" %04llx: ", (u64_t)off);
        int i;
        for (i = 0; i < block_size; i += 2) {
            if (off + i + 1 >= size)
                break;
            u16_t w = little_endian ? read_at_le16(bytes + off, i)
                                    : read_at_be16(bytes + off, i);
            printf("%04Xh ", w);
        }
        printf("\n");
        off += block_size;
    }
    printf("\n");
}

static void print_dwords(const u8_t* bytes, size_t size, int little_endian)
{
    static int block_size = 16;
    size_t     off        = 0;

    printf("\n"
           "       00        04        08        0C       \n"
           "       ---------------------------------------\n");
    while (off < size) {
        printf(" %04llx: ", (u64_t)off);
        int i;
        for (i = 0; i < block_size; i += 4) {
            if (off + i + 3 >= size)
                break;
            u32_t dw = little_endian ? read_at_le32(bytes + off, i)
                                     : read_at_be32(bytes + off, i);
            printf("%08Xh ", dw);
        }
        printf("\n");
        off += block_size;
    }
    printf("\n");
}

static void print_qwords(const u8_t* bytes, size_t size, int little_endian)
{
    static int block_size = 16;
    size_t     off        = 0;

    printf("\n"
           "       00                08               \n"
           "       -----------------------------------\n");
    while (off < size) {
        printf(" %04llx: ", (u64_t)off);
        int i;
        for (i = 0; i < block_size; i += 8) {
            if (off + i + 7 >= size)
                break;
            u64_t dw = little_endian ? read_at_le64(bytes + off, i)
                                     : read_at_be64(bytes + off, i);
            printf("%016llXh ", dw);
        }
        printf("\n");
        off += block_size;
    }
    printf("\n");
}

static int printcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    PrintCmdArgs args;
    int          r = printcmd_parse_args(pc, &args);
    if (r != COMMAND_OK)
        return r;

    size_t      size  = min(args.n_els * args.width, fb->size - fb->off);
    const u8_t* bytes = fb_read(fb, size);

    switch (args.width) {
        case WIDTH_UNSET:
        case WIDTH_BYTE:
            print_hex(bytes, size);
            break;
        case WIDTH_WORD:
            print_words(bytes, size, args.endianess == ENDIANESS_LITTLE);
            break;
        case WIDTH_DWORD:
            print_dwords(bytes, size, args.endianess == ENDIANESS_LITTLE);
            break;
        case WIDTH_QWORD:
            print_qwords(bytes, size, args.endianess == ENDIANESS_LITTLE);
            break;
    }

    return COMMAND_OK;
}

Cmd* printcmd_create()
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
