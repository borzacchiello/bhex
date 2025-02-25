#include "cmd_write.h"
#include "cmd.h"
#include "cmd_arg_handler.h"

#include <util/byte_to_num.h>
#include <util/endian.h>
#include <util/str.h>
#include <display.h>
#include <string.h>
#include <alloc.h>

#define HINT_STR "[/{s,x,b,w,d,q}/{le,be}/u/i] <data>"

#define INPUT_TYPE_UNSET  -1
#define INPUT_TYPE_STRING 0
#define INPUT_TYPE_HEX    1
#define INPUT_TYPE_BYTE   2
#define INPUT_TYPE_WORD   3
#define INPUT_TYPE_DWORD  4
#define INPUT_TYPE_QWORD  5

#define ENDIANESS_UNSET  -1
#define ENDIANESS_LITTLE 0
#define ENDIANESS_BIG    1

#define UNSIGN_UNSET -1
#define UNSIGN_SET   0

#define INSERT_UNSET -1
#define INSERT_SET   0

typedef struct WriteArg {
    u8_t*  data;
    size_t size;
    int    insert;
} WriteArg;

static void writecmd_help(void* obj)
{
    display_printf(
        "\nwrite: write data at current offset\n"
        "\n"
        "  w" HINT_STR "\n"
        "     s:   string input (default)\n"
        "     x:   hex input\n"
        "     b:   byte\n"
        "     w:   word\n"
        "     d:   dword\n"
        "     q:   qword\n"
        "     le:  little-endian (default)\n"
        "     be:  big-endian\n"
        "     u:   unsigned\n"
        "     i:   insert\n"
        "\n"
        "  data: the data to write. The format depends on the type of \n"
        "        write. Here there are some examples:\n"
        "            w/x \"00 01 02 03\"\n"
        "            w/s \"a string\"\n"
        "            w/q/be 0x1234\n"
        "\n");
}

static int parse_write_arg(ParsedCommand* pc, WriteArg* o_arg)
{
    int input_type = INPUT_TYPE_STRING;
    int endianess  = ENDIANESS_LITTLE;
    int unsign     = UNSIGN_UNSET;
    int insert     = INSERT_UNSET;

    if (handle_mods(pc, "s,x,b,w,d,q|le,be|u|i", &input_type, &endianess,
                    &unsign, &insert) != 0)
        return COMMAND_INVALID_MOD;
    unsign = unsign == UNSIGN_SET ? 1 : 0;
    insert = insert == UNSIGN_SET ? 1 : 0;

    o_arg->data = NULL;
    if (handle_args(pc, 1, 1, &o_arg->data) != 0)
        return COMMAND_INVALID_ARG;

    char* data_str = (char*)o_arg->data;
    switch (input_type) {
        case INPUT_TYPE_STRING:
            if (!unescape_ascii_string(data_str, &o_arg->data, &o_arg->size))
                return COMMAND_INVALID_ARG;
            break;
        case INPUT_TYPE_HEX:
            if (!hex_to_bytes(data_str, &o_arg->data, &o_arg->size))
                return COMMAND_INVALID_ARG;
            break;
        case INPUT_TYPE_BYTE:
            o_arg->data = bhex_malloc(1);
            o_arg->size = 1;
            if (unsign) {
                u8_t b;
                if (!str_to_uint8(data_str, &b))
                    return COMMAND_INVALID_ARG;
                write8(o_arg->data, b);
            } else {
                s8_t b;
                if (!str_to_int8(data_str, &b))
                    return COMMAND_INVALID_ARG;
                write8(o_arg->data, b);
            }
            break;
        case INPUT_TYPE_WORD:
            o_arg->data = bhex_malloc(2);
            o_arg->size = 2;
            if (unsign) {
                u16_t w;
                if (!str_to_uint16(data_str, &w))
                    return COMMAND_INVALID_ARG;
                if (endianess == ENDIANESS_LITTLE)
                    write_le16(o_arg->data, w);
                else
                    write_be16(o_arg->data, w);
            } else {
                s16_t w;
                if (!str_to_int16(data_str, &w))
                    return COMMAND_INVALID_ARG;
                if (endianess == ENDIANESS_LITTLE)
                    write_le16(o_arg->data, w);
                else
                    write_be16(o_arg->data, w);
            }
            break;
        case INPUT_TYPE_DWORD:
            o_arg->data = bhex_malloc(4);
            o_arg->size = 4;
            if (unsign) {
                u32_t d;
                if (!str_to_uint32(data_str, &d))
                    return COMMAND_INVALID_ARG;
                if (endianess == ENDIANESS_LITTLE)
                    write_le32(o_arg->data, d);
                else
                    write_be32(o_arg->data, d);
            } else {
                s32_t d;
                if (!str_to_int32(data_str, &d))
                    return COMMAND_INVALID_ARG;
                if (endianess == ENDIANESS_LITTLE)
                    write_le32(o_arg->data, d);
                else
                    write_be32(o_arg->data, d);
            }
            break;
        case INPUT_TYPE_QWORD:
            o_arg->data = bhex_malloc(8);
            o_arg->size = 8;
            if (unsign) {
                u64_t q;
                if (!str_to_uint64(data_str, &q))
                    return COMMAND_INVALID_ARG;
                if (endianess == ENDIANESS_LITTLE)
                    write_le64(o_arg->data, q);
                else
                    write_be64(o_arg->data, q);
            } else {
                s64_t q;
                if (!str_to_int64(data_str, &q))
                    return COMMAND_INVALID_ARG;
                if (endianess == ENDIANESS_LITTLE)
                    write_le64(o_arg->data, q);
                else
                    write_be64(o_arg->data, q);
            }
            break;
    }

    o_arg->insert = insert;
    return COMMAND_OK;
}

static void writecmd_dispose(void* obj) { return; }

static int writecmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    WriteArg arg;
    int      r = parse_write_arg(pc, &arg);
    if (r != COMMAND_OK) {
        bhex_free(arg.data);
        return r;
    }

    if (arg.insert) {
        if (!fb_insert(fb, arg.data, arg.size)) {
            bhex_free(arg.data);
            return COMMAND_INVALID_ARG;
        }
    } else {
        if (!fb_write(fb, arg.data, arg.size)) {
            bhex_free(arg.data);
            return COMMAND_INVALID_ARG;
        }
    }
    return COMMAND_OK;
}

Cmd* writecmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "write";
    cmd->alias = "w";
    cmd->hint  = HINT_STR;

    cmd->dispose = writecmd_dispose;
    cmd->help    = writecmd_help;
    cmd->exec    = writecmd_exec;

    return cmd;
}
