#include "cmd_seek.h"
#include "util/str.h"
#include "util/endian.h"
#include "util/byte_to_num.h"

#include "../alloc.h"
#include "../log.h"

#include <string.h>

#define INPUT_TYPE_UNSET  0
#define INPUT_TYPE_STRING 1
#define INPUT_TYPE_HEX    2
#define INPUT_TYPE_BYTE   3
#define INPUT_TYPE_WORD   4
#define INPUT_TYPE_DWORD  5
#define INPUT_TYPE_QWORD  6

#define ENDIANESS_UNSET  0
#define ENDIANESS_LITTLE 1
#define ENDIANESS_BIG    2

typedef struct WriteArg {
    u8_t*  data;
    size_t size;
} WriteArg;

static void writecmd_help(void* obj)
{
    printf("\nwrite: write data at current offset\n"
           "\n"
           "  w[{s,x,b,w,d,q}/{le,be}/u] <data>\n"
           "     s:   string input (default)\n"
           "     x:   hex input\n"
           "     b:   byte\n"
           "     w:   word\n"
           "     d:   dword\n"
           "     q:   qword\n"
           "     le:  little-endian (default)\n"
           "     be:  big-endian\n"
           "     u:   unsigned\n"
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
    int input_type = INPUT_TYPE_UNSET;
    int endiness   = ENDIANESS_UNSET;
    int unsign     = 0;

    LLNode* curr = pc->cmd_modifiers.head;
    while (curr) {
        if (strcmp((char*)curr->data, "s") == 0) {
            if (input_type != INPUT_TYPE_UNSET)
                return COMMAND_INVALID_MODE;
            input_type = INPUT_TYPE_STRING;
        } else if (strcmp((char*)curr->data, "x") == 0) {
            if (input_type != INPUT_TYPE_UNSET)
                return COMMAND_INVALID_MODE;
            input_type = INPUT_TYPE_HEX;
        } else if (strcmp((char*)curr->data, "b") == 0) {
            if (input_type != INPUT_TYPE_UNSET)
                return COMMAND_INVALID_MODE;
            input_type = INPUT_TYPE_BYTE;
        } else if (strcmp((char*)curr->data, "w") == 0) {
            if (input_type != INPUT_TYPE_UNSET)
                return COMMAND_INVALID_MODE;
            input_type = INPUT_TYPE_WORD;
        } else if (strcmp((char*)curr->data, "d") == 0) {
            if (input_type != INPUT_TYPE_UNSET)
                return COMMAND_INVALID_MODE;
            input_type = INPUT_TYPE_DWORD;
        } else if (strcmp((char*)curr->data, "q") == 0) {
            if (input_type != INPUT_TYPE_UNSET)
                return COMMAND_INVALID_MODE;
            input_type = INPUT_TYPE_QWORD;
        } else if (strcmp((char*)curr->data, "le") == 0) {
            if (endiness != ENDIANESS_UNSET)
                return COMMAND_INVALID_MODE;
            endiness = ENDIANESS_LITTLE;
        } else if (strcmp((char*)curr->data, "be") == 0) {
            if (endiness != ENDIANESS_UNSET)
                return COMMAND_INVALID_MODE;
            endiness = ENDIANESS_BIG;
        } else if (strcmp((char*)curr->data, "u") == 0) {
            if (unsign)
                return COMMAND_INVALID_MODE;
            unsign = 1;
        } else {
            return COMMAND_UNSUPPORTED_MOD;
        }
        curr = curr->next;
    }

    if (input_type == INPUT_TYPE_UNSET)
        input_type = INPUT_TYPE_STRING;

    if (endiness == ENDIANESS_UNSET)
        endiness = ENDIANESS_LITTLE;

    if (pc->args.size != 1)
        return COMMAND_INVALID_ARG;
    LLNode* arg = ll_getref(&pc->args, 0);
    if (!arg)
        return COMMAND_INVALID_ARG;

    char* data_str = (char*)arg->data;
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
                if (endiness == ENDIANESS_LITTLE)
                    write_le16(o_arg->data, w);
                else
                    write_be16(o_arg->data, w);
            } else {
                s16_t w;
                if (!str_to_int16(data_str, &w))
                    return COMMAND_INVALID_ARG;
                if (endiness == ENDIANESS_LITTLE)
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
                if (endiness == ENDIANESS_LITTLE)
                    write_le32(o_arg->data, d);
                else
                    write_be32(o_arg->data, d);
            } else {
                s32_t d;
                if (!str_to_int32(data_str, &d))
                    return COMMAND_INVALID_ARG;
                if (endiness == ENDIANESS_LITTLE)
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
                if (endiness == ENDIANESS_LITTLE)
                    write_le64(o_arg->data, q);
                else
                    write_be64(o_arg->data, q);
            } else {
                s64_t q;
                if (!str_to_int64(data_str, &q))
                    return COMMAND_INVALID_ARG;
                if (endiness == ENDIANESS_LITTLE)
                    write_le64(o_arg->data, q);
                else
                    write_be64(o_arg->data, q);
            }
            break;
    }
    return COMMAND_OK;
}

static void writecmd_dispose(void* obj) { return; }

static int writecmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    WriteArg arg;
    int      r = parse_write_arg(pc, &arg);
    if (r != COMMAND_OK)
        return r;

    if (!fb_add_modification(fb, arg.data, arg.size)) {
        warning("unable to write: the data exceeds the size of the file");
        return COMMAND_INVALID_ARG;
    }
    return COMMAND_OK;
}

Cmd* writecmd_create()
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "write";
    cmd->alias = "w";

    cmd->dispose = writecmd_dispose;
    cmd->help    = writecmd_help;
    cmd->exec    = writecmd_exec;

    return cmd;
}
