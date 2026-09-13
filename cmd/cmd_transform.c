// Copyright (c) 2022-2026, bageyelet

#include "cmd_arg_handler.h"
#include "cmd_transform.h"
#include "cmd.h"

#include <util/byte_to_num.h>
#include <util/str.h>
#include <filebuffer.h>
#include <display.h>
#include <string.h>
#include <alloc.h>
#include <defs.h>
#include <log.h>

#define HINT_STR                                                               \
    "[/{xor,and,or,add,sub,not,rol,ror,rev,swap}/{x,s}] [<arg>] [<size>]"

#define OP_XOR  0
#define OP_AND  1
#define OP_OR   2
#define OP_ADD  3
#define OP_SUB  4
#define OP_NOT  5
#define OP_ROL  6
#define OP_ROR  7
#define OP_REV  8
#define OP_SWAP 9

#define KEY_TYPE_HEX    0
#define KEY_TYPE_STRING 1

static void transformcmd_dispose(void* obj) { return; }

static void transformcmd_help(void* obj)
{
    display_printf(
        "transform: transform the bytes at current offset in place\n"
        "\n"
        "  tr" HINT_STR "\n"
        "     xor:  xor every byte with the key (default)\n"
        "     and:  bitwise and with the key\n"
        "     or:   bitwise or with the key\n"
        "     add:  add the key to every byte\n"
        "     sub:  subtract the key from every byte\n"
        "     not:  complement every byte (takes no arg)\n"
        "     rol:  rotate every byte left by <arg> bits\n"
        "     ror:  rotate every byte right by <arg> bits\n"
        "     rev:  reverse the order of the bytes (takes no arg)\n"
        "     swap: reverse the byte order of every group of <arg> bytes\n"
        "     x:    the key is a hex string (default)\n"
        "     s:    the key is a string\n"
        "\n"
        "  arg:  the key of xor/and/or/add/sub, the number of bits of\n"
        "        rol/ror, or the group size of swap (2, 4 or 8). The key\n"
        "        is repeated over the region, the others are plain numbers\n"
        "  size: number of bytes to transform (if omitted, all the\n"
        "        remaining bytes)\n"
        "\n"
        "  The result is an ordinary pending write: 'c/l' lists it, 'u'\n"
        "  undoes it and nothing reaches the file until 'c'\n"
        "\n"
        "  Here are some examples:\n"
        "      tr/xor \"de ad be ef\"\n"
        "      tr/xor/s mykey 0x100\n"
        "      tr/not\n"
        "      tr/swap 4 0x40\n");
}

// Applies the operation to every byte of `buf`, with the key repeated over it
static void apply_bytewise(int op, u8_t* buf, u64_t size, const u8_t* key,
                           size_t key_size)
{
    for (u64_t i = 0; i < size; ++i) {
        u8_t k = key_size ? key[i % key_size] : 0;
        switch (op) {
            case OP_XOR:
                buf[i] ^= k;
                break;
            case OP_AND:
                buf[i] &= k;
                break;
            case OP_OR:
                buf[i] |= k;
                break;
            case OP_ADD:
                buf[i] = (u8_t)(buf[i] + k);
                break;
            case OP_SUB:
                buf[i] = (u8_t)(buf[i] - k);
                break;
            case OP_NOT:
                buf[i] = (u8_t)~buf[i];
                break;
            case OP_ROL:
                if (k)
                    buf[i] = (u8_t)((buf[i] << k) | (buf[i] >> (8 - k)));
                break;
            case OP_ROR:
                if (k)
                    buf[i] = (u8_t)((buf[i] >> k) | (buf[i] << (8 - k)));
                break;
        }
    }
}

static void apply_reverse(u8_t* buf, u64_t size)
{
    for (u64_t i = 0; i < size / 2; ++i) {
        u8_t t            = buf[i];
        buf[i]            = buf[size - 1 - i];
        buf[size - 1 - i] = t;
    }
}

static void apply_swap(u8_t* buf, u64_t size, u64_t group)
{
    for (u64_t off = 0; off + group <= size; off += group)
        apply_reverse(buf + off, group);
}

// Reads [off, off + size) into a buffer the caller owns. fb_read() serves at
// most one block per call, so a region of any size is gathered block by block
static u8_t* read_region(FileBuffer* fb, u64_t off, u64_t size)
{
    u8_t* buf  = bhex_malloc(size);
    u64_t done = 0;
    while (done < size) {
        u64_t chunk = size - done;
        if (chunk > fb_block_size)
            chunk = fb_block_size;

        const u8_t* data = fb_read_at(fb, off + done, chunk);
        if (data == NULL) {
            bhex_free(buf);
            return NULL;
        }
        memcpy(buf + done, data, chunk);
        done += chunk;
    }
    return buf;
}

static int transformcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    int op       = OP_XOR;
    int key_type = KEY_TYPE_HEX;
    if (handle_mods(pc, "xor,and,or,add,sub,not,rol,ror,rev,swap|x,s", &op,
                    &key_type) != 0)
        return COMMAND_INVALID_MOD;

    // 'not' and 'rev' operate on the bytes alone, so their only argument is
    // the size: every other operation needs its key or its count first
    int takes_arg = (op != OP_NOT && op != OP_REV);

    char* arg_str  = NULL;
    char* size_str = NULL;
    if (takes_arg) {
        if (handle_args(pc, 2, 1, &arg_str, &size_str) != 0)
            return COMMAND_INVALID_ARG;
    } else {
        if (handle_args(pc, 1, 0, &size_str) != 0)
            return COMMAND_INVALID_ARG;
    }

    u64_t size = fb->size - fb->off;
    if (size_str != NULL) {
        u64_t requested;
        if (!str_to_uint64(size_str, &requested))
            return COMMAND_INVALID_ARG;
        if (requested > size) {
            error("the file has only %llu bytes left at this offset", size);
            return COMMAND_INVALID_ARG;
        }
        size = requested;
    }
    if (size == 0) {
        error("nothing to transform");
        return COMMAND_INVALID_ARG;
    }

    u8_t*  key      = NULL;
    size_t key_size = 0;
    u64_t  num      = 0;
    switch (op) {
        case OP_ROL:
        case OP_ROR:
            if (!str_to_uint64(arg_str, &num))
                return COMMAND_INVALID_ARG;
            // a rotation of a multiple of 8 is the identity, and shifting a
            // byte by 8 is undefined behavior: fold it away
            num %= 8;
            break;
        case OP_SWAP:
            if (!str_to_uint64(arg_str, &num))
                return COMMAND_INVALID_ARG;
            if (num != 2 && num != 4 && num != 8) {
                error("the group size must be 2, 4 or 8");
                return COMMAND_INVALID_ARG;
            }
            if (size % num != 0) {
                error("the size must be a multiple of the group size");
                return COMMAND_INVALID_ARG;
            }
            break;
        case OP_NOT:
        case OP_REV:
            break;
        default:
            if (key_type == KEY_TYPE_HEX) {
                if (!hex_to_bytes(arg_str, &key, &key_size))
                    return COMMAND_INVALID_ARG;
            } else {
                if (!unescape_ascii_string(arg_str, &key, &key_size))
                    return COMMAND_INVALID_ARG;
            }
            if (key_size == 0) {
                bhex_free(key);
                error("the key is empty");
                return COMMAND_INVALID_ARG;
            }
            break;
    }

    u8_t* buf = read_region(fb, fb->off, size);
    if (buf == NULL) {
        bhex_free(key);
        error("unable to read the data to transform");
        return COMMAND_INVALID_ARG;
    }

    switch (op) {
        case OP_REV:
            apply_reverse(buf, size);
            break;
        case OP_SWAP:
            apply_swap(buf, size, num);
            break;
        case OP_ROL:
        case OP_ROR: {
            u8_t bits = (u8_t)num;
            apply_bytewise(op, buf, size, &bits, 1);
            break;
        }
        default:
            apply_bytewise(op, buf, size, key, key_size);
            break;
    }
    bhex_free(key);

    // one write for the whole region, so that a single 'u' undoes it
    if (!fb_write(fb, buf, size)) {
        bhex_free(buf);
        return COMMAND_INVALID_ARG;
    }
    return COMMAND_OK;
}

Cmd* transformcmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "transform";
    cmd->alias = "tr";
    cmd->hint  = HINT_STR;

    cmd->dispose = transformcmd_dispose;
    cmd->help    = transformcmd_help;
    cmd->exec    = transformcmd_exec;

    return cmd;
}
