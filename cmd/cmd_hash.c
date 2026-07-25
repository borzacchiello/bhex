// Copyright (c) 2022-2026, bageyelet

#include <util/byte_to_str.h>
#include <string.h>
#include <util/byte_to_num.h>
#include <display.h>
#include <alloc.h>
#include <defs.h>
#include <log.h>

#include "cmd_arg_handler.h"
#include "cmd_hash.h"

#include <hash/hash_registry.h>

#include <util/str.h>

#define LIST_SET 0

#define HINT_STR "/l <algorithm> [ <size> <off> ]"
#define HELP_STR                                                               \
    "hash: calculate the hash of <size> bytes at current offset + <off>\n"     \
    "\n"                                                                       \
    "  hash " HINT_STR "\n"                                                    \
    "     l:  list the supported hashing algorithms\n"                         \
    "\n"                                                                       \
    "  algorithm: hashing algorithm (or '*' to use all supported "             \
    "algorithms)\n"                                                            \
    "  size: number of bytes to include in the hash (if omitted or "           \
    "zero, hash the whole file starting from current offset)\n"                \
    "  off:  starting offset wrt to current offset (default 0)\n"

static void hashcmd_dispose(void* obj) { return; }

static void hashcmd_help(void* obj) { display_printf(HELP_STR); }

static int hashcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    int list = -1;
    if (handle_mods(pc, "l", &list) != 0)
        return COMMAND_INVALID_MOD;

    if (list == LIST_SET) {
        if (handle_args(pc, 0, 0) != 0)
            return COMMAND_INVALID_ARG;

        size_t                n_hashes;
        const hash_handler_t* hashes = get_all_hashes(&n_hashes);
        for (size_t i = 0; i < n_hashes; ++i)
            display_printf("  %s\n", hashes[i].name);

        return COMMAND_OK;
    }

    char* algorithm  = NULL;
    char* size_str   = NULL;
    char* offset_str = NULL;
    if (handle_args(pc, 3, 1, &algorithm, &size_str, &offset_str) != 0)
        return COMMAND_INVALID_ARG;

    u64_t size = fb->size - fb->off;
    u64_t off  = 0;
    if (size_str) {
        if (!str_to_uint64(size_str, &size)) {
            error("invalid number '%s'", size_str);
            return COMMAND_INVALID_ARG;
        }
    }
    if (offset_str) {
        if (!str_to_uint64(offset_str, &off)) {
            error("invalid number '%s'", offset_str);
            return COMMAND_INVALID_ARG;
        }
    }

    if (size > fb->size - fb->off) {
        error("invalid size, exceeding file size");
        return COMMAND_INVALID_ARG;
    }

    if (off > fb->size - fb->off) {
        error("invalid offset, exceeding file size");
        return COMMAND_INVALID_ARG;
    }

    u64_t real_off = fb->off + off;
    if (real_off + size > fb->size) {
        error("calculated offset exceeds file size");
        return COMMAND_INVALID_ARG;
    }

    size_t                n_hashes;
    const hash_handler_t* hashes = get_all_hashes(&n_hashes);
    for (size_t i = 0; i < n_hashes; ++i) {
        if (strcmp(algorithm, "*") == 0 ||
            stristr(hashes[i].name, algorithm) != NULL) {
            char* hash = NULL;
            hashes[i].handler(fb, real_off, size, &hash);
            if (hash) {
                display_printf("  %12s : %s\n", hashes[i].name, hash);
                bhex_free(hash);
            } else {
                error("error calculating %s hash", hashes[i].name);
                return COMMAND_INTERNAL_ERROR;
            }
        }
    }
    return COMMAND_OK;
}

Cmd* hashcmd_create()
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "hash";
    cmd->alias = "hh";
    cmd->hint  = HINT_STR;

    cmd->dispose = hashcmd_dispose;
    cmd->help    = hashcmd_help;
    cmd->exec    = hashcmd_exec;
    return cmd;
}
