// Copyright (c) 2022-2026, bageyelet

#include <util/byte_to_str.h>
#include <string.h>
#include <util/byte_to_num.h>
#include <display.h>
#include <color.h>
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
    "  algorithm: hashing algorithm, or a part of one to run a family "        \
    "('md' runs md2 to md6-512), or '*' for all of them\n"                     \
    "  size: number of bytes to include in the hash (if omitted or "           \
    "zero, hash the whole file starting from current offset)\n"                \
    "  off:  starting offset wrt to current offset (default 0)\n"

// How a name given on the command line is matched against the registry. The
// narrowest tier that matches anything is the one used, so that the obvious
// reading wins: "skein-512" names one algorithm even though it is also the
// start of "skein-512-256", and "md" is the MD family and not RipeMD too.
// Matching anywhere in the name is still there, for "hh 256" and the like.
typedef enum MatchTier {
    MATCH_EXACT = 0,
    MATCH_PREFIX,
    MATCH_ANYWHERE,
    MATCH_TIER_COUNT
} MatchTier;

static int name_matches(const char* name, const char* query, MatchTier tier)
{
    switch (tier) {
        case MATCH_EXACT:
            return striequal(name, query);
        case MATCH_PREFIX:
            return striprefix(name, query);
        default:
            return stristr(name, query) != NULL;
    }
}

// The tier the query ends up being read at: the first one that names
// something. A query that matches nothing anywhere reports no algorithm, as
// it did before.
static MatchTier pick_tier(const hash_handler_t* hashes, size_t n_hashes,
                           const char* query)
{
    for (MatchTier t = MATCH_EXACT; t < MATCH_ANYWHERE; ++t)
        for (size_t i = 0; i < n_hashes; ++i)
            if (name_matches(hashes[i].name, query, t))
                return t;
    return MATCH_ANYWHERE;
}

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
            display_printf("  %s%s%s\n", color_str(COLOR_CMD), hashes[i].name,
                           color_str(COLOR_RESET));

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

    int       all = strcmp(algorithm, "*") == 0;
    MatchTier tier =
        all ? MATCH_ANYWHERE : pick_tier(hashes, n_hashes, algorithm);

    for (size_t i = 0; i < n_hashes; ++i) {
        if (all || name_matches(hashes[i].name, algorithm, tier)) {
            char* hash = NULL;
            hashes[i].handler(fb, real_off, size, &hash);
            if (hash) {
                // the escapes wrap the padded name, so that they do not
                // eat into the width of the column
                display_printf("  %s%13s%s : %s\n", color_str(COLOR_LABEL),
                               hashes[i].name, color_str(COLOR_RESET), hash);
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
