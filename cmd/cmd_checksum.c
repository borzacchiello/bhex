// Copyright (c) 2022-2026, bageyelet

#include "cmd_arg_handler.h"
#include "cmd_checksum.h"
#include "cmd.h"

#include <util/byte_to_num.h>
#include <util/str.h>

#include <filebuffer.h>
#include <checksums.h>
#include <display.h>
#include <string.h>
#include <alloc.h>
#include <defs.h>
#include <log.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

#define LIST_SET 0

#define HINT_STR "[/l] <name> [<size> <off>]"

static void checksumcmd_dispose(void* obj) { return; }

static void checksumcmd_help(void* obj)
{
    display_printf(
        "checksum: calculate a checksum at current offset + <off>\n"
        "\n"
        "  checksum " HINT_STR "\n"
        "     l:   list the supported checksum names\n"
        "\n"
        "  name:   name of the checksum (or a partial name, or '*')\n"
        "  size:   number of bytes to include (if omitted or zero, "
        "use the whole file starting from current offset)\n"
        "  offset: starting offset (if "
        "omitted, use current offset)\n");
}

static u32_t fb_calculate_checksum(const checksum_algo_t* algo, FileBuffer* fb,
                                   u64_t off, u64_t size)
{
    u64_t original_off = fb->off;
    fb_seek(fb, off);

    checksum_state_t state     = algo->init();
    u64_t            processed = 0;
    while (processed < size) {
        u64_t block_size = fb_block_size;
        if (block_size > size - processed)
            block_size = size - processed;

        const u8_t* data = fb_read(fb, block_size);
        state            = algo->step(state, data, block_size);

        processed += block_size;
    }

    fb_seek(fb, original_off);
    return algo->finalize(state);
}

static void display_checksum(const char* name, u32_t value,
                             const checksum_algo_t* algo)
{
    if (algo->decimal)
        display_printf("  %11s : %u\n", name, value);
    else if (algo->width <= 8)
        display_printf("  %11s : 0x%02x\n", name, value);
    else if (algo->width <= 16)
        display_printf("  %11s : 0x%04x\n", name, value);
    else
        display_printf("  %11s : 0x%08x\n", name, value);
}

static int checksumcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    int should_list = -1;
    if (handle_mods(pc, "l", &should_list) != 0)
        return COMMAND_INVALID_MOD;

    if (should_list == LIST_SET) {
        if (handle_args(pc, 0, 0) != 0)
            return COMMAND_INVALID_ARG;

        const char* const* names = get_all_checksum_names();
        while (*names) {
            display_printf("    %s\n", *names);
            names++;
        }
        return COMMAND_OK;
    }

    char* name       = NULL;
    char* size_str   = NULL;
    char* offset_str = NULL;
    if (handle_args(pc, 3, 1, &name, &size_str, &offset_str) != 0)
        return COMMAND_INVALID_ARG;

    u64_t size = 0;
    u32_t off  = 0;
    if (size_str) {
        if (!str_to_uint64(size_str, &size)) {
            warning("invalid number '%s'", size_str);
            return COMMAND_INVALID_ARG;
        }
    }
    if (offset_str) {
        if (!str_to_uint32(offset_str, &off)) {
            warning("invalid number '%s'", offset_str);
            return COMMAND_INVALID_ARG;
        }
    }

    u64_t offset = (u64_t)off + fb->off;
    if (offset >= fb->size) {
        warning("offset is too big '%s'", offset_str);
        return COMMAND_INVALID_ARG;
    }
    if (size == 0)
        size = fb->size - offset;
    if (size > fb->size - offset) {
        warning("reducing the size to fit the file (%llu)", fb->size - offset);
        size = fb->size - offset;
    }

    const char* const* names = get_all_checksum_names();
    while (*names) {
        if (strcmp(name, "*") == 0 || stristr(*names, name) != NULL) {
            const checksum_algo_t* algo = get_checksum_by_name(*names);
            u32_t value = fb_calculate_checksum(algo, fb, offset, size);
            display_checksum(*names, value, algo);
        }
        names++;
    }
    return COMMAND_OK;
}

Cmd* checksumcmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "checksum";
    cmd->alias = "cs";
    cmd->hint  = HINT_STR;

    cmd->dispose = checksumcmd_dispose;
    cmd->help    = checksumcmd_help;
    cmd->exec    = checksumcmd_exec;

    return cmd;
}
