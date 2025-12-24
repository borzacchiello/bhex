#include "cmd_arg_handler.h"
#include "cmd_crc.h"
#include "cmd.h"

#include <util/byte_to_num.h>
#include <filebuffer.h>
#include <display.h>
#include <string.h>
#include <alloc.h>
#include <defs.h>
#include <log.h>
#include <crc.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

#define LIST_SET 0

#define HINT_STR "[/l] <name> [<size> <off>]"

static void crccmd_dispose(void* obj) { return; }

static void crccmd_help(void* obj)
{
    display_printf(
        "import: calculate the CRC <name> at current offset + <off>\n"
        "\n"
        "  crc" HINT_STR "\n"
        "     l:   list the supported crc names\n"
        "\n"
        "  name:   name of the CRC (or a partial name, or '*')\n"
        "  size:   number of bytes to include in the crc (if omitted or zero, "
        "import the whole file starting from current offset)\n"
        "  offset: starting offset of the imported file (if "
        "omitted, import from current offset)\n");
}

static u32_t fb_calculate_crc(const crc_params_t* params, FileBuffer* fb,
                              u64_t off, u64_t size)
{
    u64_t original_off = fb->off;
    fb_seek(fb, off);

    u32_t crc       = crc_initialize(params);
    u64_t processed = 0;
    while (processed < size) {
        u64_t block_size = fb_block_size;
        if (block_size > size - processed)
            block_size = size - processed;

        const u8_t* data = fb_read(fb, block_size);
        crc              = crc_step(crc, data, block_size, params);

        processed += block_size;
    }

    fb_seek(fb, original_off);
    return crc_finalize(crc, params);
}

static int crccmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    int should_list = -1;
    if (handle_mods(pc, "l", &should_list) != 0)
        return COMMAND_INVALID_MOD;

    if (should_list == LIST_SET) {
        if (handle_args(pc, 0, 0) != 0)
            return COMMAND_INVALID_ARG;

        const char* const* crcs = get_all_crc_names();
        while (*crcs) {
            display_printf("    %s\n", *crcs);
            crcs++;
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

    const char* const* crcs = get_all_crc_names();
    while (*crcs) {
        if (strcmp(name, "*") == 0 || strstr(*crcs, name) != NULL) {
            const crc_params_t* params = get_crc_by_name(*crcs);
            u32_t crc = fb_calculate_crc(params, fb, offset, size);
            display_printf("  %24s : 0x%x\n", *crcs, crc);
        }
        crcs++;
    }
    return COMMAND_OK;
}

Cmd* crccmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "crc";
    cmd->alias = "cr";
    cmd->hint  = HINT_STR;

    cmd->dispose = crccmd_dispose;
    cmd->help    = crccmd_help;
    cmd->exec    = crccmd_exec;

    return cmd;
}
