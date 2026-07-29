// Copyright (c) 2022-2026, bageyelet

#include "cmd_entropy.h"
#include "cmd.h"
#include "cmd_arg_handler.h"

#include <entropy.h>

#include <util/byte_to_num.h>
#include <util/math.h>
#include <hash/md5.h>
#include <display.h>
#include <color.h>
#include <string.h>
#include <alloc.h>
#include <defs.h>
#include <log.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

#define AUTO_MAX_ROWS 32
#define HINT_CMDLINE  " [<rows> <len>]"

static void entropycmd_dispose(void* obj) {}

static void entropycmd_help(void* obj)
{
    display_printf(
        "entropy: display an entropy graph\n"
        "\n"
        "  e" HINT_CMDLINE "\n"
        "\n"
        "  rows: number of points in the graph (if omitted or '-', auto mode)\n"
        "  len:  number of bytes to include starting from the current offset "
        "(if omitted, use the whole file)\n");
}

// The bands of the graph, on the 0..8 scale of the Shannon entropy: above 7
// the data is usually compressed or encrypted, below 5 it is usually text,
// code or padding
static Color entropy_color(float entropy)
{
    if (entropy >= 7.0f)
        return COLOR_ENTROPY_HIGH;
    if (entropy >= 5.0f)
        return COLOR_ENTROPY_MID;
    return COLOR_ENTROPY_LOW;
}

static int entropycmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    char* len_str  = NULL;
    char* rows_str = NULL;
    if (handle_args(pc, 2, 0, &rows_str, &len_str) != 0)
        return COMMAND_INVALID_ARG;

    u32_t len  = fb->size - fb->off;
    u32_t rows = 0;
    if (len_str) {
        if (!str_to_uint32(len_str, &len)) {
            warning("not a number: '%s'", len_str);
            return COMMAND_INVALID_ARG;
        }
    }
    if (rows_str && strcmp(rows_str, "-") != 0) {
        if (!str_to_uint32(rows_str, &rows)) {
            warning("not a number: '%s'", rows_str);
            return COMMAND_INVALID_ARG;
        }
    }

    if (len > fb->size - fb->off) {
        warning("len is too high, trimming it to %llu", fb->size - fb->off);
        len = fb->size - fb->off;
    }
    if (rows == 0) {
        // choose a number so that we have at least 4096 values for each point,
        // with min: 1 and max: AUTO_MAX_ROWS.
        rows = len / 4096;
        if (rows == 0) {
            warning("the file is too small for entropy to be meaningful");
            rows = 1;
        }
        if (rows > AUTO_MAX_ROWS)
            rows = AUTO_MAX_ROWS;
    }
    u64_t last_addr = fb->off + len;

    if (rows > len)
        rows = len;
    if (rows == 0)
        return COMMAND_OK;

    u32_t bytes_per_raw = len / rows;
    u64_t addr          = fb->off;
    for (u32_t i = 0; i < rows; ++i) {
        if (i == rows - 1)
            // if we have remaining bytes, include them in the last point
            bytes_per_raw = last_addr - addr;

        float entropy = calculate_entropy(fb, addr, bytes_per_raw);

        display_printf("%s[ %08llx - %08llx ]%s ", color_str(COLOR_ADDR),
                       addr + fb->base_addr,
                       addr + bytes_per_raw + fb->base_addr,
                       color_str(COLOR_RESET));

        // the value and its bar share the color of the band, so that the
        // rows worth a second look can be spotted without reading the numbers
        display_printf("%s", color_str(entropy_color(entropy)));
        display_printf("(%.03f) ", entropy);
        u32_t bar_value = entropy * 45 / 8;
        for (u32_t i = 0; i < bar_value; ++i)
            display_printf("-");
        display_printf("+%s\n", color_str(COLOR_RESET));

        addr += bytes_per_raw;
    }

    return COMMAND_OK;
}

Cmd* entropycmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "entropy";
    cmd->alias = "e";
    cmd->hint  = HINT_CMDLINE;

    cmd->dispose = entropycmd_dispose;
    cmd->help    = entropycmd_help;
    cmd->exec    = entropycmd_exec;

    return cmd;
}
