#include "cmd_entropy.h"
#include "cmd.h"
#include "cmd_arg_handler.h"

#include <util/byte_to_num.h>
#include <util/math.h>
#include <hash/md5.h>
#include <display.h>
#include <string.h>
#include <alloc.h>
#include <defs.h>
#include <log.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

#define DEFAULT_ROWS 32
#define HINT_CMDLINE " [<len> <rows>]"

static void entropycmd_dispose(void* obj) {}

static void entropycmd_help(void* obj)
{
    display_printf("entropy: display an entropy graph\n"
                   "\n"
                   "  e" HINT_CMDLINE "\n"
                   "\n"
                   "  len:  number of bytes to include starting from the "
                   "current offset (if omitted or '-', the whole file)\n"
                   "  rows: number of points in the graph (if omitted, "
                   "defaults to %d)\n",
                   DEFAULT_ROWS);
}

static float calc_entropy(FileBuffer* fb, u64_t addr, u64_t size)
{
    if (fb->size - addr < size)
        panic("calc_entropy: invalid parameters");

    u64_t orig_off    = fb->off;
    u32_t counts[256] = {0};

    u64_t curr_off = addr;
    u64_t max_addr = addr + size;
    while (curr_off < max_addr) {
        fb_seek(fb, curr_off);

        size_t      len = min(fb_block_size, max_addr - curr_off);
        const u8_t* buf = fb_read(fb, len);

        size_t i;
        for (i = 0; i < len; ++i)
            counts[buf[i]] += 1;
        curr_off += len;
    }

    float entropy = 0;
    u32_t i;
    for (i = 0; i < 256; ++i) {
        float px = (float)counts[i] / size;
        if (px > 0)
            entropy += -px * _log2(px);
    }
    if (entropy < 0.0f)
        entropy = 0.0f;

    fb_seek(fb, orig_off);
    return entropy;
}

static int entropycmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    char* len_str  = NULL;
    char* rows_str = NULL;
    if (handle_args(pc, 2, 0, &len_str, &rows_str) != 0)
        return COMMAND_INVALID_ARG;

    u32_t len  = fb->size - fb->off;
    u32_t rows = DEFAULT_ROWS;
    if (len_str && strcmp(len_str, "-") != 0) {
        if (!str_to_uint32(len_str, &len)) {
            warning("not a number: '%s'", len_str);
            return COMMAND_INVALID_ARG;
        }
    }
    if (rows_str) {
        if (!str_to_uint32(rows_str, &rows)) {
            warning("not a number: '%s'", rows_str);
            return COMMAND_INVALID_ARG;
        }
    }

    if (len > fb->size - fb->off) {
        warning("len is too high, trimming it to %llu", fb->size - fb->off);
        len = fb->size - fb->off;
    }
    u64_t last_addr = fb->off + len;

    if (rows > len)
        rows = len;
    if (rows == 0)
        return COMMAND_OK;

    u32_t bytes_per_raw = len / rows;
    u64_t addr = fb->off;
    for (u32_t i = 0; i < rows; ++i) {
        if (i == rows - 1)
            // if we have remaining bytes, include them in the last point
            bytes_per_raw = last_addr - addr;

        float entropy = calc_entropy(fb, addr, bytes_per_raw);

        display_printf("[ %08llx - %08llx ] (%.03f) ", addr,
                       addr + bytes_per_raw, entropy);
        u32_t bar_value = entropy * 45 / 8;
        for (u32_t i = 0; i < bar_value; ++i)
            display_printf("-");
        display_printf("+\n");

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
