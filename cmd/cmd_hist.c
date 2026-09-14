// Copyright (c) 2022-2026, bageyelet

#include "cmd_hist.h"
#include "cmd_arg_handler.h"
#include "cmd.h"

#include <util/byte_to_str.h>
#include <util/byte_to_num.h>

#include <stdlib.h>

#include <filebuffer.h>
#include <histogram.h>
#include <display.h>
#include <unicode.h>
#include <color.h>
#include <alloc.h>
#include <defs.h>
#include <log.h>

#define HINT_STR "[/z/s] [<len>]"

#define ZEROS_SET  0
#define SORTED_SET 0

// How wide the bar of the most frequent value is
#define BAR_WIDTH 40

// One byte value and how many times it occurred
typedef struct Bucket {
    u64_t count;
    u8_t  value;
} Bucket;

static void histcmd_dispose(void* obj) { (void)obj; }

static void histcmd_help(void* obj)
{
    display_printf(
        "hist: draw the distribution of the byte values in a range\n"
        "\n"
        "  hi" HINT_STR "\n"
        "     z: include the values that never occur\n"
        "     s: sort by count\n"
        "\n"
        "  len: number of bytes to include starting from the current offset "
        "(if omitted, use the whole file)\n");
}

// The same "kind" coloring the dumps and the TUI use, so that the rows of the
// zeroes, of the 0xff filler and of the text stand apart at a glance
static Color value_color(u8_t b)
{
    if (b == 0x00)
        return COLOR_BYTE_ZERO;
    if (b == 0xff)
        return COLOR_BYTE_FF;
    if (is_printable_ascii((char)b))
        return COLOR_BYTE_ASCII;
    return COLOR_BYTE_OTHER;
}

// by count, the rarest first, so that the values worth looking at are the
// ones the prompt does not push off the screen. Ties go by value: the order
// has to be total, or two runs on the same file could disagree
static int bucket_cmp(const void* a, const void* b)
{
    const Bucket* x = (const Bucket*)a;
    const Bucket* y = (const Bucket*)b;
    if (x->count != y->count)
        return x->count < y->count ? -1 : 1;
    return (int)x->value - (int)y->value;
}

static u32_t decimal_width(u64_t n)
{
    u32_t w = 1;
    while (n >= 10) {
        n /= 10;
        w += 1;
    }
    return w;
}

static int histcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    (void)obj;

    char* len_str = NULL;
    if (handle_args(pc, 1, 0, &len_str) != 0)
        return COMMAND_INVALID_ARG;

    int zeros  = -1;
    int sorted = -1;
    if (handle_mods(pc, "z|s", &zeros, &sorted) != 0)
        return COMMAND_INVALID_MOD;

    u64_t len = fb->size - fb->off;
    if (len_str) {
        if (!str_to_uint64(len_str, &len)) {
            warning("not a number: '%s'", len_str);
            return COMMAND_INVALID_ARG;
        }
        if (len > fb->size - fb->off) {
            warning("len is too high, trimming it to %llu", fb->size - fb->off);
            len = fb->size - fb->off;
        }
    }

    u64_t counts[256];
    u64_t total = calculate_histogram(fb, fb->off, len, counts);
    if (total == 0)
        // an empty range has no distribution to draw
        return COMMAND_OK;

    Bucket buckets[256];
    for (u32_t i = 0; i < 256; ++i) {
        buckets[i].value = (u8_t)i;
        buckets[i].count = counts[i];
    }
    if (sorted == SORTED_SET)
        qsort(buckets, 256, sizeof(Bucket), bucket_cmp);

    u64_t max = 0;
    for (u32_t i = 0; i < 256; ++i)
        if (counts[i] > max)
            max = counts[i];

    // every count is printed in the column of the largest one, so that the
    // digits line up and the bars start where the eye expects them
    u32_t       count_width = decimal_width(max);
    const char* block       = unicode_enabled() ? "█" : "#";

    for (u32_t i = 0; i < 256; ++i) {
        u64_t count = buckets[i].count;
        if (count == 0 && zeros != ZEROS_SET)
            continue;
        u8_t v = buckets[i].value;

        display_printf("  %s%02x%s ", color_str(value_color(v)), v,
                       color_str(COLOR_RESET));
        if (is_printable_ascii((char)v))
            display_printf("'%c'", v);
        else
            display_printf("   ");

        display_printf("  %*llu  %6.2f%%  ", count_width, count,
                       (double)count * 100.0 / (double)total);

        // the most frequent value fills the bar, and a value that occurs at
        // all gets at least one block: a row that is there has to be visible
        u32_t bar = (u32_t)(count * BAR_WIDTH / max);
        if (bar == 0 && count > 0)
            bar = 1;
        display_printf("%s", color_str(value_color(v)));
        for (u32_t k = 0; k < bar; ++k)
            display_printf("%s", block);
        display_printf("%s\n", color_str(COLOR_RESET));
    }

    return COMMAND_OK;
}

Cmd* histcmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "hist";
    cmd->alias = "hi";
    cmd->hint  = HINT_STR;

    cmd->dispose = histcmd_dispose;
    cmd->help    = histcmd_help;
    cmd->exec    = histcmd_exec;

    return cmd;
}
