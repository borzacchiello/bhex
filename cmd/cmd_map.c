// Copyright (c) 2022-2026, bageyelet

#include "cmd_map.h"
#include "cmd_arg_handler.h"
#include "cmd.h"

#include <util/byte_to_str.h>
#include <util/byte_to_num.h>
#include <util/math.h>

#include <filebuffer.h>
#include <histogram.h>
#include <entropy.h>
#include <display.h>
#include <unicode.h>
#include <string.h>
#include <color.h>
#include <alloc.h>
#include <defs.h>
#include <log.h>

#define HINT_STR " [<rows> <len>]"

// One row of the map, and the most rows an automatic layout will draw: 32
// rows of 64 cells look at the whole file through 2048 windows, which is
// enough to see the shape of it without becoming a second hex dump
#define MAP_WIDTH     64
#define AUTO_MAX_ROWS 32

// The smallest cell an automatic layout will choose. A cell holds at most one
// count of each byte value, so a short one cannot reach a high entropy however
// random it is -- 112 bytes top out at log2(112), under 7 -- and a map drawn
// out of cells that small cannot tell compressed data from anything else
#define AUTO_MIN_CELL 256

// Under this many bytes the entropy of a cell says nothing at all, so the map
// does not call anything compressed
#define MIN_ENTROPY_BYTES 64

// What a cell of the map turned out to hold. The order is the order the tests
// are applied in: a run of zeroes is also low entropy, and text is also not
// high entropy, so the narrow answers have to come before the broad ones
typedef enum MapKind {
    MAP_ZERO = 0, // nothing but 0x00: padding, holes, cleared memory
    MAP_FF,       // nothing but 0xff: erased flash, filler
    MAP_TEXT,     // printable ASCII: strings, source, config
    MAP_HIGH,     // high entropy: compressed or encrypted
    MAP_MIXED,    // anything else: headers, tables, code
    MAP_KIND_COUNT
} MapKind;

// A cell is drawn as one character in the colour of its kind
typedef struct KindStyle {
    const char* glyph_unicode;
    const char* glyph_ascii;
    Color       color;
    const char* label;
} KindStyle;

// clang-format off
static const KindStyle kind_styles[MAP_KIND_COUNT] = {
    [MAP_ZERO]  = {"·", ".", COLOR_MAP_ZERO,  "zeroes"},
    [MAP_FF]    = {"▓", "F", COLOR_MAP_FF,    "0xff"},
    [MAP_TEXT]  = {"▒", "A", COLOR_MAP_TEXT,  "text"},
    [MAP_HIGH]  = {"█", "#", COLOR_MAP_HIGH,  "high entropy"},
    [MAP_MIXED] = {"░", ":", COLOR_MAP_MIXED, "mixed"},
};
// clang-format on

// A byte value is "text" if it would show up as itself in a dump: the
// printable range plus the three whitespace characters that hold text together
static int is_text_byte(u32_t b)
{
    return is_printable_ascii((char)(u8_t)b) || b == '\t' || b == '\n' ||
           b == '\r';
}

static MapKind classify(const u64_t counts[256], u64_t total)
{
    if (total == 0)
        return MAP_ZERO;

    // a cell is called after what fills it, not after what merely leads it:
    // nine tenths is the bar for the two filler answers
    if (counts[0x00] * 10 >= total * 9)
        return MAP_ZERO;
    if (counts[0xff] * 10 >= total * 9)
        return MAP_FF;

    u64_t text = 0;
    for (u32_t b = 0; b < 256; ++b)
        if (is_text_byte(b))
            text += counts[b];
    if (text * 20 >= total * 17) // 85%
        return MAP_TEXT;

    // Close to what random bytes would score in a cell this size, the data
    // is indistinguishable from random -- which is what compressed and
    // encrypted data look like.
    //
    // The bar has to move with the size of the cell. A short cell cannot
    // reach 8 bits however random it is, because it has too few bytes to
    // visit all 256 values: 256 random bytes measure about 7.2, and 64 of
    // them about 5.8. A fixed 7.5 would call none of them compressed. The
    // measured baseline is modelled well by the expression below, and a cell
    // is called random when it comes within 7% of it
    if (total >= MIN_ENTROPY_BYTES) {
        float expected = 8.0f - _log2(1.0f + 256.0f / (float)total);
        if (entropy_from_counts(counts, total) >= 0.93f * expected)
            return MAP_HIGH;
    }

    return MAP_MIXED;
}

typedef struct MapCtx {
    MapKind* cells;
    u64_t    n;
    u64_t    i;
} MapCtx;

static void bucket_cb(u64_t off, u64_t size, const u64_t counts[256],
                      void* user)
{
    (void)off;
    MapCtx* ctx = (MapCtx*)user;
    if (ctx->i < ctx->n)
        ctx->cells[ctx->i++] = classify(counts, size);
}

static void mapcmd_dispose(void* obj) { (void)obj; }

static void mapcmd_help(void* obj)
{
    (void)obj;
    display_printf(
        "map: draw the whole range as one character per slice, telling apart "
        "the\n"
        "     padding, the text, the compressed data and the rest\n"
        "\n"
        "  m" HINT_STR "\n"
        "\n"
        "  rows: number of rows of the map, %d slices each (if omitted or "
        "'-',\n"
        "        auto mode)\n"
        "  len:  number of bytes to include starting from the current offset "
        "(if omitted, use the whole file)\n",
        MAP_WIDTH);
}

static int mapcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    (void)obj;

    char* rows_str = NULL;
    char* len_str  = NULL;
    if (handle_args(pc, 2, 0, &rows_str, &len_str) != 0)
        return COMMAND_INVALID_ARG;

    u64_t len  = fb->size - fb->off;
    u64_t rows = 0;
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
    if (rows_str && strcmp(rows_str, "-") != 0) {
        if (!str_to_uint64(rows_str, &rows) || rows == 0) {
            warning("not a number: '%s'", rows_str);
            return COMMAND_INVALID_ARG;
        }
    }

    if (len == 0)
        // an empty range has no shape to draw
        return COMMAND_OK;

    if (rows == 0) {
        // as many rows as it takes to keep the cells worth measuring, and no
        // more than the screenful AUTO_MAX_ROWS stands for
        u64_t per_row = (u64_t)MAP_WIDTH * AUTO_MIN_CELL;
        rows          = (len + per_row - 1) / per_row;
        if (rows == 0)
            rows = 1;
        if (rows > AUTO_MAX_ROWS)
            rows = AUTO_MAX_ROWS;
    }

    u64_t ncells = rows * MAP_WIDTH;
    if (ncells > len)
        // never draw a cell that holds nothing
        ncells = len;

    MapCtx ctx = {0};
    ctx.n      = ncells;
    ctx.cells  = bhex_calloc(sizeof(MapKind) * ncells);

    calculate_histogram_buckets(fb, fb->off, len, ncells, bucket_cb, &ctx);

    // the same split calculate_histogram_buckets made, so that the address in
    // the gutter is the offset the row really starts at
    u64_t cell_size = len / ncells;
    u64_t cell_rem  = len % ncells;
    for (u64_t i = 0; i < ncells; i += MAP_WIDTH) {
        u64_t row_off = fb->off + i * cell_size + (i < cell_rem ? i : cell_rem);
        display_printf("%s[ %08llx ]%s ", color_str(COLOR_ADDR),
                       row_off + fb->base_addr, color_str(COLOR_RESET));

        Color curr = COLOR_COUNT; // no escape emitted yet
        for (u64_t j = i; j < i + MAP_WIDTH && j < ncells; ++j) {
            const KindStyle* s = &kind_styles[ctx.cells[j]];
            // one escape per run of cells of the same kind, not one per cell
            if (s->color != curr) {
                display_printf("%s", color_str(s->color));
                curr = s->color;
            }
            display_printf("%s", unicode_enabled() ? s->glyph_unicode
                                                   : s->glyph_ascii);
        }
        display_printf("%s\n", color_str(COLOR_RESET));
    }

    // the glyphs mean nothing without this, so it is not optional
    display_printf("\n");
    for (u32_t k = 0; k < MAP_KIND_COUNT; ++k) {
        const KindStyle* s = &kind_styles[k];
        display_printf("  %s%s%s %s", color_str(s->color),
                       unicode_enabled() ? s->glyph_unicode : s->glyph_ascii,
                       color_str(COLOR_RESET), s->label);
    }
    display_printf("\n  %llu byte%s per cell, %llu cells\n", cell_size,
                   cell_size == 1 ? "" : "s", ncells);

    bhex_free(ctx.cells);
    return COMMAND_OK;
}

Cmd* mapcmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "map";
    cmd->alias = "m";
    cmd->hint  = HINT_STR;

    cmd->dispose = mapcmd_dispose;
    cmd->help    = mapcmd_help;
    cmd->exec    = mapcmd_exec;

    return cmd;
}
