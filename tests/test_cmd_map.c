// Copyright (c) 2022-2026, bageyelet

#include "t_cmd_common.h"
#include "dummy_filebuffer.h"
#include "t.h"

#include <color.h>

/* The escapes the map paints its kinds with, see common/color.c */
#define mc_zero  "\x1b[0;90m"
#define mc_ff    "\x1b[0;33m"
#define mc_text  "\x1b[0;32m"
#define mc_mixed "\x1b[0;36m"
#define mc_high  "\x1b[0;31m"

#ifndef TEST
#define TEST(name) test_##name
#endif

// 4 KiB in four equal regions, one per kind the map can name: zeroes, text,
// 0xff filler and bytes with no structure at all. The last quarter comes out
// of a small generator rather than a table, so that the test carries the
// intent instead of 1024 magic numbers
static void map_fixture(u8_t* buf)
{
    memset(buf, 0x00, 1024);
    memset(buf + 1024, 'A', 1024);
    memset(buf + 2048, 0xff, 1024);

    u32_t x = 12345;
    for (int i = 0; i < 1024; ++i) {
        x             = x * 1103515245u + 12345u;
        buf[3072 + i] = (u8_t)(x >> 16);
    }
}

int TEST(regions)(void)
{
    // one row of 64 cells over 4 KiB: 16 cells per region
    // clang-format off
    const char* expected =
        "[ 00000000 ] ................AAAAAAAAAAAAAAAAFFFFFFFFFFFFFFFF################\n"
        "\n"
        "  . zeroes  F 0xff  A text  # high entropy  : mixed\n"
        "  64 bytes per cell, 64 cells\n";
    // clang-format on

    u8_t buf[4096];
    map_fixture(buf);

    int              r   = TEST_FAILED;
    char*            out = NULL;
    DummyFilebuffer* tfb = dummyfilebuffer_create(buf, sizeof(buf));
    if (tfb == NULL)
        goto end;
    if (exec_commands_on("map 1", tfb) != 0)
        goto end;

    out = strbuilder_reset(sb);
    r   = compare_strings_ignoring_X(expected, out);

end:
    bhex_free(out);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(len_arg)(void)
{
    // half the range, so the same 64 cells cover only the zeroes and the text
    u8_t buf[4096];
    map_fixture(buf);

    int              r   = TEST_FAILED;
    char*            out = NULL;
    DummyFilebuffer* tfb = dummyfilebuffer_create(buf, sizeof(buf));
    if (tfb == NULL)
        goto end;
    if (exec_commands_on("map 1 2048", tfb) != 0)
        goto end;

    out = strbuilder_reset(sb);
    ASSERT(strstr(out, "] "
                       "................................"
                       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n") != NULL);
    ASSERT(strstr(out, "32 bytes per cell") != NULL);
    ASSERT(strstr(out, "F") == NULL || strstr(out, "0xff") != NULL);
    r = TEST_SUCCEEDED;

end:
    bhex_free(out);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// A cell too short to visit many byte values cannot be told from random
// whatever it holds, so the map declines to call one compressed: at two rows
// the cells are 32 bytes and the last region reads as mixed, not as entropy
int TEST(short_cells_are_not_called_compressed)(void)
{
    u8_t buf[4096];
    map_fixture(buf);

    int              r   = TEST_FAILED;
    char*            out = NULL;
    DummyFilebuffer* tfb = dummyfilebuffer_create(buf, sizeof(buf));
    if (tfb == NULL)
        goto end;

    // 64-byte cells: the region is called what it is
    if (exec_commands_on("map 1", tfb) != 0)
        goto end;
    out = strbuilder_reset(sb);
    ASSERT(strstr(out, "################") != NULL);
    bhex_free(out);
    out = NULL;

    // 32-byte cells: below the floor, so it falls back to mixed
    if (exec_commands_on("map 2", tfb) != 0)
        goto end;
    out = strbuilder_reset(sb);
    ASSERT(strstr(out, "::::::::::::::::") != NULL);
    ASSERT(strstr(out, "####") == NULL);
    r = TEST_SUCCEEDED;

end:
    bhex_free(out);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(colors_by_kind)(void)
{
    u8_t buf[4096];
    map_fixture(buf);

    int              r   = TEST_FAILED;
    char*            out = NULL;
    DummyFilebuffer* tfb = dummyfilebuffer_create(buf, sizeof(buf));
    if (tfb == NULL)
        goto end;

    colors_set_enabled(1);
    if (exec_commands_on("map 1", tfb) != 0)
        goto end;

    out = strbuilder_reset(sb);
    // four kinds, four different escapes: the palette exists so that they do
    // not have to be told apart by glyph alone
    ASSERT(strstr(out, mc_zero ".") != NULL);
    ASSERT(strstr(out, mc_text "A") != NULL);
    ASSERT(strstr(out, mc_ff "F") != NULL);
    ASSERT(strstr(out, mc_high "#") != NULL);
    ASSERT(strstr(out, mc_mixed) != NULL); // the legend at least
    r = TEST_SUCCEEDED;

end:
    colors_set_enabled(0);
    bhex_free(out);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(empty)(void)
{
    int r = TEST_FAILED;
    if (exec_commands("s 0 ; d 324 ; map ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X("", out);
    bhex_free(out);

end:
    return r;
}

int TEST(invalid_args)(void)
{
    return exec_commands("map 1 2 3") != 0 && exec_commands("map nope") != 0 &&
           exec_commands("map 0") != 0;
}
