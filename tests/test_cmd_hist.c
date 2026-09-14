// Copyright (c) 2022-2026, bageyelet

#include "t_cmd_common.h"
#include "dummy_filebuffer.h"
#include "t.h"

#include <color.h>

/* The escapes the rows are painted with, see common/color.c */
#define hc_zero  "\x1b[0;90m"
#define hc_ff    "\x1b[0;31m"
#define hc_ascii "\x1b[0;32m"
#define hc_off   "\x1b[0m"

#ifndef TEST
#define TEST(name) test_##name
#endif

// 0x00 once, 0xff twice and 'A' three times: the byte order and the count
// order disagree, which is what tells '/s' apart from the default
static u8_t hist_sample[] = {0x00, 0xff, 0xff, 0x41, 0x41, 0x41};

int TEST(distribution)(void)
{
    // the bar of the most frequent value is full, and the others are scaled
    // against it: 1/3 and 2/3 of 40 columns
    // clang-format off
    const char* expected =
        "  00      1   16.67%  #############\n"
        "  41 'A'  3   50.00%  ########################################\n"
        "  ff      2   33.33%  ##########################\n";
    // clang-format on

    int              r   = TEST_FAILED;
    char*            out = NULL;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(hist_sample, sizeof(hist_sample));
    if (tfb == NULL)
        goto end;
    if (exec_commands_on("hist", tfb) != 0)
        goto end;

    out = strbuilder_reset(sb);
    r   = compare_strings_ignoring_X(expected, out);

end:
    bhex_free(out);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(sorted_rarest_first)(void)
{
    // the most frequent value goes last, where the prompt leaves it in sight
    // clang-format off
    const char* expected =
        "  00      1   16.67%  #############\n"
        "  ff      2   33.33%  ##########################\n"
        "  41 'A'  3   50.00%  ########################################\n";
    // clang-format on

    int              r   = TEST_FAILED;
    char*            out = NULL;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(hist_sample, sizeof(hist_sample));
    if (tfb == NULL)
        goto end;
    if (exec_commands_on("hist/s", tfb) != 0)
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
    // only the first three bytes, so 'A' is not in the range at all and the
    // shares are counted against 3 bytes rather than 6
    // clang-format off
    const char* expected =
        "  00      1   33.33%  ####################\n"
        "  ff      2   66.67%  ########################################\n";
    // clang-format on

    int              r   = TEST_FAILED;
    char*            out = NULL;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(hist_sample, sizeof(hist_sample));
    if (tfb == NULL)
        goto end;
    if (exec_commands_on("hist 3", tfb) != 0)
        goto end;

    out = strbuilder_reset(sb);
    r   = compare_strings_ignoring_X(expected, out);

end:
    bhex_free(out);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(zeros_lists_every_value)(void)
{
    int              r   = TEST_FAILED;
    char*            out = NULL;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(hist_sample, sizeof(hist_sample));
    if (tfb == NULL)
        goto end;

    // the default leaves out the values that never occur, '/z' keeps them
    if (exec_commands_on("hist", tfb) != 0)
        goto end;
    out = strbuilder_reset(sb);
    ASSERT(strstr(out, "\n  01 ") == NULL);
    bhex_free(out);
    out = NULL;

    if (exec_commands_on("hist/z", tfb) != 0)
        goto end;
    out = strbuilder_reset(sb);

    u64_t rows = 0;
    for (const char* p = out; *p; ++p)
        if (*p == '\n')
            rows += 1;
    ASSERT(rows == 256);
    ASSERT(strstr(out, "  01      0    0.00%") != NULL);
    r = TEST_SUCCEEDED;

end:
    bhex_free(out);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(colors_by_byte_kind)(void)
{
    int              r   = TEST_FAILED;
    char*            out = NULL;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(hist_sample, sizeof(hist_sample));
    if (tfb == NULL)
        goto end;

    // the colors are off by default in the tests, as they are whenever the
    // output is not a terminal
    colors_set_enabled(1);
    if (exec_commands_on("hist", tfb) != 0)
        goto end;

    out = strbuilder_reset(sb);
    // each row carries the color its byte has in a dump: gray for the zero,
    // red for the 0xff filler, green for the printable ASCII
    ASSERT(strstr(out, hc_zero "00" hc_off) != NULL);
    ASSERT(strstr(out, hc_ff "ff" hc_off) != NULL);
    ASSERT(strstr(out, hc_ascii "41" hc_off) != NULL);
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
    if (exec_commands("s 0 ; d 324 ; hist ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X("", out);
    bhex_free(out);

end:
    return r;
}
