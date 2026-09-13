// Copyright (c) 2022-2026, bageyelet

#include "t_cmd_common.h"
#include "t.h"

#include <color.h>

#ifndef TEST
#define TEST(name) test_##name
#endif

#define highlight_begin "\x1b[31;49;1m"
#define highlight_end   "\x1b[0m"

int TEST(equal_smaller)(void)
{
    // clang-format off
    const char* expected =
        "current file is bigger\n"
        "common size is identical\n";
    // clang-format on

    char cmd[128] = {0};
    if (snprintf(cmd, sizeof(cmd) - 1, "df %s", dfb_alt_1->fname) < 0)
        panic("snprintf failed");

    int r = TEST_FAILED;
    if (exec_commands(cmd) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(different_smaller)(void)
{
    // clang-format off
    const char* expected =
        "current file is bigger\n"
        "common size is different [ difference 4.167% ]\n";
    // clang-format on

    char cmd[128] = {0};
    if (snprintf(cmd, sizeof(cmd) - 1, "df %s", dfb_alt_2->fname) < 0)
        panic("snprintf failed");

    int r = TEST_FAILED;
    if (exec_commands(cmd) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(different_smaller_print)(void)
{
    // clang-format off
    const char* expected =
        "            00 01 02 03 04 05 06 07  00 01 02 03 04 05 06 07\n"
        "            -----------------------  -----------------------\n"
        "     *\n"
        "0000000008  00 00 00 00 00 00 00 " highlight_begin "00" highlight_end
        "  "
        "00 00 00 00 00 00 00 " highlight_begin "FF" highlight_end " \n"
        "     *\n"
        "\n"
        "current file is bigger\n"
        "common size is different [ difference 4.167% ]\n";
    // clang-format on

    char cmd[128] = {0};
    if (snprintf(cmd, sizeof(cmd) - 1, "df/p %s", dfb_alt_2->fname) < 0)
        panic("snprintf failed");

    // the colors are off by default in the tests, as they are whenever the
    // output is not a terminal: turn them on to check the highlighting
    colors_set_enabled(1);

    int r = TEST_FAILED;
    if (exec_commands(cmd) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    colors_set_enabled(0);
    return r;
}

int TEST(different_smaller_print_no_colors)(void)
{
    // clang-format off
    const char* expected =
        "            00 01 02 03 04 05 06 07  00 01 02 03 04 05 06 07\n"
        "            -----------------------  -----------------------\n"
        "     *\n"
        "0000000008  00 00 00 00 00 00 00 00"
        "  "
        "00 00 00 00 00 00 00 FF \n"
        "     *\n"
        "\n"
        "current file is bigger\n"
        "common size is different [ difference 4.167% ]\n";
    // clang-format on

    char cmd[128] = {0};
    if (snprintf(cmd, sizeof(cmd) - 1, "df/p/n %s", dfb_alt_2->fname) < 0)
        panic("snprintf failed");

    // 'n' overrides the colors even when they are enabled
    colors_set_enabled(1);

    int r = TEST_FAILED;
    if (exec_commands(cmd) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    colors_set_enabled(0);
    return r;
}

int TEST(different_smaller_print_wide)(void)
{
    // clang-format off
    const char* expected =
        "            00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
        "            -----------------------------------------------  -----------------------------------------------\n"
        "0000000000  7F 45 4C 46 01 01 01 00 00 00 00 00 00 00 00 " highlight_begin "00" highlight_end
        "  "
        "7F 45 4C 46 01 01 01 00 00 00 00 00 00 00 00 " highlight_begin "FF" highlight_end " \n"
        "     *\n"
        "\n"
        "current file is bigger\n"
        "common size is different [ difference 4.167% ]\n";
    // clang-format on

    char cmd[128] = {0};
    if (snprintf(cmd, sizeof(cmd) - 1, "df/p/w %s", dfb_alt_2->fname) < 0)
        panic("snprintf failed");

    // the colors are off by default in the tests, as they are whenever the
    // output is not a terminal: turn them on to check the highlighting
    colors_set_enabled(1);

    int r = TEST_FAILED;
    if (exec_commands(cmd) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    colors_set_enabled(0);
    return r;
}

// Runs "df/c <other>" on `self` and compares the emitted script
static int check_script(DummyFilebuffer* self, DummyFilebuffer* other,
                        const char* expected)
{
    char cmd[128] = {0};
    if (snprintf(cmd, sizeof(cmd) - 1, "df/c %s", other->fname) < 0)
        panic("snprintf failed");

    int r = TEST_FAILED;
    if (exec_commands_on(cmd, self) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(script_one_run)(void)
{
    // one run of differing bytes becomes a seek and an overwrite
    DummyFilebuffer* a =
        dummyfilebuffer_create((const u8_t*)"AAAABBBBCCCC", 12);
    DummyFilebuffer* b =
        dummyfilebuffer_create((const u8_t*)"AAAAXXXXCCCC", 12);

    int r = check_script(a, b,
                         "s 0x4\n"
                         "w/x \"58 58 58 58\"\n"
                         "c\n");

    dummyfilebuffer_destroy(a);
    dummyfilebuffer_destroy(b);
    return r;
}

int TEST(script_two_runs)(void)
{
    // the bytes that agree in between split the patch in two
    DummyFilebuffer* a =
        dummyfilebuffer_create((const u8_t*)"AAAABBBBCCCC", 12);
    DummyFilebuffer* b =
        dummyfilebuffer_create((const u8_t*)"XAAABBBBCCCX", 12);

    int r = check_script(a, b,
                         "s 0x0\n"
                         "w/x \"58\"\n"
                         "s 0xb\n"
                         "w/x \"58\"\n"
                         "c\n");

    dummyfilebuffer_destroy(a);
    dummyfilebuffer_destroy(b);
    return r;
}

int TEST(script_append)(void)
{
    // a longer other file is appended with an insert
    DummyFilebuffer* a = dummyfilebuffer_create((const u8_t*)"AAAA", 4);
    DummyFilebuffer* b = dummyfilebuffer_create((const u8_t*)"AAAABB", 6);

    int r = check_script(a, b,
                         "s 0x4\n"
                         "w/i/x \"42 42\"\n"
                         "c\n");

    dummyfilebuffer_destroy(a);
    dummyfilebuffer_destroy(b);
    return r;
}

int TEST(script_truncate)(void)
{
    // a shorter one drops the tail
    DummyFilebuffer* a = dummyfilebuffer_create((const u8_t*)"AAAABB", 6);
    DummyFilebuffer* b = dummyfilebuffer_create((const u8_t*)"AAAA", 4);

    int r = check_script(a, b,
                         "s 0x4\n"
                         "d\n"
                         "c\n");

    dummyfilebuffer_destroy(a);
    dummyfilebuffer_destroy(b);
    return r;
}

int TEST(script_identical)(void)
{
    // nothing to do, but the commit is emitted all the same
    DummyFilebuffer* a = dummyfilebuffer_create((const u8_t*)"AAAA", 4);
    DummyFilebuffer* b = dummyfilebuffer_create((const u8_t*)"AAAA", 4);

    int r = check_script(a, b, "c\n");

    dummyfilebuffer_destroy(a);
    dummyfilebuffer_destroy(b);
    return r;
}

int TEST(script_ignores_the_base_address)(void)
{
    // the script is replayed on a file with no base, so the offsets it
    // carries are raw ones
    DummyFilebuffer* a =
        dummyfilebuffer_create((const u8_t*)"AAAABBBBCCCC", 12);
    DummyFilebuffer* b =
        dummyfilebuffer_create((const u8_t*)"AAAAXXXXCCCC", 12);

    a->fb->base_addr = 0x400000;
    int r            = check_script(a, b,
                                    "s 0x4\n"
                                    "w/x \"58 58 58 58\"\n"
                                    "c\n");
    a->fb->base_addr = 0;

    dummyfilebuffer_destroy(a);
    dummyfilebuffer_destroy(b);
    return r;
}
