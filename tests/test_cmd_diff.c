#include "t_cmd_common.h"
#include "t.h"

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

    int r = TEST_FAILED;
    if (exec_commands(cmd) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
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

    int r = TEST_FAILED;
    if (exec_commands(cmd) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}
