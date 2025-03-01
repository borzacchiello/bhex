#include "t_cmd_common.h"
#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

#define bold_begin "\033[1m"
#define bold_end   "\033[22m"

int TEST(equal_smaller)(void)
{
    // clang-format off
    const char* expected =
        "\n"
        "current file is bigger\n"
        "0.000% of current file is different\n"
        "\n";
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
        "\n"
        "current file is bigger\n"
        "4.167% of current file is different\n"
        "\n";
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
           " 000f: 00                                                .\n"
bold_begin " 000f: FF                                                .\n" bold_end
           " ...\n"
           "\n"
           "current file is bigger\n"
           "4.167% of current file is different\n"
           "\n";
    // clang-format on

    char cmd[128] = {0};
    if (snprintf(cmd, sizeof(cmd) - 1, "df/p %s", dfb_alt_2->fname) < 0)
        panic("snprintf failed");

    int r = TEST_FAILED;
    if (exec_commands(cmd) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}
