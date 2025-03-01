#include "t_cmd_common.h"
#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(no_param_1)(void)
{
    // clang-format off
    const char* expected =
        " 0x0000001 @ ELF\n"
        " 0x0000080 @ hello world\n"
        " 0x000008D @ .shstrtab\n"
        " 0x0000097 @ .text\n"
        " 0x000009D @ .data\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("strings") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(min_len_1)(void)
{
    // clang-format off
    const char* expected =
        " 0x0000080 @ hello world\n"
        " 0x000008D @ .shstrtab\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("strings 8") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(null_terminated_1)(void)
{
    // clang-format off
    const char* expected =
        " 0x0000080 @ hello world\n"
        " 0x000008D @ .shstrtab\n"
        " 0x0000097 @ .text\n"
        " 0x000009D @ .data\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("strings/n") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}
