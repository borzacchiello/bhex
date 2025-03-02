#include "t_cmd_common.h"
#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(undo_write)(void)
{
    // clang-format off
    const char* expected =
        "AABB\n"
        "7F45\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("w/x aabb ; p/r 2 ; u ; p/r 2") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(undo_insert)(void)
{
    // clang-format off
    const char* expected =
        "AA7F\n"
        "7F45\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("w/i/x aa ; p/r 2 ; u ; p/r 2") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(undo_write_insert)(void)
{
    // clang-format off
    const char* expected =
        "BBCC45\n"
        "AA7F45\n"
        "7F454C\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("w/x/i aa ; w/x bbcc ; p/r 3 ; u ; p/r 3 ; u ; p/r 3") !=
        0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(undo_delete)(void)
{
    // clang-format off
    const char* expected =
        "454C\n"
        "7F45\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("d 1 ; p/r 2 ; u ; p/r 2") !=
        0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}
