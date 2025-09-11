#include "dummy_filebuffer.h"
#include "t_cmd_common.h"
#include "t.h"

#include "data/big_buffers.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(commit_list_one_overwrite)(void)
{
    // clang-format off
    const char* expected =
        "\n"
        " ~ overwrite @ 0x0000000 [ 4 ]\n"
        "      7f 45 4c 46 -> 63 69 61 6f \n"
        "\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("w ciao; c/l") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(commit_list_one_insert)(void)
{
    // clang-format off
    const char* expected =
        "\n"
        " ~ insert    @ 0x0000000 [ 4 ]\n"
        "      63 69 61 6f \n"
        "\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("w/i ciao; c/l") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(commit_list_one_delete)(void)
{
    // clang-format off
    const char* expected =
        "\n"
        " ~ delete    @ 0x0000000 [ 4 ]\n"
        "      7f 45 4c 46 \n"
        "\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("d 4; c/l") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(commit_list_one_more_than_8)(void)
{
    // clang-format off
    const char* expected =
        "\n"
        " ~ overwrite @ 0x0000000 [ 18 ]\n"
        "      7f 45 4c 46 01 01 01 00 ... -> 76 65 72 79 6c 6f 6e 67 ... \n"
        "\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("w verylongword......; c/l") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(commit_list_multiple)(void)
{
    // clang-format off
    const char* expected =
        "\n"
        " ~ delete    @ 0x0000000 [ 2 ]\n"
        "      2b 2b \n"
        " ~ insert    @ 0x0000000 [ 7 ]\n"
        "      2b 2b 68 65 79 2c 20 \n"
        " ~ overwrite @ 0x0000000 [ 4 ]\n"
        "      7f 45 4c 46 -> 63 69 61 6f \n"
        "\n"
        "hey, ciao...\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("w ciao ; w/i \"++hey, \" ; d 2 ; c/l ; p/a") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(commit_list_after_delete)(void)
{
    // clang-format off
    const char* expected =
    "\n"
    " ~ delete    @ 0x0000000 [ 24 ]\n"
    "      7f 45 4c 46 01 01 01 00 ... \n"
    "\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands_on("d 24; c/l", dfb_alt_1) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(commit_1)(void)
{
    // clang-format off
    const char* expected =
        "\n"
        " ~ delete    @ 0x0000000 [ 2 ]\n"
        "      2b 2b \n"
        " ~ insert    @ 0x0000000 [ 7 ]\n"
        "      2b 2b 68 65 79 2c 20 \n"
        " ~ overwrite @ 0x0000000 [ 5 ]\n"
        "      58 54 45 4e 4a -> 63 69 61 6f 00 \n"
        "\n"
        "hey, ciao\n"
        "hey, ciao\n";
    // clang-format on

    DummyFilebuffer* dfb =
        dummyfilebuffer_create(pseudo_random, sizeof(pseudo_random));
    int r = TEST_FAILED;
    if (exec_commands_on(
            "w \"ciao\\0\"; w/i \"++hey, \"; d 2; c/l; p/a; c; c/l; p/a",
            dfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(dfb);
    return r;
}
