#include "t_cmd_common.h"
#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(delete_off_at_zero)(void)
{
    const char* expected = "01010100\n";

    int r = TEST_FAILED;
    if (exec_commands("d 4; p/r 4") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(delete_offset_not_zero)(void)
{
    const char* expected = "00000000\n";

    int r = TEST_FAILED;
    if (exec_commands("s 4; d 4; p/r 4") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(delete_no_size)(void)
{
    const char* expected = "7F454C46\n";

    int r = TEST_FAILED;
    if (exec_commands("s 4; d; s 0; p/r 4") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(delete_partial)(void)
{
    const char* expected = "7F46\n";

    int r = TEST_FAILED;
    if (exec_commands("s 1; d 2; s 0; p/r 2") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(delete_and_print_all_1)(void)
{
    const char* expected = "41414141414143444541414141414141\n"
                           "41414141414141414141414141\n";

    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)"AAAAAACDEAAAAAAA", 16);

    int r = TEST_FAILED;
    if (exec_commands_on("p/r 16; s 6; d 3; s 0; p/r 13", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
}
