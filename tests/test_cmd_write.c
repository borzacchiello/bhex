#include "dummy_filebuffer.h"
#include "t_cmd_common.h"
#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(invalid_number_of_args)(void) { return exec_commands("w a b") != 0; }

int TEST(byte_1)(void)
{
    const char* expected = "2A\n";

    int r = TEST_FAILED;
    if (exec_commands("w/b 42 ; p/r 1 ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(byte_2)(void)
{
    const char* expected = "12\n";

    int r = TEST_FAILED;
    if (exec_commands("w/b 0x12 ; p/r 1 ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(byte_3)(void)
{
    const char* expected = "FF\n";

    int r = TEST_FAILED;
    if (exec_commands("w/b -1 ; p/r 1 ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(word_1)(void)
{
    const char* expected = "4342\n";

    int r = TEST_FAILED;
    if (exec_commands("w/w 0x4243 ; p/r 2 ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(word_2)(void)
{
    const char* expected = "4243\n";

    int r = TEST_FAILED;
    if (exec_commands("w/w 0x4342 ; p/r 2 ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(word_3)(void)
{
    const char* expected = "FFFF\n";

    int r = TEST_FAILED;
    if (exec_commands("w/w -1 ; p/r 2 ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(word_4)(void)
{
    const char* expected = "FFFF\n";

    int r = TEST_FAILED;
    if (exec_commands("w/w/u 0xffff ; p/r 2 ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(dword_1)(void)
{
    const char* expected = "0000ABAD\n";

    int r = TEST_FAILED;
    if (exec_commands("w/d/be/u 0xabad ; p/r 4 ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(dword_2)(void)
{
    const char* expected = "ADAB0000\n";

    int r = TEST_FAILED;
    if (exec_commands("w/d/u 0xabad ; p/r 4 ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(dword_3)(void)
{
    const char* expected = "FFFFFFFF\n";

    int r = TEST_FAILED;
    if (exec_commands("w/d -1 ; p/r 4 ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(qword_1)(void)
{
    const char* expected = "FFFFFFFFFFFFFFFF\n";

    int r = TEST_FAILED;
    if (exec_commands("w/q -1 ; p/r 8 ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(qword_2)(void)
{
    const char* expected = "CAFEBABE00000000\n";

    int r = TEST_FAILED;
    if (exec_commands("w/q/be/u 0xcafebabe00000000 ; p/r 8 ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(qword_3)(void)
{
    const char* expected = "CAFEBABE00000000\n";

    int r = TEST_FAILED;
    if (exec_commands("w/q/le/u 0xbebafeca ; p/r 8 ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(hex_1)(void)
{
    const char* expected = "CAFEBABEABADCAFE1234\n";

    int r = TEST_FAILED;
    if (exec_commands("w/x CAFEBABEABADCAFE1234 ; p/r 10 ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(string_1)(void)
{
    const char* expected = "hello world\n";

    int r = TEST_FAILED;
    if (exec_commands("w/s \"hello world\\0\" ; p/a ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(insert_1)(void)
{
    const char* expected = "ABAD7F\n";

    int r = TEST_FAILED;
    if (exec_commands("s 0; w/i/x ABAD ; p/r 3") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(insert_and_write_1)(void)
{
    const char* expected = "0F\n"
                           "9F7F\n";

    int r = TEST_FAILED;
    if (exec_commands("s 0; w/i/x 0F ; p/r 1; w/x 9F; s 0; p/r 2") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(insert_and_write_2)(void)
{
    const char* expected = "01\n"
                           "0F\n"
                           "9F01\n";

    int r = TEST_FAILED;
    if (exec_commands("s 4; p/r 1; w/i/x 0F ; p/r 1; w/x 9F; s 4; p/r 2") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(insert_and_write_3)(void)
{
    const char* expected = "41414141414141414141414141414141\n"
                           "41414141FD414141414141414141414141\n";

    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)"AAAAAAAAAAAAAAAA", 16);

    int r = TEST_FAILED;
    if (exec_commands_on("p/r 16; s 4; w/i/x 0D; w/x FD; s 0; p/r 17", tfb) !=
        0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(insert_and_write_4)(void)
{
    const char* expected = "41414141414141414141414141414141\n"
                           "41414141FDBBCC414141414141414141414141\n";

    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)"AAAAAAAAAAAAAAAA", 16);

    int r = TEST_FAILED;
    if (exec_commands_on("p/r 16; s 4; w/i/x 0DBBCC; w/x FD; s 0; p/r 19",
                         tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(insert_and_write_5)(void)
{
    const char* expected = "41414141414141414141414141414141\n"
                           "414141FDBB\n";

    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)"AAAAAAAAAAAAAAAA", 16);

    int r = TEST_FAILED;
    if (exec_commands_on("p/r 16; s 4; w/i/x 0DBBCC; w/x FD; s 1; p/r 5",
                         tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(insert_and_write_6)(void)
{
    const char* expected = "41414141414141414141414141414141\n"
                           "41414141FFFF414141414141414141414141\n";

    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)"AAAAAAAAAAAAAAAA", 16);

    int r = TEST_FAILED;
    if (exec_commands_on("p/r 16; s 4; w/i/x 0F; w/x FF; s 5; w/i/x 0F; w/x "
                         "FF; s 0; p/r 18",
                         tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
}
