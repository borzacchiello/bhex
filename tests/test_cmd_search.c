#include "t_cmd_common.h"
#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(hello)()
{
    const char* expected = " >> Match @ 0x0000080\n";

    int r = TEST_FAILED;
    if (exec_commands("src hello") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(hello_p)()
{
    // clang-format off
    const char* expected =
        " >> Match @ 0x0000080\n"
        "\n"
        "       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
        "       -----------------------------------------------\n"
        " 0070: 00 10 00 00 B8 01 00 00 00 BB 2A 00 00 00 CD 80   ..........*.....\n"
        " 0080: 68 65 6C 6C 6F 20 77 6F 72 6C 64 00 00 2E 73 68   hello world...sh\n"
        " 0090: 73 74 72 74 61                                    strta\n"
        "\n"
    ;
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("src/p hello") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(hex)()
{
    const char* expected = " >> Match @ 0x0000074\n";

    int r = TEST_FAILED;
    if (exec_commands("src/x B8010000") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(hex_seek)()
{
    const char* expected = " >> Match @ 0x0000074\n0x74\n";

    int r = TEST_FAILED;
    if (exec_commands("src/x/sk B8010000 ; s ; s 0") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}
