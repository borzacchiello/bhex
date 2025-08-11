#include "t_cmd_common.h"
#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(hex_1)(void)
{
    // clang-format off
    const char* expected =
    "       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
    "       -----------------------------------------------\n"
    " 0000: 7F 45 4C 46 01 01 01 00 00 00 00 00 00 00 00 00   .ELF............\n"
    " 0010: 02 00 03 00 01 00 00 00 74 80 04 08 34 00 00 00   ........t...4...\n"
    " 0020: A4 00 00 00 00 00 00 00 34 00 20 00 02 00 28 00   ........4. ...(.\n"
    " 0030: 04 00 03 00 01 00 00 00 00 00 00 00 00 80 04 08   ................\n"
    " 0040: 00 80 04 08 80 00 00 00 80 00 00 00 05 00 00 00   ................\n"
    " 0050: 00 10 00 00 01 00 00 00 80 00 00 00 80 90 04 08   ................\n"
    " 0060: 80 90 04 08 0C 00 00 00 0C 00 00 00 06 00 00 00   ................\n"
    " 0070: 00 10 00 00 B8 01 00 00 00 BB 2A 00 00 00 CD 80   ..........*.....\n"
    " 0080: 68 65 6C 6C 6F 20 77 6F 72 6C 64 00 00 2E 73 68   hello world...sh\n"
    " 0090: 73 74 72 74 61 62 00 2E 74 65 78 74 00 2E 64 61   strtab..text..da\n"
    " 00a0: 74 61 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ta..............\n"
    " 00b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................\n"
    " 00c0: 00 00 00 00 00 00 00 00 00 00 00 00 0B 00 00 00   ................\n"
    " 00d0: 01 00 00 00 06 00 00 00 74 80 04 08 74 00 00 00   ........t...t...\n"
    " 00e0: 0C 00 00 00 00 00 00 00 00 00 00 00 04 00 00 00   ................\n"
    " 00f0: 00 00 00 00 11 00 00 00 01 00 00 00 03 00 00 00   ................\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("s 0 ; print") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strcmp(out, expected) == 0 ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    return r;
}

int TEST(hex_2)(void)
{
    // clang-format off
    const char* expected =
    "       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
    "       -----------------------------------------------\n"
    " 0000: 7F                                                .\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("s 0 ; print 1") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strcmp(out, expected) == 0 ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    return r;
}

int TEST(near_end_1)(void)
{
    const char* expected = "";

    int r = TEST_FAILED;
    if (exec_commands("s 0 ; s/- 1 ; print ; s 0") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strcmp(out, expected) == 0 ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    return r;
}

int TEST(near_end_2)(void)
{
    // clang-format off
    const char* expected =
        "       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
        "       -----------------------------------------------\n"
        " 0000: 00                                                .\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("s 0 ; s/- 2 ; print ; s 0") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strcmp(out, expected) == 0 ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    return r;
}

int TEST(word_1)(void)
{
    // clang-format off
    const char* expected =
    "       00    02    04    06    08    0A    0C    0E   \n"
    "       -----------------------------------------------\n"
    " 0000: 457Fh \n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("s 0 ; print/w 1") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strcmp(out, expected) == 0 ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    return r;
}

int TEST(word_2)(void)
{
    // clang-format off
    const char* expected =
    "       00    02    04    06    08    0A    0C    0E   \n"
    "       -----------------------------------------------\n"
    " 0000: 7F45h \n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("s 0 ; print/w/be 1") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strcmp(out, expected) == 0 ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    return r;
}

int TEST(word_3)(void)
{
    // clang-format off
    const char* expected =
    "       00    02    04    06    08    0A    0C    0E   \n"
    "       -----------------------------------------------\n"
    " 0000: 457Fh 464Ch \n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("s 0 ; print/w/le 2") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strcmp(out, expected) == 0 ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    return r;
}

int TEST(dword_1)(void)
{
    // clang-format off
    const char* expected =
    "       00        04        08        0C       \n"
    "       ---------------------------------------\n"
    " 0000: 464C457Fh \n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("s 0 ; print/d/le 1") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strcmp(out, expected) == 0 ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    return r;
}

int TEST(dword_2)(void)
{
    // clang-format off
    const char* expected =
    "       00        04        08        0C       \n"
    "       ---------------------------------------\n"
    " 0000: 7F454C46h \n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("s 0 ; print/d/be 1") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strcmp(out, expected) == 0 ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    return r;
}

int TEST(qword_1)(void)
{
    // clang-format off
    const char* expected =
    "       00                08               \n"
    "       -----------------------------------\n"
    " 0000: 00010101464C457Fh \n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("s 0 ; p/q/le 1") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strcmp(out, expected) == 0 ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    return r;
}

int TEST(qword_2)(void)
{
    // clang-format off
    const char* expected =
    "       00                08               \n"
    "       -----------------------------------\n"
    " 0000: 7F454C4601010100h \n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("s 0 ; p/q/be 1") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strcmp(out, expected) == 0 ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    return r;
}

int TEST(raw_1)(void)
{
    const char* expected = "7F454C4601010100\n";

    int r = TEST_FAILED;
    if (exec_commands("s 0 ; print/r 8") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strcmp(out, expected) == 0 ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    return r;
}

int TEST(C_1)(void)
{
    const char* expected = "{ 0x7f, 0x45, 0x4c }\n";

    int r = TEST_FAILED;
    if (exec_commands("s 0 ; print/C 3") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strcmp(out, expected) == 0 ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    return r;
}

int TEST(ascii_1)(void)
{
    const char* expected = "hello world\n";

    int r = TEST_FAILED;
    if (exec_commands("s 0x80 ; p/a") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strcmp(out, expected) == 0 ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    return r;
}
