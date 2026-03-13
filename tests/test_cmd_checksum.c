// Copyright (c) 2022-2026, bageyelet

#include "t_cmd_common.h"
#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(whole_file_all_checksums)(void)
{
    // clang-format off
    const char* expected =
    "          BSD : 0x43b5\n"
    "         SYSV : 0x1b6b\n"
    "        SUM-8 : 0x6b\n"
    "     INTERNET : 0xfc7c\n"
    "       SUM-24 : 0x00001b6b\n"
    "       SUM-32 : 0x00001b6b\n"
    "   FLETCHER-4 : 0x06\n"
    "   FLETCHER-8 : 0x7e\n"
    "  FLETCHER-16 : 0xeb86\n"
    "  FLETCHER-32 : 0xa98b0383\n"
    "     ADLER-32 : 0xec5d1b6c\n"
    "        XOR-8 : 0x0b\n"
    "         LUHN : 9\n"
    "     VERHOEFF : 1\n"
    "         DAMM : 3\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("checksum *") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(whole_file_fletcher)(void)
{
    // clang-format off
    const char* expected =
    "   FLETCHER-4 : 0x06\n"
    "   FLETCHER-8 : 0x7e\n"
    "  FLETCHER-16 : 0xeb86\n"
    "  FLETCHER-32 : 0xa98b0383\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("checksum FLETCHER") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(whole_file_one_checksum)(void)
{
    // clang-format off
    const char* expected =
    "     ADLER-32 : 0xec5d1b6c\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("checksum ADLER-32") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(one_byte_one_checksum)(void)
{
    // clang-format off
    const char* expected =
    "     ADLER-32 : 0x00800080\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("checksum ADLER-32 1") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(one_byte_off_one_checksum)(void)
{
    // clang-format off
    const char* expected =
    "     ADLER-32 : 0x00460046\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("checksum ADLER-32 1 1") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(invalid_offset)(void)
{
    int r = TEST_SUCCEEDED;
    if (exec_commands("checksum ADLER-32 1 99999999") == 0)
        r = TEST_FAILED;
    return r;
}

int TEST(size_too_big)(void)
{
    // clang-format off
    const char* expected =
    "     ADLER-32 : 0x4ba01aed\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("checksum ADLER-32 99999 1") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(list_checksums)(void)
{
    int r = TEST_FAILED;
    if (exec_commands("checksum/l") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    // Verify some known names are in the output
    if (strstr(out, "BSD") && strstr(out, "ADLER-32") && strstr(out, "LUHN") &&
        strstr(out, "DAMM"))
        r = TEST_SUCCEEDED;
    bhex_free(out);

end:
    return r;
}

int TEST(alias_cs)(void)
{
    // clang-format off
    const char* expected =
    "     ADLER-32 : 0xec5d1b6c\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("cs ADLER-32") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}
