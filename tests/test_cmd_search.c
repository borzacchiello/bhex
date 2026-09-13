// Copyright (c) 2022-2026, bageyelet

#include "t_cmd_common.h"
#include "t.h"
#include "data/big_buffers.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(hello)(void)
{
    const char* expected = " >> Match @ 0x0000080\n";

    int r = TEST_FAILED;
    if (exec_commands_on("src hello", elf_fb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(hello_p)(void)
{
    // clang-format off
    const char* expected =
        " >> Match @ 0x0000080\n"
        "\n"
        "       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F \n"
        "       -----------------------------------------------\n"
        " 0070: 00 10 00 00 B8 01 00 00 00 BB 2A 00 00 00 CD 80   ..........*.....\n"
        " 0080: 68 65 6C 6C 6F 20 77 6F 72 6C 64 00 00 2E 73 68   hello world...sh\n"
        " 0090: 73 74 72 74 61 62 00 2E 74 65 78 74 00 2E 64 61   strtab..text..da\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands_on("src/p hello", elf_fb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(hex)(void)
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

int TEST(hex_seek)(void)
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

int TEST(search_in_big_buffer)(void)
{
    const char* expected = "";

    DummyFilebuffer* tfb =
        dummyfilebuffer_create(answer_to_universe, sizeof(answer_to_universe));

    int r = TEST_FAILED;
    if (exec_commands_on("src/x 80", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(hex_wildcard)(void)
{
    // '?' matches any value for that nibble: B8 01 00 00 is at 0x74
    const char* expected = " >> Match @ 0x0000074\n";

    int r = TEST_FAILED;
    if (exec_commands("src/x \"B8 ?1 0? ??\"") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(hex_wildcard_no_match)(void)
{
    // the nibbles that are pinned down still have to agree
    const char* expected = "";

    int r = TEST_FAILED;
    if (exec_commands("src/x \"B8 ?2 0? ??\"") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(hex_bad_wildcard)(void)
{
    // a lone '?' leaves the needle with half a byte
    if (exec_commands("src/x \"B8 ?\"") == 0)
        return TEST_FAILED;
    return TEST_SUCCEEDED;
}

int TEST(range)(void)
{
    // "hello" is at 0x80, out of a 0x40 bytes window opened at 0x10
    const char* expected = "";

    int r = TEST_FAILED;
    if (exec_commands("s 0x10; src hello 0x40") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(range_hit)(void)
{
    // ... and inside one that covers it
    const char* expected = " >> Match @ 0x0000080\n";

    int r = TEST_FAILED;
    if (exec_commands("s 0x70; src hello 0x40") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(range_stops_at_eof)(void)
{
    // a length past the end of the file is clamped, not an error
    const char* expected = " >> Match @ 0x0000080\n";

    int r = TEST_FAILED;
    if (exec_commands("s 0x70; src hello 0xffffff") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(first_only)(void)
{
    // '/1' stops at the first match, which is also the lowest one: the elf
    // header holds several 0x00 0x00 pairs
    const char* expected = " >> Match @ 0x0000007\n";

    int r = TEST_FAILED;
    if (exec_commands("src/1/x \"00 00 00\"") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(first_only_seek)(void)
{
    // and with '/sk' the cursor lands on it, not on the last match reported
    const char* expected = " >> Match @ 0x0000007\n0x7\n";

    int r = TEST_FAILED;
    if (exec_commands("src/1/sk/x \"00 00 00\" ; s ; s 0") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}
