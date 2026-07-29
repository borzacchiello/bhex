// Copyright (c) 2022-2026, bageyelet

#include "t_cmd_common.h"
#include "dummy_filebuffer.h"
#include "t.h"

#include <color.h>

/* The escapes of the colored graph, see common/color.c */
#define c_addr "\x1b[0;1;37m"
#define c_low  "\x1b[0;32m"
#define c_mid  "\x1b[0;33m"
#define c_high "\x1b[0;31m"
#define c_off  "\x1b[0m"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(notkitty)(void)
{
    // clang-format off
    const char* expected =
        "[ 00000000 - 0000000a ] (2.373) -------------+\n"
        "[ 0000000a - 00000014 ] (0.918) -----+\n"
        "[ 00000014 - 0000001e ] (2.518) --------------+\n"
        "[ 0000001e - 00000028 ] (0.464) --+\n"
        "[ 00000028 - 00000032 ] (2.156) ------------+\n"
        "[ 00000032 - 0000003c ] (0.918) -----+\n"
        "[ 0000003c - 00000046 ] (1.973) -----------+\n"
        "[ 00000046 - 00000050 ] (0.918) -----+\n"
        "[ 00000050 - 0000005a ] (1.357) -------+\n"
        "[ 0000005a - 00000064 ] (2.318) -------------+\n"
        "[ 00000064 - 0000006e ] (1.157) ------+\n"
        "[ 0000006e - 00000078 ] (1.357) -------+\n"
        "[ 00000078 - 00000082 ] (2.518) --------------+\n"
        "[ 00000082 - 0000008c ] (2.646) --------------+\n"
        "[ 0000008c - 00000096 ] (2.918) ----------------+\n"
        "[ 00000096 - 000000a0 ] (2.718) ---------------+\n"
        "[ 000000a0 - 000000aa ] (0.918) -----+\n"
        "[ 000000aa - 000000b4 ] (0.000) +\n"
        "[ 000000b4 - 000000be ] (0.000) +\n"
        "[ 000000be - 000000c8 ] (0.000) +\n"
        "[ 000000c8 - 000000d2 ] (0.918) -----+\n"
        "[ 000000d2 - 000000dc ] (2.156) ------------+\n"
        "[ 000000dc - 000000e6 ] (0.918) -----+\n"
        "[ 000000e6 - 000000f0 ] (0.464) --+\n"
        "[ 000000f0 - 000000fa ] (0.918) -----+\n"
        "[ 000000fa - 00000104 ] (2.156) ------------+\n"
        "[ 00000104 - 0000010e ] (0.918) -----+\n"
        "[ 0000010e - 00000118 ] (0.464) --+\n"
        "[ 00000118 - 00000122 ] (0.918) -----+\n"
        "[ 00000122 - 0000012c ] (0.000) +\n"
        "[ 0000012c - 00000136 ] (0.918) -----+\n"
        "[ 00000136 - 00000144 ] (0.368) --+\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("entropy 32") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(notkitty_rows_2)(void)
{
    // clang-format off
    const char* expected =
        "[ 00000000 - 000000a2 ] (3.456) -------------------+\n"
        "[ 000000a2 - 00000144 ] (1.155) ------+\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("entropy 2") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(notkitty_len_8)(void)
{
    // clang-format off
    const char* expected =
        "[ 00000000 - 00000008 ] (2.402) -------------+\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("entropy - 8") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(notkitty_len_8_rows_2)(void)
{
    // clang-format off
    const char* expected =
        "[ 00000000 - 00000004 ] (1.995) -----------+\n"
        "[ 00000004 - 00000008 ] (0.809) ----+\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("entropy 2 8") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(colors_by_band)(void)
{
    // 256 bytes covering every value land in the high band, 256 bytes
    // covering 64 of them in the middle one, and a run of zeroes in the low
    u8_t buf[768];
    for (int i = 0; i < 256; ++i) {
        buf[i]       = (u8_t)i;
        buf[256 + i] = (u8_t)(i % 64);
        buf[512 + i] = 0;
    }
    DummyFilebuffer* tfb = dummyfilebuffer_create(buf, sizeof(buf));

    // the colors are off by default in the tests, as they are whenever the
    // output is not a terminal
    colors_set_enabled(1);

    int r = TEST_FAILED;
    if (exec_commands_on("entropy 3", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r = strstr(out, c_high "(7.995)") != NULL &&
                strstr(out, c_mid "(5.995)") != NULL &&
                strstr(out, c_low "(0.000)") != NULL &&
                strstr(out, c_addr "[ 00000000 - 00000100 ]" c_off) != NULL
            ? TEST_SUCCEEDED
            : TEST_FAILED;
    bhex_free(out);

end:
    colors_set_enabled(0);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(empty)(void)
{
    int r = TEST_FAILED;
    if (exec_commands("s 0 ; d 324 ; entropy ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X("", out);
    bhex_free(out);

end:
    return r;
}
