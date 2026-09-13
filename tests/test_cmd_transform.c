// Copyright (c) 2022-2026, bageyelet

#include "t_cmd_common.h"
#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

static DummyFilebuffer* counting_fb(void)
{
    static const u8_t data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    return dummyfilebuffer_create(data, sizeof(data));
}

static int check(const char* cmds, const char* expected)
{
    DummyFilebuffer* tfb = counting_fb();

    int r = TEST_FAILED;
    if (exec_commands_on(cmds, tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
}

static int check_fails(const char* cmds)
{
    DummyFilebuffer* tfb = counting_fb();
    int r = exec_commands_on(cmds, tfb) != 0 ? TEST_SUCCEEDED : TEST_FAILED;
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(xor_key)(void)
{
    // the key is repeated over the region
    return check("tr/xor \"ff 00\"; p/r 8", "FF01FD03FB05F907\n");
}

int TEST(xor_string_key)(void)
{
    return check("tr/xor/s A; p/r 8", "4140434245444746\n");
}

int TEST(xor_is_its_own_inverse)(void)
{
    return check("tr/xor \"de ad be ef\"; tr/xor \"de ad be ef\"; p/r 8",
                 "0001020304050607\n");
}

int TEST(not)(void) { return check("tr/not; p/r 8", "FFFEFDFCFBFAF9F8\n"); }

int TEST(and_or)(void)
{
    return check("tr/or \"f0\"; tr/and \"0f\"; p/r 8", "0001020304050607\n");
}

int TEST(add_sub)(void)
{
    // both wrap around a byte
    return check("tr/add \"10\"; p/r 8; tr/sub \"11\"; p/r 8",
                 "1011121314151617\nFF00010203040506\n");
}

int TEST(rol_ror)(void)
{
    return check("tr/rol 1; p/r 8; tr/ror 1; p/r 8",
                 "00020406080A0C0E\n0001020304050607\n");
}

int TEST(rol_of_eight_is_identity)(void)
{
    return check("tr/rol 8; p/r 8", "0001020304050607\n");
}

int TEST(rev)(void) { return check("tr/rev; p/r 8", "0706050403020100\n"); }

int TEST(swap)(void) { return check("tr/swap 4; p/r 8", "0302010007060504\n"); }

int TEST(swap_2)(void)
{
    return check("tr/swap 2; p/r 8", "0100030205040706\n");
}

int TEST(region)(void)
{
    // only <size> bytes at the cursor are touched
    return check("s 4; tr/not 2; s 0; p/r 8", "00010203FBFA0607\n");
}

int TEST(is_undoable)(void)
{
    // the whole transform is a single pending write
    return check("tr/not; u; p/r 8", "0001020304050607\n");
}

int TEST(bad_group_size)(void) { return check_fails("tr/swap 3"); }

int TEST(size_not_multiple_of_group)(void)
{
    return check_fails("tr/swap 4 6");
}

int TEST(size_past_the_end)(void) { return check_fails("tr/not 99"); }

int TEST(missing_key)(void) { return check_fails("tr/xor"); }

int TEST(bad_hex_key)(void) { return check_fails("tr/xor zz"); }

int TEST(rev_takes_no_key)(void) { return check_fails("tr/rev 4 4"); }

int TEST(nothing_left_to_transform)(void) { return check_fails("s 8; tr/not"); }
