// Copyright (c) 2022-2026, bageyelet

#include <stdio.h>

#include "t_cmd_common.h"
#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(setbase_default_zero)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("sb") == 0);

    char* out = strbuilder_reset(sb);
    ASSERT(strcmp(out, "0x0\n") == 0);
    bhex_free(out);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(setbase_set_value)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("sb 0x1000") == 0);
    ASSERT(elf_fb->fb->base_addr == 0x1000);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(setbase_change_value)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("sb 0x1000") == 0);
    ASSERT(elf_fb->fb->base_addr == 0x1000);
    ASSERT(exec_commands("sb 0x4000") == 0);
    ASSERT(elf_fb->fb->base_addr == 0x4000);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(setbase_display_after_set)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("sb 0xABCD; sb") == 0);

    char* out = strbuilder_reset(sb);
    ASSERT(strcmp(out, "0xabcd\n") == 0);
    bhex_free(out);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(setbase_seek_absolute)(void)
{
    /* With base=0x1000, s 0x1020 should seek to file offset 0x20 */
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("sb 0x1000; s 0x1020") == 0);
    ASSERT(elf_fb->fb->off == 0x20);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(setbase_seek_display)(void)
{
    /* With base=0x1000, s (no args) shows offset + base */
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("sb 0x1000; s 0x1020; s") == 0);
    ASSERT(elf_fb->fb->off == 0x20);

    char* out = strbuilder_reset(sb);
    ASSERT(strcmp(out, "0x1020\n") == 0);
    bhex_free(out);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(setbase_seek_below_base)(void)
{
    /* Cannot seek below base */
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("sb 0x1000; s 0x500") != 0);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(setbase_seek_below_base_zero)(void)
{
    /* s 0 is below base=0x1000 */
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("sb 0x1000; s 0") != 0);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(setbase_seek_relative_plus)(void)
{
    /* s/+ should continue working on raw file offsets */
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("sb 0x1000; s 0x1010; s/+ 0x5") == 0);
    ASSERT(elf_fb->fb->off == 0x15);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(setbase_seek_relative_minus)(void)
{
    /* s/- should continue working on raw file offsets */
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("sb 0x1000; s 0x1020; s/- 0x5") == 0);
    ASSERT(elf_fb->fb->off == 0x1b);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(setbase_seek_prev)(void)
{
    /* s - should still restore previous file offset */
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("sb 0x1000; s 0x1010; s 0x1020; s -") == 0);
    ASSERT(elf_fb->fb->off == 0x10);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(setbase_seek_minus_wrap)(void)
{
    /* s/- 1 at offset 0 with base=0x1000 wraps to end of file */
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("sb 0x1000; s 0x1000; s/- 1; s") == 0);
    ASSERT(elf_fb->fb->off == elf_fb->fb->size);

    /* displayed address should be base + size */
    char* out = strbuilder_reset(sb);
    char  expected[32];
    snprintf(expected, sizeof(expected), "0x%llx\n", elf_fb->fb->size + 0x1000);
    ASSERT(strcmp(out, expected) == 0);
    bhex_free(out);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(setbase_print_addresses)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("sb 0x1000; s 0x1000; p 4") == 0);

    /* First data line of output should show address 1000: */
    char*       out            = strbuilder_reset(sb);
    const char* expected_start = " 1000:";
    ASSERT(strstr(out, expected_start) != NULL);
    bhex_free(out);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(setbase_seek_no_base)(void)
{
    /* Without base, absolute seeks are raw file offsets */
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("s 0x50") == 0);
    ASSERT(elf_fb->fb->off == 0x50);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(setbase_invalid_mod)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("sb/x 0x1000") != 0);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(setbase_invalid_arg)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("sb not_a_number") != 0);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(setbase_too_many_args)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("sb 0x1000 0x2000") != 0);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}
