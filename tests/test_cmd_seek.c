// Copyright (c) 2022-2026, bageyelet

#include "t_cmd_common.h"
#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(print_offset)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("s") == 0);

    char* out = strbuilder_reset(sb);
    ASSERT(strcmp(out, "0x0\n") == 0);
    bhex_free(out);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(seek_absolute)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("s 0x10") == 0);
    ASSERT(elf_fb->fb->off == 0x10);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(seek_relative_plus)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("s 0x10;s/+ 0x5") == 0);
    ASSERT(elf_fb->fb->off == 0x15);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(seek_relative_minus)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("s 0x20;s/- 0x5") == 0);
    ASSERT(elf_fb->fb->off == 0x1b);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(seek_previous)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("s 0x10;s 0x20;s -") == 0);
    ASSERT(elf_fb->fb->off == 0x10);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(seek_past_end)(void)
{
    int r = TEST_SUCCEEDED;
    // Seeking past file size should fail
    ASSERT(exec_commands("s 0xffffffffffff") != 0);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(seek_minus_wrap)(void)
{
    int r = TEST_SUCCEEDED;
    // Subtracting more than current offset should wrap
    ASSERT(exec_commands("s 0x5;s/- 0x10") == 0);
    // Should wrap around: size + 1 - min(size, 0x10)

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}
