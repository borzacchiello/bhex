// Copyright (c) 2022-2026, bageyelet

#include "t_cmd_common.h"
#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(echo_no_args)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("echo") == 0);

    char* out = strbuilder_reset(sb);
    ASSERT(strcmp(out, "\n") == 0);
    bhex_free(out);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(echo_string_arg)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("echo hello") == 0);

    char* out = strbuilder_reset(sb);
    ASSERT(strcmp(out, "hello\n") == 0);
    bhex_free(out);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(echo_multiple_strings)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("echo hello world") == 0);

    char* out = strbuilder_reset(sb);
    ASSERT(strcmp(out, "hello world\n") == 0);
    bhex_free(out);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(echo_number_hex_default)(void)
{
    // Numbers are printed in hex by default
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("echo 42") == 0);

    char* out = strbuilder_reset(sb);
    ASSERT(strcmp(out, "0x2a\n") == 0);
    bhex_free(out);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(echo_number_dec_mod)(void)
{
    // /d modifier forces decimal
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("echo/d 42") == 0);

    char* out = strbuilder_reset(sb);
    ASSERT(strcmp(out, "42\n") == 0);
    bhex_free(out);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(echo_number_hex_mod)(void)
{
    // /x modifier forces hex (explicit)
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("echo/x 42") == 0);

    char* out = strbuilder_reset(sb);
    ASSERT(strcmp(out, "0x2a\n") == 0);
    bhex_free(out);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(echo_expr_simple)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("echo `10 + 20`") == 0);

    char* out = strbuilder_reset(sb);
    ASSERT(strcmp(out, "0x1e\n") == 0);
    bhex_free(out);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(echo_expr_hex)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("echo `0x10 + 0x20`") == 0);

    char* out = strbuilder_reset(sb);
    ASSERT(strcmp(out, "0x30\n") == 0);
    bhex_free(out);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(echo_expr_dec)(void)
{
    // Expression result with /d modifier
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("echo/d `10 + 20`") == 0);

    char* out = strbuilder_reset(sb);
    ASSERT(strcmp(out, "30\n") == 0);
    bhex_free(out);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(echo_mixed_args)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("echo value: `10 + 5`") == 0);

    char* out = strbuilder_reset(sb);
    // "value:" is a string, "15" is a number -> printed in hex
    ASSERT(strcmp(out, "value: 0xf\n") == 0);
    bhex_free(out);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(echo_mem_deref)(void)
{
    int r = TEST_SUCCEEDED;
    // First byte of ELF is 0x7f
    ASSERT(exec_commands("echo `[8 0x0]`") == 0);

    char* out = strbuilder_reset(sb);
    ASSERT(strcmp(out, "0x7f\n") == 0);
    bhex_free(out);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(seek_with_expr)(void)
{
    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("s `0x10 + 0x20`") == 0);
    ASSERT(elf_fb->fb->off == 0x30);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(echo_expr_failed)(void)
{
    // Invalid expression should cause the command to not execute
    int r = exec_commands("echo `[12 0x0]`");
    ASSERT(r == 1); // should fail

    return TEST_SUCCEEDED;

fail:
    return TEST_FAILED;
}
