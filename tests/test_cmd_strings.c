#include "dummy_filebuffer.h"
#include "t_cmd_common.h"
#include "t.h"

#include "data/wide_strings.h"
#include "data/big_buffers.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(no_param_1)(void)
{
    // clang-format off
    const char* expected =
        " [A] 0x0000001 @ ELF\n"
        " [A] 0x0000080 @ hello world\n"
        " [A] 0x000008D @ .shstrtab\n"
        " [A] 0x0000097 @ .text\n"
        " [A] 0x000009D @ .data\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("strings") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(min_len_1)(void)
{
    // clang-format off
    const char* expected =
        " [A] 0x0000080 @ hello world\n"
        " [A] 0x000008D @ .shstrtab\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("strings * 8") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(pattern_1)(void)
{
    // clang-format off
    const char* expected =
    " [A] 0x000008D @ .shstrtab\n"
    " [A] 0x0000097 @ .text\n"
    " [A] 0x000009D @ .data\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("strings .") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(null_terminated_1)(void)
{
    // clang-format off
    const char* expected =
        " [A] 0x0000080 @ hello world\n"
        " [A] 0x000008D @ .shstrtab\n"
        " [A] 0x0000097 @ .text\n"
        " [A] 0x000009D @ .data\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("strings/n") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(wide_strings)(void)
{
    // clang-format off
    const char* expected =
    " [W] 0x0000003 @ Hello, World!\n"
    " [A] 0x0000022 @ Ciao Mondo\n"
    " [W] 0x000002E @ Hola Mundo\n";
    // clang-format on

    DummyFilebuffer* tfb =
        dummyfilebuffer_create(wide_strings_data, sizeof(wide_strings_data));

    int r = TEST_FAILED;
    if (exec_commands_on("strings", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(exclude_wide_strings)(void)
{
    // clang-format off
    const char* expected =
    " [A] 0x0000022 @ Ciao Mondo\n";
    // clang-format on

    DummyFilebuffer* tfb =
        dummyfilebuffer_create(wide_strings_data, sizeof(wide_strings_data));

    int r = TEST_FAILED;
    if (exec_commands_on("strings/a", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(exclude_8bit_strings)(void)
{
    // clang-format off
    const char* expected =
    " [W] 0x0000003 @ Hello, World!\n"
    " [W] 0x000002E @ Hola Mundo\n";
    // clang-format on

    DummyFilebuffer* tfb =
        dummyfilebuffer_create(wide_strings_data, sizeof(wide_strings_data));

    int r = TEST_FAILED;
    if (exec_commands_on("strings/w", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(wide_strings_null_terminated)(void)
{
    // clang-format off
    const char* expected =
    " [W] 0x0000003 @ Hello, World!\n";
    // clang-format on

    DummyFilebuffer* tfb =
        dummyfilebuffer_create(wide_strings_data, sizeof(wide_strings_data));

    int r = TEST_FAILED;
    if (exec_commands_on("strings/n", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(sparse_strings)(void)
{
    // clang-format off
    const char* expected =
    " [A] 0x00003E8 @ Hello, World!\n"
    " [A] 0x0001388 @ The answer is 42.\n"
    " [W] 0x0002EE0 @ ciao\n";
    // clang-format on

    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sparse_strings, sizeof(sparse_strings));

    int r = TEST_FAILED;
    if (exec_commands_on("strings", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
}
