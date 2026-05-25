// Copyright (c) 2022-2026, bageyelet

#include "dummy_filebuffer.h"
#include "t_cmd_common.h"
#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(invalid_num_args)(void)
{
#ifndef DISABLE_KEYSTONE
    return exec_commands("as") != 0;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(invalid_arch)(void)
{
#ifndef DISABLE_KEYSTONE
    return exec_commands("as invalid_arch \"nop\"") != 0;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(list_archs)(void)
{
#ifndef DISABLE_KEYSTONE
    const char* expected = "Supported architectures:\n"
                           "    x64\n"
                           "    x86\n"
                           "    i8086\n"
                           "    arm32\n"
                           "    aarch64\n"
                           "    arm32-thumb\n"
                           "    mips32\n"
                           "    mips64\n"
                           "    mipsel32\n"
                           "    mipsel64\n"
                           "    ppc32\n"
                           "    ppc64\n"
                           "    ppcle32\n"
                           "    ppcle64\n"
                           "    riscv32\n"
                           "    riscv64\n"
                           "    s390x\n"
                           "    sparc\n"
                           "    sparc64\n";

    int r = TEST_FAILED;
    if (exec_commands("as/l") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(x64_nop)(void)
{
#ifndef DISABLE_KEYSTONE
    /* Assemble "nop" for x64: should write 0x90 at current offset */
    const char* expected = "90\n";

    int r = TEST_FAILED;
    if (exec_commands("as x64 \"nop\" ; p/r 1 ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(x86_nop)(void)
{
#ifndef DISABLE_KEYSTONE
    const char* expected = "90\n";

    int r = TEST_FAILED;
    if (exec_commands("as x86 \"nop\" ; p/r 1 ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(x64_seek)(void)
{
#ifndef DISABLE_KEYSTONE
    /*
     * With /s, the offset advances past the written bytes.
     * After writing a 1-byte nop at offset 0, the offset moves to 1.
     * p/r 1 then reads the original byte at offset 1.
     */
    const u8_t       orig_bytes[] = {0xAA, 0xBB, 0xCC, 0xDD};
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(orig_bytes, sizeof(orig_bytes));

    const char* expected = "BB\n";

    int r = TEST_FAILED;
    if (exec_commands_on("as/s x64 \"nop\" ; p/r 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(x64_insert)(void)
{
#ifndef DISABLE_KEYSTONE
    /*
     * With /i, the assembled bytes are inserted rather than overwriting.
     * After inserting nop (0x90) at offset 0, the file grows by 1:
     * first byte is 0x90, second byte is the original 0xAA.
     */
    const u8_t       orig_bytes[] = {0xAA, 0xBB, 0xCC};
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(orig_bytes, sizeof(orig_bytes));

    const char* expected = "90AA\n";

    int r = TEST_FAILED;
    if (exec_commands_on("as/i x64 \"nop\" ; p/r 2", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(riscv64_addiw)(void)
{
#ifndef DISABLE_KEYSTONE
    const char* expected = "1B00A000\n";

    int r = TEST_FAILED;
    if (exec_commands("as riscv64 \"addiw x0, x0, 10\" ; p/r 4 ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(s390x_a)(void)
{
#ifndef DISABLE_KEYSTONE
    const char* expected = "5A0F1FFF\n";

    int r = TEST_FAILED;
    if (exec_commands("as s390x \"a %r0, 4095(%r15,%r1)\" ; p/r 4 ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(sparc_add)(void)
{
#ifndef DISABLE_KEYSTONE
    const char* expected = "86004002\n";

    int r = TEST_FAILED;
    if (exec_commands("as sparc \"add %g1, %g2, %g3\" ; p/r 4 ; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
#else
    return TEST_SKIPPED;
#endif
}
