// Copyright (c) 2022-2026, bageyelet

#include "dummy_filebuffer.h"
#include "t_cmd_common.h"
#include "t.h"

#include <color.h>

/* The escapes of the colored disassembly, see common/color.c */
#define c_addr "\x1b[0;1;37m"
#define c_dim  "\x1b[0;90m" /* opcode bytes */
#define c_mnem "\x1b[0;1;37m"
#define c_flow "\x1b[0;1;33m" /* jumps, calls, returns */
#define c_off  "\x1b[0m"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(invalid_num_args)(void)
{
#ifndef DISABLE_CAPSTONE
    return exec_commands("ds") != 0;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(invalid_arch)(void)
{
#ifndef DISABLE_CAPSTONE
    return exec_commands("ds invalid_arch") != 0;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(list_archs)(void)
{
#ifndef DISABLE_CAPSTONE
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
                           "    m68k\n"
                           "    alpha\n"
                           "    riscv32\n"
                           "    riscv64\n"
                           "    s390x\n"
                           "    sparc\n"
                           "    sparc64\n"
                           "    bpf\n"
                           "    ebpf\n";

    int r = TEST_FAILED;
    if (exec_commands("ds/l") != 0)
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
#ifndef DISABLE_CAPSTONE
    const u8_t       nop_bytes[] = {0x90, 0x90};
    DummyFilebuffer* tfb = dummyfilebuffer_create(nop_bytes, sizeof(nop_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds x64 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "nop") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(x64_ret)(void)
{
#ifndef DISABLE_CAPSTONE
    const u8_t       ret_bytes[] = {0xC3, 0x00};
    DummyFilebuffer* tfb = dummyfilebuffer_create(ret_bytes, sizeof(ret_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds x64 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "ret") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(x64_colors)(void)
{
#ifndef DISABLE_CAPSTONE
    const u8_t       nop_bytes[] = {0x90, 0x90};
    DummyFilebuffer* tfb = dummyfilebuffer_create(nop_bytes, sizeof(nop_bytes));
    const char*      expected =
        c_addr "0x00000000:" c_off " " c_dim "90                   " c_off
               " " c_mnem "nop" c_off "\t\t\n";

    // the colors are off by default in the tests, as they are whenever the
    // output is not a terminal
    colors_set_enabled(1);

    int r = TEST_FAILED;
    if (exec_commands_on("ds x64 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strcmp(out, expected) == 0 ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    colors_set_enabled(0);
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(x64_colors_control_flow)(void)
{
#ifndef DISABLE_CAPSTONE
    // a return is a control flow instruction: it must stand out from the
    // mnemonics that just compute something
    const u8_t       ret_bytes[] = {0xC3, 0x00};
    DummyFilebuffer* tfb = dummyfilebuffer_create(ret_bytes, sizeof(ret_bytes));

    colors_set_enabled(1);

    int r = TEST_FAILED;
    if (exec_commands_on("ds x64 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r = strstr(out, c_flow "ret" c_off) != NULL ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    colors_set_enabled(0);
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(x86_nop)(void)
{
#ifndef DISABLE_CAPSTONE
    const u8_t       nop_bytes[] = {0x90, 0x90};
    DummyFilebuffer* tfb = dummyfilebuffer_create(nop_bytes, sizeof(nop_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds x86 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "nop") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(ppc32_blr)(void)
{
#ifndef DISABLE_CAPSTONE
    const u8_t       blr_bytes[] = {0x4E, 0x80, 0x00, 0x20, 0x00};
    DummyFilebuffer* tfb = dummyfilebuffer_create(blr_bytes, sizeof(blr_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds ppc32 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "blr") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(ppc32_nop)(void)
{
#ifndef DISABLE_CAPSTONE
    const u8_t       nop_bytes[] = {0x60, 0x00, 0x00, 0x00, 0x00};
    DummyFilebuffer* tfb = dummyfilebuffer_create(nop_bytes, sizeof(nop_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds ppc32 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "nop") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(ppc64_mflr)(void)
{
#ifndef DISABLE_CAPSTONE
    const u8_t       mflr_bytes[] = {0x7C, 0x08, 0x02, 0xA6, 0x00};
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(mflr_bytes, sizeof(mflr_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds ppc64 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "mflr") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(ppc32_add)(void)
{
#ifndef DISABLE_CAPSTONE
    const u8_t       add_bytes[] = {0x7C, 0x22, 0x1A, 0x14, 0x00};
    DummyFilebuffer* tfb = dummyfilebuffer_create(add_bytes, sizeof(add_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds ppc32 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "add") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(ppcle64_blr)(void)
{
#ifndef DISABLE_CAPSTONE
    const u8_t       blr_bytes[] = {0x20, 0x00, 0x80, 0x4E, 0x00};
    DummyFilebuffer* tfb = dummyfilebuffer_create(blr_bytes, sizeof(blr_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds ppcle64 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "blr") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(m68k_nop)(void)
{
#ifndef DISABLE_CAPSTONE
    const u8_t       nop_bytes[] = {0x4E, 0x71, 0x00};
    DummyFilebuffer* tfb = dummyfilebuffer_create(nop_bytes, sizeof(nop_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds m68k 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "nop") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(alpha_addq)(void)
{
#ifndef DISABLE_CAPSTONE
    const u8_t       addq_bytes[] = {0x03, 0x04, 0x22, 0x40, 0x00};
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(addq_bytes, sizeof(addq_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds alpha 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "addq") != NULL;
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
#ifndef DISABLE_CAPSTONE
    const u8_t       addiw_bytes[] = {0x1B, 0x00, 0xA0, 0x00, 0x00};
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(addiw_bytes, sizeof(addiw_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds riscv64 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "addiw") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(s390x_agr)(void)
{
#ifndef DISABLE_CAPSTONE
    const u8_t       agr_bytes[] = {0xB9, 0x08, 0x00, 0x78, 0x00};
    DummyFilebuffer* tfb = dummyfilebuffer_create(agr_bytes, sizeof(agr_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds s390x 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "agr") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(sparc_add)(void)
{
#ifndef DISABLE_CAPSTONE
    const u8_t       add_bytes[] = {0x86, 0x00, 0x40, 0x02, 0x00};
    DummyFilebuffer* tfb = dummyfilebuffer_create(add_bytes, sizeof(add_bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds sparc 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "add") != NULL;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}
