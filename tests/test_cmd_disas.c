// Copyright (c) 2022-2026, bageyelet

#include "dummy_filebuffer.h"
#include "t_cmd_common.h"
#include "t.h"

#include <unicode.h>
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
               " " c_mnem "nop" c_off "\n";

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

int TEST(m68k_operands_aligned)(void)
{
#ifndef DISABLE_CAPSTONE
    // the mnemonics of m68k carry a size suffix and differ in length ("moveq"
    // against "movea.l"): the operands must start at the same column anyway
    const u8_t bytes[] = {0x70, 0x0c, 0x2a, 0x7c, 0x40, 0x66, 0x35, 0x24, 0x00};
    DummyFilebuffer* tfb = dummyfilebuffer_create(bytes, sizeof(bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds m68k 2", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = (strstr(out, "moveq   #$c, d0\n") != NULL &&
                 strstr(out, "movea.l #$40663524, a5\n") != NULL)
                    ? TEST_SUCCEEDED
                    : TEST_FAILED;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

/* The branch arrows of "ds/a". The bytes are hand assembled so that the
 * geometry of the gutter is known exactly: a m68k branch lands on
 * <address of the branch> + 2 + <displacement>. */

int TEST(m68k_arrows_forward)(void)
{
#ifndef DISABLE_CAPSTONE
    // bra.b $6, then three nops: the branch and its target are both printed,
    // so the two are joined by a line
    const u8_t bytes[] = {0x60, 0x04, 0x4e, 0x71, 0x4e, 0x71, 0x4e, 0x71, 0x00};
    DummyFilebuffer* tfb = dummyfilebuffer_create(bytes, sizeof(bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds/a m68k 4", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = (strstr(out, "/< bra.b") != NULL && /* the jump */
                 strstr(out, "|  nop") != NULL &&   /* the rows it spans */
                 strstr(out, "\\> nop") != NULL)    /* where it lands */
                    ? TEST_SUCCEEDED
                    : TEST_FAILED;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(m68k_arrows_backward)(void)
{
#ifndef DISABLE_CAPSTONE
    // a nop and a "dbra d0, $0" jumping back to it: the corners are the other
    // way around, as the target is above the branch
    const u8_t       bytes[] = {0x4e, 0x71, 0x51, 0xc8, 0xff, 0xfc, 0x00};
    DummyFilebuffer* tfb     = dummyfilebuffer_create(bytes, sizeof(bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds/a m68k 2", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r = (strstr(out, "/> nop") != NULL && strstr(out, "\\< dbra") != NULL)
            ? TEST_SUCCEEDED
            : TEST_FAILED;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(m68k_arrows_nested)(void)
{
#ifndef DISABLE_CAPSTONE
    // bra.b $a and bra.b $8: the second one is nested in the first, so they
    // cannot share a lane. The shorter one gets the lane closest to the code
    const u8_t       bytes[] = {0x60, 0x08, 0x60, 0x04, 0x4e, 0x71, 0x4e,
                                0x71, 0x4e, 0x71, 0x4e, 0x71, 0x00};
    DummyFilebuffer* tfb     = dummyfilebuffer_create(bytes, sizeof(bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds/a m68k 6", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r = (strstr(out, "/-< bra.b") != NULL && /* outer branch */
         strstr(out, "|/< bra.b") != NULL && /* inner one, crossed by it */
         strstr(out, "||  nop") != NULL &&   /* both lanes busy */
         strstr(out, "|\\> nop") != NULL &&  /* inner target */
         strstr(out, "\\-> nop") != NULL)    /* outer target */
            ? TEST_SUCCEEDED
            : TEST_FAILED;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(m68k_arrows_off_listing)(void)
{
#ifndef DISABLE_CAPSTONE
    // the same branches, with a listing that stops before their targets: with
    // nothing to draw a line to, only the direction is marked
    const u8_t       bytes[] = {0x60, 0x08, 0x60, 0x04, 0x4e, 0x71, 0x4e,
                                0x71, 0x4e, 0x71, 0x4e, 0x71, 0x00};
    DummyFilebuffer* tfb     = dummyfilebuffer_create(bytes, sizeof(bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds/a m68k 2", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r = (strstr(out, "v< bra.b   $a") != NULL &&
         strstr(out, "v< bra.b   $8") != NULL && strchr(out, '|') == NULL)
            ? TEST_SUCCEEDED
            : TEST_FAILED;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(m68k_arrows_off_listing_backwards)(void)
{
#ifndef DISABLE_CAPSTONE
    // four nops and a "dbra d0, $0"; the listing starts at the branch, so its
    // target is above what is printed
    const u8_t       bytes[] = {0x4e, 0x71, 0x4e, 0x71, 0x4e, 0x71, 0x4e,
                                0x71, 0x51, 0xc8, 0xff, 0xf6, 0x00};
    DummyFilebuffer* tfb     = dummyfilebuffer_create(bytes, sizeof(bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("s 8; ds/a m68k 1", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "^< dbra") != NULL ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(x64_arrows)(void)
{
#ifndef DISABLE_CAPSTONE
    // capstone hands over the target of a branch in a different way for m68k
    // than for every other architecture: x86 exercises the common one
    const u8_t       bytes[] = {0xeb, 0x02, 0x90, 0x90, 0x90, 0x90};
    DummyFilebuffer* tfb     = dummyfilebuffer_create(bytes, sizeof(bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds/a x64 4", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r = (strstr(out, "/< jmp") != NULL && strstr(out, "\\> nop") != NULL)
            ? TEST_SUCCEEDED
            : TEST_FAILED;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(x64_arrows_indirect)(void)
{
#ifndef DISABLE_CAPSTONE
    // "jmp rax" goes somewhere that is not known here: no arrow, and with no
    // arrow at all in the listing there is no gutter either
    const u8_t       bytes[] = {0xff, 0xe0, 0x90, 0x90};
    DummyFilebuffer* tfb     = dummyfilebuffer_create(bytes, sizeof(bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds/a x64 2", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r = (strstr(out, "jmp     rax") != NULL && strpbrk(out, "|<>v^") == NULL)
            ? TEST_SUCCEEDED
            : TEST_FAILED;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(x64_no_arrows_without_mod)(void)
{
#ifndef DISABLE_CAPSTONE
    // the arrows are asked for with "/a": a plain "ds" of the very listing
    // that has one keeps printing what it always did
    const u8_t       bytes[]  = {0xeb, 0x02, 0x90, 0x90, 0x90, 0x90};
    DummyFilebuffer* tfb      = dummyfilebuffer_create(bytes, sizeof(bytes));
    const char*      expected = "0x00000000: eb 02                 jmp     4\n"
                                "0x00000002: 90                    nop\n"
                                "0x00000003: 90                    nop\n"
                                "0x00000004: 90                    nop\n";

    int r = TEST_FAILED;
    if (exec_commands_on("ds x64 4", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strcmp(out, expected) == 0 ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(x64_arrows_colors)(void)
{
#ifndef DISABLE_CAPSTONE
    // the gutter is painted as what it describes: control flow
    const u8_t       bytes[] = {0xeb, 0x02, 0x90, 0x90, 0x90, 0x90};
    DummyFilebuffer* tfb     = dummyfilebuffer_create(bytes, sizeof(bytes));

    colors_set_enabled(1);

    int r = TEST_FAILED;
    if (exec_commands_on("ds/a x64 4", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, c_flow "/<" c_off " " c_flow "jmp" c_off) != NULL
                    ? TEST_SUCCEEDED
                    : TEST_FAILED;
    bhex_free(out);

end:
    colors_set_enabled(0);
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(m68k_arrows_join)(void)
{
#ifndef DISABLE_CAPSTONE
    // two branches landing on the same instruction: the two lines have to join
    // into one, not sit next to each other. "bra.b $c" and "bra.b $c" from two
    // different places, with the nesting that keeps them in two lanes
    const u8_t       bytes[] = {0x60, 0x0a, 0x4e, 0x71, 0x60, 0x06, 0x4e, 0x71,
                                0x4e, 0x71, 0x4e, 0x71, 0x4e, 0x71, 0x00};
    DummyFilebuffer* tfb     = dummyfilebuffer_create(bytes, sizeof(bytes));

    int r = TEST_FAILED;
    // the instruction the two land on is the seventh
    if (exec_commands_on("ds/a m68k 7", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    /* the junction of the outer line with the inner one, '+' in ascii */
    r = strstr(out, "\\+> nop") != NULL ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(m68k_arrows_unicode)(void)
{
#ifndef DISABLE_CAPSTONE
    // the same listing as m68k_arrows_nested, drawn with box drawing
    // characters: this is what a UTF-8 terminal gets
    const u8_t       bytes[] = {0x60, 0x08, 0x60, 0x04, 0x4e, 0x71, 0x4e,
                                0x71, 0x4e, 0x71, 0x4e, 0x71, 0x00};
    DummyFilebuffer* tfb     = dummyfilebuffer_create(bytes, sizeof(bytes));

    // as the colors, unicode is off unless the environment is known to take
    // it, which is never the case for the tests
    unicode_set_enabled(1);

    int r = TEST_FAILED;
    if (exec_commands_on("ds/a m68k 6", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r = (strstr(out, "╭─◂ bra.b") != NULL && strstr(out, "│╭◂ bra.b") != NULL &&
         strstr(out, "││  nop") != NULL && strstr(out, "│╰▸ nop") != NULL &&
         strstr(out, "╰─▸ nop") != NULL)
            ? TEST_SUCCEEDED
            : TEST_FAILED;
    bhex_free(out);

end:
    unicode_set_enabled(0);
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(m68k_arrows_unicode_join)(void)
{
#ifndef DISABLE_CAPSTONE
    // where two lines meet, the glyph is the one that joins them
    const u8_t       bytes[] = {0x60, 0x0a, 0x4e, 0x71, 0x60, 0x06, 0x4e, 0x71,
                                0x4e, 0x71, 0x4e, 0x71, 0x4e, 0x71, 0x00};
    DummyFilebuffer* tfb     = dummyfilebuffer_create(bytes, sizeof(bytes));

    unicode_set_enabled(1);

    int r = TEST_FAILED;
    if (exec_commands_on("ds/a m68k 7", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "╰┴▸ nop") != NULL ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    unicode_set_enabled(0);
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(m68k_arrows_unicode_off_listing)(void)
{
#ifndef DISABLE_CAPSTONE
    // the direction markers of the targets that are not printed
    const u8_t       bytes[] = {0x60, 0x08, 0x60, 0x04, 0x4e, 0x71, 0x4e,
                                0x71, 0x4e, 0x71, 0x4e, 0x71, 0x00};
    DummyFilebuffer* tfb     = dummyfilebuffer_create(bytes, sizeof(bytes));

    unicode_set_enabled(1);

    int r = TEST_FAILED;
    if (exec_commands_on("ds/a m68k 2", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "▾◂ bra.b") != NULL ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    unicode_set_enabled(0);
    dummyfilebuffer_destroy(tfb);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(arrows_invalid_mod_combination)(void)
{
#ifndef DISABLE_CAPSTONE
    // listing the architectures and disassembling are two different requests
    return exec_commands("ds/l/a") != 0;
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
