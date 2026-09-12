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

// A listing longer than what a single fb_read() can serve is read,
// disassembled and printed one block at a time
#define LONG_LISTING_BYTES 5000
// the address of its last instruction, all of them being one byte long
#define LONG_LISTING_LAST "0x00001387:"

__attribute__((unused)) static u8_t* nop_buffer(size_t size)
{
    u8_t* b = bhex_malloc(size);
    memset(b, 0x90, size); /* x64 nop */
    return b;
}

__attribute__((unused)) static size_t count_occurrences(const char* s,
                                                        const char* what)
{
    size_t n = 0;
    for (const char* p = strstr(s, what); p != NULL; p = strstr(p + 1, what))
        n += 1;
    return n;
}

// The column the mnemonic of the row of `addr` starts at, or -1 when that row
// is not part of the output. Only the rows holding a nop can be asked for
__attribute__((unused)) static int mnemonic_column(const char* out,
                                                   const char* addr)
{
    const char* line = strstr(out, addr);
    if (line == NULL)
        return -1;

    const char* end = strchr(line, '\n');
    const char* m   = strstr(line, "nop");
    if (m == NULL || (end != NULL && m > end))
        return -1;
    return (int)(m - line);
}

int TEST(x64_listing_longer_than_a_block)(void)
{
#ifndef DISABLE_CAPSTONE
    // more nops than one block holds: every one of them must be printed
    // exactly once, the instruction the blocks are cut at included
    u8_t*            bytes = nop_buffer(LONG_LISTING_BYTES);
    DummyFilebuffer* tfb   = dummyfilebuffer_create(bytes, LONG_LISTING_BYTES);

    int r = TEST_FAILED;
    if (exec_commands_on("ds x64 5000", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = (count_occurrences(out, "nop") == LONG_LISTING_BYTES &&
                 strstr(out, "0x00000000:") != NULL &&
                 strstr(out, LONG_LISTING_LAST) != NULL &&
                 count_occurrences(out, "0x00000fff:") == 1)
                    ? TEST_SUCCEEDED
                    : TEST_FAILED;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    bhex_free(bytes);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(x64_listing_stops_at_the_end_of_the_file)(void)
{
#ifndef DISABLE_CAPSTONE
    // asking for more instructions than the file holds is not an error: the
    // listing simply ends with the file
    const u8_t       bytes[] = {0x90, 0x90};
    DummyFilebuffer* tfb     = dummyfilebuffer_create(bytes, sizeof(bytes));

    int r = TEST_FAILED;
    if (exec_commands_on("ds x64 1000", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r = (count_occurrences(out, "nop") == 2 && strstr(out, "invalid") == NULL)
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

int TEST(x64_arrows_across_blocks)(void)
{
#ifndef DISABLE_CAPSTONE
    // the same listing, with a jump near the end of the first block landing
    // in the second one: the arrows of a block are drawn without seeing the
    // rest of the listing, so the target is an off-listing one
    u8_t* bytes          = nop_buffer(LONG_LISTING_BYTES);
    bytes[0x0fe0]        = 0xeb; /* jmp $+0x81 */
    bytes[0x0fe1]        = 0x7f;
    DummyFilebuffer* tfb = dummyfilebuffer_create(bytes, LONG_LISTING_BYTES);

    int r = TEST_FAILED;
    if (exec_commands_on("ds/a x64 5000", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    // and the gutter keeps the width it has on the first row all the way
    // down, so that the mnemonics of every block stay in the same column
    r = (strstr(out, "v< jmp") != NULL &&
         mnemonic_column(out, "0x00000000:") > 0 &&
         mnemonic_column(out, "0x00000000:") ==
             mnemonic_column(out, LONG_LISTING_LAST))
            ? TEST_SUCCEEDED
            : TEST_FAILED;
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    bhex_free(bytes);
    return r;
#else
    return TEST_SKIPPED;
#endif
}

// "ds <arch>" with no count runs to the end of the function. What that means
// is one thing per architecture, see common/disassemble

// Runs the command on `bytes` and gives back what it printed, for the caller
// to free, or NULL when the command failed
__attribute__((unused)) static char*
disas_until_return(const char* arch, const u8_t* bytes, size_t size)
{
    DummyFilebuffer* tfb = dummyfilebuffer_create(bytes, size);
    char             cmd[64];
    snprintf(cmd, sizeof(cmd), "ds %s", arch);

    char* out = NULL;
    if (exec_commands_on(cmd, tfb) == 0)
        out = strbuilder_reset(sb);

    dummyfilebuffer_destroy(tfb);
    return out;
}

// the rows of a listing: every one of them starts with the address
__attribute__((unused)) static size_t count_rows(const char* out)
{
    size_t n = strncmp(out, "0x", 2) == 0 ? 1 : 0;
    return n + count_occurrences(out, "\n0x");
}

__attribute__((unused)) static int until_return_is(const char* arch,
                                                   const u8_t* bytes,
                                                   size_t size, size_t rows,
                                                   const char* last)
{
    char* out = disas_until_return(arch, bytes, size);
    int   r   = out != NULL && count_rows(out) == rows &&
                strstr(out, last) != NULL && strstr(out, "invalid") == NULL;
    bhex_free(out);
    return r ? TEST_SUCCEEDED : TEST_FAILED;
}

int TEST(x64_until_return)(void)
{
#ifndef DISABLE_CAPSTONE
    // two nops, a ret, and instructions that are not part of the function
    const u8_t bytes[] = {0x90, 0x90, 0xc3, 0x90, 0x90, 0x90, 0x90};
    return until_return_is("x64", bytes, sizeof(bytes), 3, "ret");
#else
    return TEST_SKIPPED;
#endif
}

int TEST(m68k_until_return)(void)
{
#ifndef DISABLE_CAPSTONE
    // nop, rts
    const u8_t bytes[] = {0x4e, 0x71, 0x4e, 0x75, 0x4e, 0x71, 0x4e, 0x71};
    return until_return_is("m68k", bytes, sizeof(bytes), 2, "rts");
#else
    return TEST_SKIPPED;
#endif
}

int TEST(ppc32_until_return)(void)
{
#ifndef DISABLE_CAPSTONE
    // "blr" is a "bclr" that capstone prints as its alias, so the mnemonic is
    // what says the branch to the link register is the unconditional one
    const u8_t bytes[] = {0x60, 0x00, 0x00, 0x00, 0x4e, 0x80, 0x00, 0x20,
                          0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00};
    return until_return_is("ppc32", bytes, sizeof(bytes), 2, "blr");
#else
    return TEST_SKIPPED;
#endif
}

int TEST(mips32_until_return_takes_the_delay_slot)(void)
{
#ifndef DISABLE_CAPSTONE
    // "jr $ra" is a return, and the instruction in its delay slot runs
    // before it is taken: the listing ends with that one
    const u8_t bytes[] = {0x00, 0x00, 0x00, 0x00, 0x03, 0xe0, 0x00, 0x08,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    return until_return_is("mips32", bytes, sizeof(bytes), 3, "jr");
#else
    return TEST_SKIPPED;
#endif
}

int TEST(mips32_jump_through_another_register_is_not_a_return)(void)
{
#ifndef DISABLE_CAPSTONE
    // the same "jr", through $t9: a jump like any other, and the listing
    // carries on to the end of the file
    const u8_t bytes[] = {0x03, 0x20, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    return until_return_is("mips32", bytes, sizeof(bytes), 4, "jr");
#else
    return TEST_SKIPPED;
#endif
}

int TEST(sparc_until_return_takes_the_delay_slot)(void)
{
#ifndef DISABLE_CAPSTONE
    // "retl" is a "jmpl" printed as its alias, and it has a delay slot too
    const u8_t bytes[] = {0x01, 0x00, 0x00, 0x00, 0x81, 0xc3, 0xe0, 0x08,
                          0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    return until_return_is("sparc", bytes, sizeof(bytes), 3, "retl");
#else
    return TEST_SKIPPED;
#endif
}

int TEST(aarch64_until_return)(void)
{
#ifndef DISABLE_CAPSTONE
    const u8_t bytes[] = {0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6,
                          0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5};
    return until_return_is("aarch64", bytes, sizeof(bytes), 2, "ret");
#else
    return TEST_SKIPPED;
#endif
}

int TEST(arm32_thumb_until_return)(void)
{
#ifndef DISABLE_CAPSTONE
    // capstone puts a "bx lr" in its return group in arm mode but not in
    // thumb mode, which is why the operand is looked at rather than the group
    const u8_t bytes[] = {0x00, 0xbf, 0x70, 0x47, 0x00, 0xbf, 0x00, 0xbf};
    return until_return_is("arm32-thumb", bytes, sizeof(bytes), 2, "bx");
#else
    return TEST_SKIPPED;
#endif
}

int TEST(arm32_until_return_pops_the_program_counter)(void)
{
#ifndef DISABLE_CAPSTONE
    // "pop {r4, pc}": the epilogue that restores the registers and returns
    const u8_t bytes[] = {0x00, 0xf0, 0x20, 0xe3, 0x10, 0x80, 0xbd, 0xe8,
                          0x00, 0xf0, 0x20, 0xe3, 0x00, 0xf0, 0x20, 0xe3};
    return until_return_is("arm32", bytes, sizeof(bytes), 2, "pop");
#else
    return TEST_SKIPPED;
#endif
}

int TEST(riscv64_until_return)(void)
{
#ifndef DISABLE_CAPSTONE
    // riscv returns with a "jalr" that capstone prints as "ret"
    const u8_t bytes[] = {0x13, 0x00, 0x00, 0x00, 0x67, 0x80, 0x00, 0x00,
                          0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00};
    return until_return_is("riscv64", bytes, sizeof(bytes), 2, "ret");
#else
    return TEST_SKIPPED;
#endif
}

int TEST(s390x_until_return)(void)
{
#ifndef DISABLE_CAPSTONE
    // a branch to %r14, the register holding the return address
    const u8_t bytes[] = {0x07, 0xfe, 0x07, 0x07, 0x07, 0x07};
    return until_return_is("s390x", bytes, sizeof(bytes), 1, "br");
#else
    return TEST_SKIPPED;
#endif
}

int TEST(alpha_until_return)(void)
{
#ifndef DISABLE_CAPSTONE
    const u8_t bytes[] = {0x01, 0x80, 0xfa, 0x6b, 0x00, 0x00,
                          0xfe, 0x2f, 0x00, 0x00, 0xfe, 0x2f};
    return until_return_is("alpha", bytes, sizeof(bytes), 1, "ret");
#else
    return TEST_SKIPPED;
#endif
}

int TEST(ebpf_until_return)(void)
{
#ifndef DISABLE_CAPSTONE
    const u8_t bytes[] = {0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    return until_return_is("ebpf", bytes, sizeof(bytes), 1, "exit");
#else
    return TEST_SKIPPED;
#endif
}

int TEST(until_return_runs_to_the_end_of_the_file)(void)
{
#ifndef DISABLE_CAPSTONE
    // no return anywhere: the listing ends with the file
    const u8_t bytes[] = {0x90, 0x90, 0x90, 0x90};
    return until_return_is("x64", bytes, sizeof(bytes), 4, "nop");
#else
    return TEST_SKIPPED;
#endif
}

int TEST(until_return_stops_at_an_invalid_instruction)(void)
{
#ifndef DISABLE_CAPSTONE
    // ff ff decodes as nothing: the listing says so and stops
    const u8_t bytes[] = {0x90, 0xff, 0xff, 0xff, 0xff};
    char*      out     = disas_until_return("x64", bytes, sizeof(bytes));
    int        r =
        out != NULL && count_rows(out) == 1 && strstr(out, "invalid") != NULL;
    bhex_free(out);
    return r ? TEST_SUCCEEDED : TEST_FAILED;
#else
    return TEST_SKIPPED;
#endif
}

int TEST(arm32_conditional_return_is_not_the_end)(void)
{
#ifndef DISABLE_CAPSTONE
    // "bxeq lr" returns only when the condition holds, so the function goes
    // on: the listing ends with the unconditional "bx lr" below it
    const u8_t bytes[] = {0x1e, 0xff, 0x2f, 0x01, 0x00, 0xf0, 0x20, 0xe3,
                          0x1e, 0xff, 0x2f, 0xe1, 0x00, 0xf0, 0x20, 0xe3};
    return until_return_is("arm32", bytes, sizeof(bytes), 3, "bxeq");
#else
    return TEST_SKIPPED;
#endif
}
