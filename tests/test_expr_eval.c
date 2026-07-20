// Copyright (c) 2022-2026, bageyelet

#include "t_cmd_common.h"
#include "t.h"

#include <expr_eval.h>
#include <util/endian.h>

#ifndef TEST
#define TEST(name) test_##name
#endif

static int eval(const char* expr, u64_t* o_result)
{
    return expr_eval(expr, elf_fb->fb, o_result);
}

// --- Basic arithmetic ---

int TEST(add)(void)
{
    u64_t r;
    ASSERT(eval("10+20", &r) == EXPR_EVAL_OK);
    ASSERT(r == 30);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(add_spaces)(void)
{
    u64_t r;
    ASSERT(eval("10 + 20", &r) == EXPR_EVAL_OK);
    ASSERT(r == 30);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(sub)(void)
{
    u64_t r;
    ASSERT(eval("50 - 10", &r) == EXPR_EVAL_OK);
    ASSERT(r == 40);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(mul)(void)
{
    u64_t r;
    ASSERT(eval("5 * 3", &r) == EXPR_EVAL_OK);
    ASSERT(r == 15);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(shl)(void)
{
    u64_t r;
    ASSERT(eval("1 << 4", &r) == EXPR_EVAL_OK);
    ASSERT(r == 16);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(shr)(void)
{
    u64_t r;
    ASSERT(eval("0x80 >> 4", &r) == EXPR_EVAL_OK);
    ASSERT(r == 8);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(bit_and)(void)
{
    u64_t r;
    ASSERT(eval("0xff & 0x0f", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0x0f);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(bit_or)(void)
{
    u64_t r;
    ASSERT(eval("0xf0 | 0x0f", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0xff);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(bit_not)(void)
{
    u64_t r;
    ASSERT(eval("~0", &r) == EXPR_EVAL_OK);
    ASSERT(r == UINT64_MAX);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(bit_not_mask)(void)
{
    u64_t r;
    ASSERT(eval("~0xff & 0xff", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

// --- Hex numbers ---

int TEST(hex)(void)
{
    u64_t r;
    ASSERT(eval("0x10", &r) == EXPR_EVAL_OK);
    ASSERT(r == 16);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(hex_upper)(void)
{
    u64_t r;
    ASSERT(eval("0XAB", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0xAB);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(decimal)(void)
{
    u64_t r;
    ASSERT(eval("42", &r) == EXPR_EVAL_OK);
    ASSERT(r == 42);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

// --- Parentheses ---

int TEST(parens)(void)
{
    u64_t r;
    ASSERT(eval("(1 + 2) * 3", &r) == EXPR_EVAL_OK);
    ASSERT(r == 9);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(nested_parens)(void)
{
    u64_t r;
    ASSERT(eval("((10 + 20) * 2) >> 2", &r) == EXPR_EVAL_OK);
    ASSERT(r == 15);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

// --- Precedence ---

int TEST(precedence_mul_add)(void)
{
    u64_t r;
    ASSERT(eval("2 + 3 * 4", &r) == EXPR_EVAL_OK);
    ASSERT(r == 14);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(precedence_shift_add)(void)
{
    u64_t r;
    ASSERT(eval("1 << 2 + 1", &r) == EXPR_EVAL_OK);
    ASSERT(r == 8); // 1 << 3 == 8
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(precedence_and_or)(void)
{
    u64_t r;
    ASSERT(eval("0xff & 0x0f | 0xf0", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0xff);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

// --- Memory dereference ---

int TEST(mem_deref_default)(void)
{
    // Read first 4 bytes (LE32) of the ELF. The ELF starts with 0x7f 'E' 'L'
    // 'F'
    u64_t r;
    ASSERT(eval("[0x0]", &r) == EXPR_EVAL_OK);
    u32_t expected = read_at_le32(elf_fb->fb->block, 0);
    ASSERT(r == (u64_t)expected);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(mem_deref_32le)(void)
{
    u64_t r;
    ASSERT(eval("[32le 0x0]", &r) == EXPR_EVAL_OK);
    u32_t expected = read_at_le32(elf_fb->fb->block, 0);
    ASSERT(r == (u64_t)expected);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(mem_deref_32be)(void)
{
    u64_t r;
    ASSERT(eval("[32be 0x0]", &r) == EXPR_EVAL_OK);
    u32_t expected = read_at_be32(elf_fb->fb->block, 0);
    ASSERT(r == (u64_t)expected);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(mem_deref_16)(void)
{
    u64_t r;
    ASSERT(eval("[16 0x0]", &r) == EXPR_EVAL_OK);
    u16_t expected = read_at_le16(elf_fb->fb->block, 0);
    ASSERT(r == (u64_t)expected);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(mem_deref_16be)(void)
{
    u64_t r;
    ASSERT(eval("[16be 0x0]", &r) == EXPR_EVAL_OK);
    u16_t expected = read_at_be16(elf_fb->fb->block, 0);
    ASSERT(r == (u64_t)expected);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(mem_deref_64le)(void)
{
    u64_t r;
    ASSERT(eval("[64 0x0]", &r) == EXPR_EVAL_OK);
    u64_t expected = read_at_le64(elf_fb->fb->block, 0);
    ASSERT(r == expected);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(mem_deref_8)(void)
{
    u64_t r;
    ASSERT(eval("[8 0x0]", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0x7f); // ELF magic first byte
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(mem_deref_with_offset)(void)
{
    // Read from offset 1 (0x45 = 'E')
    u64_t r;
    ASSERT(eval("[8 0x1]", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0x45);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(mem_deref_nested)(void)
{
    // [8 [32le 0x0]] -- read the first 4 bytes (LE) as an address,
    // then read 1 byte at that address. This test is complex,
    // so just check that it parses and runs without error.
    u64_t r;
    int   res = eval("[8 [32le 0x0]]", &r);
    // This should at least parse correctly (might read OOB though)
    ASSERT(res == EXPR_EVAL_OK || res == EXPR_EVAL_ERR_READ_OOB);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(mem_deref_expr_addr)(void)
{
    u64_t r;
    ASSERT(eval("[8 0x0 + 1]", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0x45); // 'E' at offset 1
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(mem_deref_paren_addr)(void)
{
    u64_t r;
    ASSERT(eval("[8 (2 * 2)]", &r) == EXPR_EVAL_OK);
    // offset 4 in the ELF header -- just check that it reads without error
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

// --- Error cases ---

int TEST(err_invalid_bitlen)(void)
{
    // 12 is not a valid bitlen; 12be is parsed as an expression (12) + trailing
    // junk
    u64_t r;
    ASSERT(eval("[12be 0x0]", &r) != EXPR_EVAL_OK);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(err_read_oob)(void)
{
    // Read past the end of the file
    u64_t r;
    u64_t far_off = (u64_t)elf_fb->fb->size + 100;
    char  buf[64];
    snprintf(buf, sizeof(buf), "[8 %llu]", far_off);
    ASSERT(eval(buf, &r) == EXPR_EVAL_ERR_READ_OOB);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(err_read_oob_32)(void)
{
    // Read 32-bit near the end -- only 1 byte available
    u64_t r;
    u64_t off = (u64_t)elf_fb->fb->size;
    char  buf[64];
    snprintf(buf, sizeof(buf), "[32 %llu]", off);
    ASSERT(eval(buf, &r) == EXPR_EVAL_ERR_READ_OOB);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(err_unclosed_bracket)(void)
{
    u64_t r;
    ASSERT(eval("[32be 0x0", &r) == EXPR_EVAL_ERR_UNCLOSED_BRACKET);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(err_unclosed_paren)(void)
{
    u64_t r;
    ASSERT(eval("(1 + 2", &r) == EXPR_EVAL_ERR_SYNTAX);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(err_trailing_garbage)(void)
{
    u64_t r;
    ASSERT(eval("10 + 20 abc", &r) == EXPR_EVAL_ERR_SYNTAX);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(err_empty)(void)
{
    u64_t r;
    ASSERT(eval("", &r) == EXPR_EVAL_ERR_INVALID_NUMBER);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

// --- Complex expressions ---

int TEST(complex1)(void)
{
    u64_t r;
    ASSERT(eval("0x1000 + 42 * 2", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0x1000 + 84);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(complex2)(void)
{
    u64_t r;
    ASSERT(eval("(0xff & 0x0f) | (0xf0 << 4)", &r) == EXPR_EVAL_OK);
    ASSERT(r == (((0xff & 0x0f) | (0xf0 << 4))));
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

// --- Builtin variables ---

int TEST(var_current_default)(void)
{
    /* $o at offset 0 with base 0 should be 0 */
    u64_t r;
    ASSERT(eval("$o", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(var_base_default)(void)
{
    /* $b should be 0 by default */
    u64_t r;
    ASSERT(eval("$b", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(var_current_after_seek)(void)
{
    /* $o should reflect offset after seeking */
    elf_fb->fb->base_addr = 0;
    fb_seek(elf_fb->fb, 0x42);
    u64_t r;
    ASSERT(eval("$o", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0x42);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(var_current_with_base)(void)
{
    /* $o should be offset + base */
    elf_fb->fb->base_addr = 0x1000;
    fb_seek(elf_fb->fb, 0x20);
    u64_t r;
    ASSERT(eval("$o", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0x1020);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(var_base_after_set)(void)
{
    /* $b should reflect base after being set */
    elf_fb->fb->base_addr = 0xABCD;
    fb_seek(elf_fb->fb, 0);
    u64_t r;
    ASSERT(eval("$b", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0xABCD);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(var_current_arithmetic)(void)
{
    /* $o + 10 should work */
    elf_fb->fb->base_addr = 0x1000;
    fb_seek(elf_fb->fb, 0x50);
    u64_t r;
    ASSERT(eval("$o + 0x10", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0x1060);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(var_both_in_expr)(void)
{
    /* $b + $o should work */
    elf_fb->fb->base_addr = 0x100;
    fb_seek(elf_fb->fb, 0x50);
    u64_t r;
    ASSERT(eval("$b + $o", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0x100 + 0x150);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(var_in_mem_deref)(void)
{
    /* [$o] should dereference memory at current offset */
    elf_fb->fb->base_addr = 0;
    fb_seek(elf_fb->fb, 0);
    u64_t r;
    ASSERT(eval("[32 $o]", &r) == EXPR_EVAL_OK);
    u32_t expected = read_at_le32(elf_fb->fb->block, 0);
    ASSERT(r == (u64_t)expected);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(var_invalid)(void)
{
    /* $x is not a valid variable */
    u64_t r;
    ASSERT(eval("$x", &r) != EXPR_EVAL_OK);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(var_invalid_err_code)(void)
{
    /* $unknown should fail with EXPR_EVAL_ERR_UNKNOWN_GLOBAL_VAR */
    u64_t r;
    ASSERT(eval("$unknown", &r) == EXPR_EVAL_ERR_UNKNOWN_GLOBAL_VAR);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(var_off_default)(void)
{
    /* $off at offset 0 should be 0 */
    elf_fb->fb->base_addr = 0;
    fb_seek(elf_fb->fb, 0);
    u64_t r;
    ASSERT(eval("$off", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(var_off_after_seek)(void)
{
    /* $off includes base address */
    elf_fb->fb->base_addr = 0x1000;
    fb_seek(elf_fb->fb, 0x42);
    u64_t r;
    ASSERT(eval("$off", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0x1042);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(var_off_alias_o)(void)
{
    /* $o is an alias for $off */
    elf_fb->fb->base_addr = 0x2000;
    fb_seek(elf_fb->fb, 0x10);
    u64_t r;
    ASSERT(eval("$o", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0x2010);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(var_size_default)(void)
{
    /* $size should return the file size */
    u64_t r;
    ASSERT(eval("$size", &r) == EXPR_EVAL_OK);
    ASSERT(r == elf_fb->fb->size);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(var_size_alias_s)(void)
{
    /* $s is an alias for $size */
    u64_t r;
    ASSERT(eval("$s", &r) == EXPR_EVAL_OK);
    ASSERT(r == elf_fb->fb->size);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(var_off_arithmetic)(void)
{
    /* $off + 10 should work */
    elf_fb->fb->base_addr = 0;
    fb_seek(elf_fb->fb, 0x50);
    u64_t r;
    ASSERT(eval("$off + 0x10", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0x60);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(var_base_alias)(void)
{
    /* $base is the full name for $b */
    elf_fb->fb->base_addr = 0xBEEF;
    fb_seek(elf_fb->fb, 0);
    u64_t r;
    ASSERT(eval("$base", &r) == EXPR_EVAL_OK);
    ASSERT(r == 0xBEEF);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}

int TEST(var_size_in_expr)(void)
{
    /* $size - $off should give remaining bytes (base=0) */
    elf_fb->fb->base_addr = 0;
    fb_seek(elf_fb->fb, 10);
    u64_t r;
    ASSERT(eval("$size - $off", &r) == EXPR_EVAL_OK);
    ASSERT(r == elf_fb->fb->size - 10);
    return TEST_SUCCEEDED;
fail:
    return TEST_FAILED;
}
