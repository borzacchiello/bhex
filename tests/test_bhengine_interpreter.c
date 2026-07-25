// Copyright (c) 2022-2026, bageyelet

#include <string.h>
#include <alloc.h>
#include <log.h>
#include <defs.h>

#include "data/big_buffers.h"
#include "../bhengine/interpreter.h"
#include "../bhengine/scope.h"
#include "dummy_filebuffer.h"
#include "strbuilder.h"
#include "t_cmd_common.h"
#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

#define IS_TENGINE_SNUM_EQ(r, v, n)                                            \
    if ((v) == NULL)                                                           \
        goto end;                                                              \
    if ((v)->t != TENGINE_SNUM)                                                \
        goto end;                                                              \
    if ((v)->snum != (n))                                                      \
        goto end;                                                              \
    (r) = 1;

#define IS_TENGINE_UNUM_EQ(r, v, n)                                            \
    if ((v) == NULL)                                                           \
        goto end;                                                              \
    if ((v)->t != TENGINE_UNUM)                                                \
        goto end;                                                              \
    if ((v)->unum != (n))                                                      \
        goto end;                                                              \
    (r) = 1;

#define ASSERT_TENGINE_UNUM_EQ(v, n)                                           \
    if ((v) == NULL) {                                                         \
        printf("[!] v is null\n");                                             \
        goto fail;                                                             \
    }                                                                          \
    if ((v)->t != TENGINE_UNUM) {                                              \
        printf("[!] v type is not TENGINE_UNUM\n");                            \
        goto fail;                                                             \
    }                                                                          \
    if ((v)->unum != (n)) {                                                    \
        printf("[!] expected %llu, got %llu\n", (v)->unum, (u64_t)(n));        \
        goto fail;                                                             \
    }

#define ASSERT_TENGINE_SNUM_EQ(v, n)                                           \
    if ((v) == NULL) {                                                         \
        printf("[!] v is null\n");                                             \
        goto fail;                                                             \
    }                                                                          \
    if ((v)->t != TENGINE_SNUM) {                                              \
        printf("[!] v type is not TENGINE_SNUM\n");                            \
        goto fail;                                                             \
    }                                                                          \
    if ((v)->snum != (n)) {                                                    \
        printf("[!] expected %lld, got %lld\n", (v)->snum, (s64_t)(n));        \
        goto fail;                                                             \
    }

#define IS_TENGINE_BOOL_EQ(r, v, n)                                            \
    if ((v) == NULL)                                                           \
        goto end;                                                              \
    if ((v)->t != TENGINE_UNUM)                                                \
        goto end;                                                              \
    if ((v)->unum_size != 1)                                                   \
        goto end;                                                              \
    if ((v)->unum != (n))                                                      \
        goto end;                                                              \
    (r) = 1;

#define IS_TENGINE_STRING_EQ(r, v, n)                                          \
    if ((v) == NULL)                                                           \
        goto end;                                                              \
    if ((v)->t != TENGINE_STRING)                                              \
        goto end;                                                              \
    if (strcmp((char*)(v)->str, (n)) != 0)                                     \
        goto end;                                                              \
    (r) = 1;

int TEST(const)(void)
{
    const char* prog = "proc { local a = 0; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(const_s8)(void)
{
    const char* prog = "proc { local a = 42s8; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    Scope_free(scope);
    return r;
}

int TEST(const_s16)(void)
{
    const char* prog = "proc { local a = 42s16; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    Scope_free(scope);
    return r;
}

int TEST(const_s32)(void)
{
    const char* prog = "proc { local a = 42s32; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    Scope_free(scope);
    return r;
}

int TEST(const_u8)(void)
{
    const char* prog = "proc { local a = 16u8; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 16);

end:
    Scope_free(scope);
    return r;
}

int TEST(const_u16)(void)
{
    const char* prog = "proc { local a = 300u16; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 300);

end:
    Scope_free(scope);
    return r;
}

int TEST(const_u32)(void)
{
    const char* prog = "proc { local a = 100000u32; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 100000);

end:
    Scope_free(scope);
    return r;
}

int TEST(const_u64)(void)
{
    const char* prog = "proc { local a = 1099511627537u64; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 1099511627537ull);

end:
    Scope_free(scope);
    return r;
}

int TEST(hex_const)(void)
{
    const char* prog = "proc { local a = 0xdeadbeef; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 0xdeadbeef);

end:
    Scope_free(scope);
    return r;
}

int TEST(hex_const_u8)(void)
{
    const char* prog = "proc { local a = 0xffu8; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 255);

end:
    Scope_free(scope);
    return r;
}

int TEST(hex_const_u16)(void)
{
    const char* prog = "proc { local a = 0xfffu16; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 0xfff);

end:
    Scope_free(scope);
    return r;
}

int TEST(hex_const_u32)(void)
{
    const char* prog = "proc { local a = 0xffffffu32; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 0xffffff);

end:
    Scope_free(scope);
    return r;
}

int TEST(hex_const_u64)(void)
{
    const char* prog = "proc { local a = 0xffffffffffu64; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 0xffffffffffull);

end:
    Scope_free(scope);
    return r;
}

int TEST(cast_u8)(void)
{
    const char* prog = "proc { "
                       "  local a = 0xffff;"
                       "  local b = u8(a);"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0xff);

end:
    Scope_free(scope);
    return r;
}

int TEST(cast_i8)(void)
{
    const char* prog = "proc { "
                       "  local a = 0xffff;"
                       "  local b = i8(a);"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -1);

end:
    Scope_free(scope);
    return r;
}

int TEST(const_limit_1)(void)
{
    const char* prog = "proc { local a = 0x7fffffffffffffff; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 0x7fffffffffffffffl);

end:
    Scope_free(scope);
    return r;
}

int TEST(const_limit_2)(void)
{
    const char* prog = "proc { local a = -0x7fffffffffffffff-1; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, (int64_t)-0x8000000000000000l);

end:
    Scope_free(scope);
    return r;
}

int TEST(neg_const)(void)
{
    const char* prog = "proc { local a = -42; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, -42);

end:
    Scope_free(scope);
    return r;
}

int TEST(str_const_1)(void)
{
    const char* prog = "proc { local a = \"ciao\"; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_STRING_EQ(r, v, "ciao");

end:
    Scope_free(scope);
    return r;
}

int TEST(str_const_2)(void)
{
    const char* prog = "proc { local a = \"ciao\xde\xad\xbe\xef\"; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_STRING_EQ(r, v, "ciao\xde\xad\xbe\xef");

end:
    Scope_free(scope);
    return r;
}

int TEST(eq_str)(void)
{
    const char* prog =
        "proc { local a = \"ciao\"; local b = \"ciao\"; local c = a == b; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "c");
    IS_TENGINE_UNUM_EQ(r, v, 1);

end:
    Scope_free(scope);
    return r;
}

int TEST(sub)(void)
{
    const char* prog = "proc { local a = 4; local b = a - 5; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -1);

end:
    Scope_free(scope);
    return r;
}

int TEST(sub_no_space)(void)
{
    const char* prog = "proc { local a = 4; local b = a-5; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -1);

end:
    print_err_sb();
    Scope_free(scope);
    return r;
}

int TEST(add)(void)
{
    const char* prog = "proc { local a = 4; local b = a + 10; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 14);

end:
    Scope_free(scope);
    return r;
}

int TEST(add_no_space)(void)
{
    const char* prog = "proc { local a = 4; local b = a+10; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 14);

end:
    Scope_free(scope);
    return r;
}

int TEST(add_wrap_s8)(void)
{
    const char* prog = "proc { local a = 127s8; local b = a + 1s8; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -0x80);

end:
    Scope_free(scope);
    return r;
}

int TEST(add_wrap_s16)(void)
{
    const char* prog = "proc { local a = 0x7fffs16; local b = a + 1s16; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -0x8000);

end:
    Scope_free(scope);
    return r;
}

int TEST(add_wrap_s32)(void)
{
    const char* prog = "proc { local a = 0x7fffffffs32; local b = a + 1s32; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -0x80000000ll);

end:
    Scope_free(scope);
    return r;
}

int TEST(add_wrap_u8)(void)
{
    const char* prog = "proc { local a = 250u8; local b = a + 6u8; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(add_wrap_u16)(void)
{
    const char* prog = "proc { local a = 0xffffu16; local b = a + 1u16; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(add_wrap_u32)(void)
{
    const char* prog = "proc { local a = 0xffffffffu32; local b = a + 1u32; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(add_wrap_u64)(void)
{
    const char* prog =
        "proc { local a = 0xffffffffffffffffu64; local b = a + 1u64; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(mul)(void)
{
    const char* prog = "proc { local a = 4; local b = a * 10; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 40);

end:
    Scope_free(scope);
    return r;
}

int TEST(div_1)(void)
{
    const char* prog = "proc { local a = 44; local b = a / 10; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 4);

end:
    Scope_free(scope);
    return r;
}

int TEST(div_2)(void)
{
    const char* prog = "proc { local a = 16; local b = a / 4; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 4);

end:
    Scope_free(scope);
    return r;
}

int TEST(div_3)(void)
{
    // clang-format off
    const char* expected =
        "[  ERROR  ] 001: proc {   local a = 1 / 0;}\n"
        "[  ERROR  ]      ________________________^\n"
        "[  ERROR  ] Exception @ line 1, col 25 > div by zero\n";
    // clang-format on

    const char* prog = "proc { "
                       "  local a = 1 / 0;"
                       "}";

    int    r     = 1;
    char*  out   = NULL;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);

    out = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (out)
        bhex_free(out);
    return r;

fail:
    r = 0;
    goto end;
}

int TEST(mod_1)(void)
{
    const char* prog = "proc { local a = 43; local b = a % 10; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 3);

end:
    Scope_free(scope);
    return r;
}

int TEST(mod_2)(void)
{
    const char* prog = "proc { local a = 16; local b = a % 4; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(mod_3)(void)
{
    // clang-format off
    const char* expected =
        "[  ERROR  ] 001: proc {   local a = 1 % 0;}\n"
        "[  ERROR  ]      ________________________^\n"
        "[  ERROR  ] Exception @ line 1, col 25 > div by zero\n";
    // clang-format on

    const char* prog = "proc { "
                       "  local a = 1 % 0;"
                       "}";

    int    r     = 1;
    char*  out   = NULL;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);

    out = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (out)
        bhex_free(out);
    return r;

fail:
    r = 0;
    goto end;
}

int TEST (and)(void)
{
    const char* prog = "proc { local a = 0xffff; local b = a & 0xf0f0; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0xf0f0);

end:
    Scope_free(scope);
    return r;
}

int TEST(or)(void)
{
    const char* prog = "proc { local a = 0xf0f0; local b = a | 0x0f0f; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0xffff);

end:
    Scope_free(scope);
    return r;
}

int TEST (xor)(void)
{
    const char* prog = "proc { local a = 0xff; local b = a ^ 0xf0; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0x0f);

end:
    Scope_free(scope);
    return r;
}

int TEST(shr_1)(void)
{
    const char* prog = "proc { local a = 0xff; local b = a >> 1; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0xff >> 1);

end:
    Scope_free(scope);
    return r;
}

int TEST(shr_2)(void)
{
    const char* prog = "proc { local a = 0xff; local b = a >> 2; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0xff >> 2);

end:
    Scope_free(scope);
    return r;
}

int TEST(shr_3)(void)
{
    const char* prog = "proc { local a = 0xff; local b = a >> 10; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(shl_1)(void)
{
    const char* prog = "proc { local a = 1; local b = a << 1; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 1 << 1);

end:
    Scope_free(scope);
    return r;
}

int TEST(shl_2)(void)
{
    const char* prog = "proc { local a = 1; local b = a << 2; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 1 << 2);

end:
    Scope_free(scope);
    return r;
}

int TEST(shl_3)(void)
{
    const char* prog = "proc { local a = 1u8; local b = a << 10u8; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(neg_1)(void)
{
    const char* prog = "proc { local a = -(42+16); }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, -58);

end:
    Scope_free(scope);
    return r;
}

int TEST(neg_2)(void)
{
    const char* prog = "proc { local a = 43 + -(42+16); }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, -58 + 43);

end:
    Scope_free(scope);
    return r;
}

int TEST(band_1)(void)
{
    const char* prog = "proc {"
                       "  local a = 1;"
                       "  local b = 0;"
                       "  local c = a && b;"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "c");
    IS_TENGINE_BOOL_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(band_2)(void)
{
    const char* prog = "proc {"
                       "  local a = 1;"
                       "  local b = 1;"
                       "  local c = a && b;"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "c");
    IS_TENGINE_BOOL_EQ(r, v, 1);

end:
    Scope_free(scope);
    return r;
}

int TEST(bor_1)(void)
{
    const char* prog = "proc {"
                       "  local a = 1;"
                       "  local b = 0;"
                       "  local c = a || b;"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "c");
    IS_TENGINE_BOOL_EQ(r, v, 1);

end:
    Scope_free(scope);
    return r;
}

int TEST(bor_2)(void)
{
    const char* prog = "proc {"
                       "  local a = 0;"
                       "  local b = 0;"
                       "  local c = a || b;"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "c");
    IS_TENGINE_BOOL_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(bneq_1)(void)
{
    const char* prog = "proc {"
                       "  local a = 0;"
                       "  local b = 1;"
                       "  if (a != 42) {"
                       "    b = b + 41;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    Scope_free(scope);
    return r;
}

int TEST(bnot_1)(void)
{
    const char* prog = "proc {"
                       "  local a = 0;"
                       "  local b = 1;"
                       "  if (!(a == 42)) {"
                       "    b = b + 41;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    Scope_free(scope);
    return r;
}

int TEST(implicit_conversion_enum_value_unum_1)(void)
{
    DummyFilebuffer* tfb = dummyfilebuffer_create((const u8_t*)"\x07\x01", 2);

    const char* prog = "orenum MyEnum : u8 { A = 1, B = 2, C = 4 }"
                       "proc {"
                       "  MyEnum a;"
                       "  MyEnum b;"
                       "  local res = 0;"
                       "  if (a & MyEnum::C) {"
                       "    res = res + 1;"
                       "  }"
                       "  if (a & MyEnum::B) {"
                       "    res = res + 2;"
                       "  }"
                       "  if (a & MyEnum::A) {"
                       "    res = res + 4;"
                       "  }"
                       "  if (b & MyEnum::C) {"
                       "    res = res + 10;"
                       "  }"
                       "  if (b & MyEnum::B) {"
                       "    res = res + 20;"
                       "  }"
                       "  if (b & MyEnum::A) {"
                       "    res = res + 40;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "res");
    IS_TENGINE_SNUM_EQ(r, v, 47);

end:
    dummyfilebuffer_destroy(tfb);
    Scope_free(scope);
    return r;
}

int TEST(precedence_op_1)(void)
{
    const char* prog = "proc { local a = 4 + 3 * 8; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 28);

end:
    Scope_free(scope);
    return r;
}

int TEST(precedence_op_2)(void)
{
    const char* prog = "proc { local a = 4 - 3 * 8; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, -20);

end:
    Scope_free(scope);
    return r;
}

int TEST(precedence_op_3)(void)
{
    const char* prog = "proc { local a = 4 - 3 + 3 * 2; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 7);

end:
    Scope_free(scope);
    return r;
}

int TEST(precedence_op_4)(void)
{
    const char* prog = "proc { local a = 4 * 3 - 1; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 11);

end:
    Scope_free(scope);
    return r;
}

int TEST(precedence_op_5)(void)
{
    const char* prog = "proc { local a = (4 + 3) * 8; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 56);

end:
    Scope_free(scope);
    return r;
}

int TEST(if_1)(void)
{
    const char* prog = "proc {"
                       "  local a = 4;"
                       "  local b = 3;"
                       "  if (a - 3 > 0) {"
                       "    b = b + 42;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 45);

end:
    Scope_free(scope);
    return r;
}

int TEST(if_2)(void)
{
    const char* prog = "proc {"
                       "  local a = 4;"
                       "  local b = 3;"
                       "  if (a - 5 > 0) {"
                       "    b = b + 42;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 3);

end:
    Scope_free(scope);
    return r;
}

int TEST(if_3)(void)
{
    const char* prog = "proc {"
                       "  local a = 4;"
                       "  local b = 3;"
                       "  if (a == 1) {"
                       "    b = b + 42;"
                       "  } elif (a == 4) {"
                       "    b = b + 43;"
                       "  } else {"
                       "    b = b + 44;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 46);

end:
    Scope_free(scope);
    return r;
}

int TEST(if_4)(void)
{
    const char* prog = "proc { "
                       "  local a = 8;"
                       "  local b = 3;"
                       "  if (a == 1) {"
                       "    b = b + 42;"
                       "  } elif (a == 4) {"
                       "    b = b + 43;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 3);

end:
    Scope_free(scope);
    return r;
}

int TEST(if_5)(void)
{
    const char* prog = "proc { "
                       "  local a = 8;"
                       "  local b = 3;"
                       "  if (a == 1) {"
                       "    b = b + 42;"
                       "  } elif (a == 4) {"
                       "    b = b + 43;"
                       "  } else {"
                       "    b = b + 44;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 47);

end:
    Scope_free(scope);
    return r;
}

int TEST(if_6)(void)
{
    const char* prog = "proc { "
                       "  local a = 8;"
                       "  local b = 3;"
                       "  if (a == 1) {"
                       "  } elif (a == 4) {"
                       "    b = b + 43;"
                       "  } else {"
                       "    b = b + 44;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 47);

end:
    Scope_free(scope);
    return r;
}

int TEST(if_7)(void)
{
    const char* prog = "proc { "
                       "  local a = 8;"
                       "  local b = 3;"
                       "  if (a == 1) {"
                       "    b = b + 42;"
                       "  } elif (a == 4) {"
                       "  } else {"
                       "    b = b + 44;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 47);

end:
    Scope_free(scope);
    return r;
}

int TEST(if_8)(void)
{
    const char* prog = "proc { "
                       "  local a = 4;"
                       "  local b = 3;"
                       "  if (a == 1) {"
                       "    b = b + 42;"
                       "  } elif (a == 4) {"
                       "    b = b + 43;"
                       "  } else {"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 46);

end:
    Scope_free(scope);
    return r;
}

int TEST(if_9)(void)
{
    const char* prog = "proc { "
                       "  local a = 8;"
                       "  local b = 3;"
                       "  if (a == 1) {"
                       "    b = b + 42;"
                       "  } elif (a == 4) {"
                       "    b = b + 43;"
                       "  } else {"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 3);

end:
    Scope_free(scope);
    return r;
}

int TEST(while_1)(void)
{
    const char* prog = "proc { "
                       "  local a = 0;"
                       "  local b = 0;"
                       "  while (a < 10) {"
                       "    b = b + (2*a);"
                       "    a = a + 1;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 90);

end:
    Scope_free(scope);
    return r;
}

int TEST(while_2)(void)
{
    const char* prog = "proc { "
                       "  local a = 0;"
                       "  local b = 0;"
                       "  while (a < 3) {"
                       "    local c = 0;"
                       "    while (c < 3) {"
                       "      b = b + (a<<1) + (c<<2);"
                       "      c = c + 1;"
                       "    }"
                       "    a = a + 1;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 54);

end:
    Scope_free(scope);
    return r;
}

int TEST(while_3)(void)
{
    const char* prog = "proc { "
                       "  local a = 0;"
                       "  local b = 0;"
                       "  while (a < 3) {"
                       "    local c = 0;"
                       "    while (c < 3) {"
                       "      b = b + (a<<1) + (c<<2);"
                       "      c = c + 1;"
                       "      break;"
                       "    }"
                       "    a = a + 1;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r  = 0;
    BHEngineValue* vb = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, vb, 6);
    BHEngineValue* va = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, va, 3);

end:
    Scope_free(scope);
    return r;
}

int TEST(while_4)(void)
{
    const char* prog = "proc { "
                       "  local a = 0;"
                       "  local b = 0;"
                       "  while (a < 3) {"
                       "    local c = 0;"
                       "    break;"
                       "    while (c < 3) {"
                       "      b = b + (a<<1) + (c<<2);"
                       "      c = c + 1;"
                       "    }"
                       "    a = a + 1;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(continue_1)(void)
{
    // basic continue: skip the rest of loop body
    const char* prog = "proc { "
                       "  local a = 0;"
                       "  local b = 0;"
                       "  while (a < 5) {"
                       "    a = a + 1;"
                       "    continue;"
                       "    b = b + 1;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r  = 0;
    BHEngineValue* va = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, va, 5);
    r                 = 0;
    BHEngineValue* vb = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, vb, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(continue_2)(void)
{
    // continue skips even iterations, only odd values of a contribute to b
    const char* prog = "proc { "
                       "  local a = 0;"
                       "  local b = 0;"
                       "  while (a < 6) {"
                       "    a = a + 1;"
                       "    if (a % 2 == 0) {"
                       "      continue;"
                       "    }"
                       "    b = b + a;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r  = 0;
    BHEngineValue* va = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, va, 6);
    r                 = 0;
    BHEngineValue* vb = Scope_get_local(scope, "b");
    // odd values: 1 + 3 + 5 = 9
    IS_TENGINE_SNUM_EQ(r, vb, 9);

end:
    Scope_free(scope);
    return r;
}

int TEST(continue_3)(void)
{
    // continue in nested while: only affects inner loop
    const char* prog = "proc { "
                       "  local a = 0;"
                       "  local b = 0;"
                       "  while (a < 3) {"
                       "    local c = 0;"
                       "    while (c < 3) {"
                       "      c = c + 1;"
                       "      continue;"
                       "      b = b + 100;"
                       "    }"
                       "    b = b + 1;"
                       "    a = a + 1;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r  = 0;
    BHEngineValue* va = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, va, 3);
    r                 = 0;
    BHEngineValue* vb = Scope_get_local(scope, "b");
    // b incremented 3 times (once per outer iteration), inner b+100 skipped
    IS_TENGINE_SNUM_EQ(r, vb, 3);

end:
    Scope_free(scope);
    return r;
}

int TEST(continue_4)(void)
{
    // continue and break together
    const char* prog = "proc { "
                       "  local a = 0;"
                       "  local b = 0;"
                       "  while (a < 10) {"
                       "    a = a + 1;"
                       "    if (a == 5) {"
                       "      break;"
                       "    }"
                       "    if (a % 2 == 0) {"
                       "      continue;"
                       "    }"
                       "    b = b + a;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r  = 0;
    BHEngineValue* va = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, va, 5);
    r                 = 0;
    BHEngineValue* vb = Scope_get_local(scope, "b");
    // odd values before break: 1 + 3 = 4
    IS_TENGINE_SNUM_EQ(r, vb, 4);

end:
    Scope_free(scope);
    return r;
}

int TEST(invalid_continue_1)(void)
{
    // clang-format off
    const char* expected =
    "[  ERROR  ] 001: proc {   continue;}\n"
    "[  ERROR  ]      _________^\n"
    "[  ERROR  ] Exception @ line 1, col 10 > unexpected continue\n";
    // clang-format on

    const char* prog = "proc { "
                       "  continue;"
                       "}";

    int    r     = 1;
    char*  out   = NULL;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);

    out = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope != NULL)
        Scope_free(scope);
    if (out)
        bhex_free(out);
    return r;

fail:
    r = 0;
    goto end;
}

int TEST(invalid_continue_2)(void)
{
    // clang-format off
    const char* expected =
    "[  ERROR  ] 001: fn func() { continue; }proc {   local i = 0;  while (i < 10) {    func();    i = i + 1;  }}\n"
    "[  ERROR  ]      ____________^\n"
    "[  ERROR  ] Exception @ line 1, col 13 > unexpected continue\n";
    // clang-format on

    const char* prog = "fn func() { continue; }"
                       "proc { "
                       "  local i = 0;"
                       "  while (i < 10) {"
                       "    func();"
                       "    i = i + 1;"
                       "  }"
                       "}";

    int    r     = 1;
    char*  out   = NULL;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);

    out = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope != NULL)
        Scope_free(scope);
    if (out)
        bhex_free(out);
    return r;

fail:
    r = 0;
    goto end;
}

int TEST(while_with_error_1)(void)
{
    // clang-format off
    const char* expected =
    "[  ERROR  ] 001: struct A { u8 v; break; }proc {   local i = 0;  while (i < 10) {    error(\"an error\");  }}\n"
    "[  ERROR  ]      ____________________________________________________________________________________^\n"
    "[  ERROR  ] Exception @ line 1, col 85 > an error\n";
    // clang-format on

    const char* prog = "struct A { u8 v; break; }"
                       "proc { "
                       "  local i = 0;"
                       "  while (i < 10) {"
                       "    error(\"an error\");"
                       "  }"
                       "}";

    int    r     = 1;
    char*  out   = NULL;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);

    out = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope != NULL)
        Scope_free(scope);
    if (out)
        bhex_free(out);
    return r;

fail:
    r = 0;
    goto end;
}

int TEST(invalid_break_1)(void)
{
    // clang-format off
    const char* expected =
    "[  ERROR  ] 001: proc {   break;}\n"
    "[  ERROR  ]      _________^\n"
    "[  ERROR  ] Exception @ line 1, col 10 > unexpected break\n";
    // clang-format on

    const char* prog = "proc { "
                       "  break;"
                       "}";

    int    r     = 1;
    char*  out   = NULL;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);

    out = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope != NULL)
        Scope_free(scope);
    if (out)
        bhex_free(out);
    return r;

fail:
    r = 0;
    goto end;
}

int TEST(invalid_break_2)(void)
{
    // clang-format off
    const char* expected =
    "[  ERROR  ] 001: fn func() { break; }proc {   local i = 0;  while (i < 10) {    func();    i = i + 1;  }}\n"
    "[  ERROR  ]      ____________^\n"
    "[  ERROR  ] Exception @ line 1, col 13 > unexpected break\n";
    // clang-format on

    const char* prog = "fn func() { break; }"
                       "proc { "
                       "  local i = 0;"
                       "  while (i < 10) {"
                       "    func();"
                       "    i = i + 1;"
                       "  }"
                       "}";

    int    r     = 1;
    char*  out   = NULL;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);

    out = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope != NULL)
        Scope_free(scope);
    if (out)
        bhex_free(out);
    return r;

fail:
    r = 0;
    goto end;
}

int TEST(invalid_break_3)(void)
{
    // clang-format off
    const char* expected =
    "[  ERROR  ] 001: struct A { u8 v; break; }proc {   local i = 0;  while (i < 10) {    A a;    i = i + 1;  }}\n"
    "[  ERROR  ]      _________________^\n"
    "[  ERROR  ] Exception @ line 1, col 18 > unexpected break, error while processing A\n";
    // clang-format on

    const char* prog = "struct A { u8 v; break; }"
                       "proc { "
                       "  local i = 0;"
                       "  while (i < 10) {"
                       "    A a;"
                       "    i = i + 1;"
                       "  }"
                       "}";

    int    r     = 1;
    char*  out   = NULL;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);

    out = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope != NULL)
        Scope_free(scope);
    if (out)
        bhex_free(out);
    return r;

fail:
    r = 0;
    goto end;
}

int TEST(invalid_break_4)(void)
{
    // clang-format off
    const char* expected =
    "[  ERROR  ] 001: fn func() { break; }proc {   local i = 0;  local a = 0;  while (i < 10) {    a = a + func();    i = i + 1;  }}\n"
    "[  ERROR  ]      ____________^\n"
    "[  ERROR  ] Exception @ line 1, col 13 > unexpected break\n";
    // clang-format on

    const char* prog = "fn func() { break; }"
                       "proc { "
                       "  local i = 0;"
                       "  local a = 0;"
                       "  while (i < 10) {"
                       "    a = a + func();"
                       "    i = i + 1;"
                       "  }"
                       "}";

    int    r     = 1;
    char*  out   = NULL;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);

    out = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope != NULL)
        Scope_free(scope);
    if (out)
        bhex_free(out);
    return r;

fail:
    r = 0;
    goto end;
}

int TEST(return_1)(void)
{
    const char* prog = "fn f(a) {"
                       "   result = 0;"
                       "   if (a == 0) { return; }"
                       "   result = a + 10;"
                       "}"
                       "proc { "
                       "  local a = 0;"
                       "  a = a + f(0);"
                       "  a = a + f(1);"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 11);

end:
    Scope_free(scope);
    return r;
}

int TEST(return_2)(void)
{
    const char* prog = "fn bar(a) {"
                       "   result = 0;"
                       "   if (a == 0) { return; }"
                       "   result = a + 10;"
                       "}"
                       "fn foo(a) {"
                       "   result = a + bar(a);"
                       "   result = result + 8;"
                       "}"
                       "proc { "
                       "  local a = 0;"
                       "  a = a + foo(0);"
                       "  a = a + foo(1);"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 28);

end:
    Scope_free(scope);
    return r;
}

int TEST(return_while_1)(void)
{
    // A return inside a while body must unwind the whole function
    // immediately, not just the current loop iteration.
    int              r    = 0;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"\x00\xAA", 2);
    const char*      prog = "fn parse_until_end(end_off) {"
                            "   while (off() < end_off) {"
                            "      u8 marker;"
                            "      if (marker == 0) {"
                            "         result = off();"
                            "         return;"
                            "      }"
                            "   }"
                            "}"
                            "proc {"
                            "   disable_print();"
                            "   local end = parse_until_end(size());"
                            "   local curr = off();"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* end = Scope_get_local(scope, "end");
    IS_TENGINE_UNUM_EQ(r, end, 1);
    BHEngineValue* curr = Scope_get_local(scope, "curr");
    IS_TENGINE_UNUM_EQ(r, curr, 1);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(invalid_return_1)(void)
{
    // clang-format off
    const char* expected =
    "[  ERROR  ] 001: proc {   return;}\n"
    "[  ERROR  ]      _________^\n"
    "[  ERROR  ] Exception @ line 1, col 10 > unexpected return\n";
    // clang-format on

    const char* prog = "proc { "
                       "  return;"
                       "}";

    int    r     = 1;
    char*  out   = NULL;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);

    out = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope != NULL)
        Scope_free(scope);
    if (out)
        bhex_free(out);
    return r;

fail:
    r = 0;
    goto end;
}

int TEST(invalid_return_2)(void)
{
    // clang-format off
    const char* expected =
    "[  ERROR  ] 001: struct A { return; }fn foo() { A a; }proc {   foo();}\n"
    "[  ERROR  ]      ___________^\n"
    "[  ERROR  ] Exception @ line 1, col 12 > unexpected return, error while processing A\n";
    // clang-format on

    const char* prog = "struct A { return; }"
                       "fn foo() { A a; }"
                       "proc { "
                       "  foo();"
                       "}";

    int    r     = 1;
    char*  out   = NULL;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);

    out = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope != NULL)
        Scope_free(scope);
    if (out)
        bhex_free(out);
    return r;

fail:
    r = 0;
    goto end;
}

int TEST(array_1)(void)
{
    int              r = 0;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)"AAAAAAAAAB", 10);
    const char* prog = "proc {"
                       "    disable_print();"
                       "    u8 buf[10];"
                       "    local a = buf[9];"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 'B');

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(array_2)(void)
{
    int              r = 0;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)"AAAAAAAAABC", 11);
    const char* prog = "proc {"
                       "    disable_print();"
                       "    u16 buf[5];"
                       "    u8  b;"
                       "    local a = buf[4];"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* va = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, va, ((u32_t)'B' << 8) | 'A');

    BHEngineValue* vb = Scope_get_local(scope, "b");
    IS_TENGINE_UNUM_EQ(r, vb, 'C');

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(array_3)(void)
{
    int              r = 0;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)"AAAAAAAAAB", 10);
    const char* prog = "proc {"
                       "    disable_print();"
                       "    big_endian();"
                       "    u16 buf[5];"
                       "    local a = buf[4];"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, ((u32_t)'A' << 8) | 'B');

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(array_4)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000  data: [ \n"
        "                [0]\n"
        "b+00000000      n1: 41\n"
        "b+00000001      n2: 42\n"
        "b+00000002      n3: 43\n"
        "                [1]\n"
        "b+00000003      n1: 44\n"
        "b+00000004      n2: 45\n"
        "b+00000005      n3: 46 ]";
    // clang-format on

    reset_global_state();
    int              r    = 0;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"ABCDEF", 6);
    const char*      prog = "struct Triple {"
                            "   u8 n1;"
                            "   u8 n2;"
                            "   u8 n3;"
                            "}\n"
                            "proc {"
                            "    Triple data[2];"
                            "    local  a = data[1].n2;"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 'E');

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(array_5)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000   v: \n"
        "b+00000000      n1: 41\n"
        "b+00000001      n2: 42\n"
        "b+00000002      n3: [ 4443, 4645, 4847, 4a49 ]\n"
        "b+0000000a      n4: 4b";
    // clang-format on

    reset_global_state();
    int              r = 0;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)"ABCDEFGHIJK", 11);
    const char* prog = "struct AStruct {"
                       "   u8  n1;"
                       "   u8  n2;"
                       "   u16 n3[4];"
                       "   u8  n4;"
                       "}\n"
                       "proc {"
                       "    AStruct v;"
                       "    local   a = v.n4;"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 'K');

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(array_noprint)(void)
{
    // clang-format off
    const char* expected = "";
    // clang-format on

    reset_global_state();
    int              r    = 0;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"ABCDEF", 6);
    const char*      prog = "struct Triple {"
                            "   u8 n1;"
                            "   u8 n2;"
                            "   u8 n3;"
                            "}\n"
                            "proc {"
                            "    disable_print();"
                            "    Triple data[2];"
                            "    local  a = data[1].n2;"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 'E');

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(array_too_big)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000  buf: [ 4141, 4141, 4141, 4141, 4141, 4141, 4141, 4141, 4141, 4141, 4141, 4141, 4141, 4141, 4141, 4141, ... ]";
    // clang-format on

    reset_global_state();
    int              r = 0;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                               64);
    const char* prog = "proc {"
                       "    u16 buf[32];"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(elf_1)(void)
{
    int              r = 0;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(elf_not_kitty, sizeof(elf_not_kitty));
    const char* prog = "struct ElfIdent {"
                       "    u8 ei_mag[4];"
                       "    u8 ei_class;"
                       "    u8 ei_data;"
                       "    u8 ei_version;"
                       "    u8 ei_osabi;"
                       "    u8 ei_abiversion;"
                       "    u8 ei_pad[6];"
                       "    u8 ei_nident;"
                       "}\n"
                       "struct Elf_Ehdr {"
                       "    ElfIdent e_ident;"
                       "    u16 e_type;"
                       "    u16 e_machine;"
                       "    u32 e_version;"
                       "    if (e_ident.ei_class == 2) {"
                       "        u64 e_entry;"
                       "        u64 e_phoff;"
                       "        u64 e_shoff;"
                       "    } else {"
                       "        u32 e_entry;"
                       "        u32 e_phoff;"
                       "        u32 e_shoff;"
                       "    }"
                       "    u32 e_flags;"
                       "    u16 e_ehsize;"
                       "    u16 e_phentsize;"
                       "    u16 e_phnum;"
                       "    u16 e_shentsize;"
                       "    u16 e_shnum;"
                       "    u16 e_shstrndx;"
                       "}\n"
                       "proc {"
                       "    disable_print();"
                       "    Elf_Ehdr header;"
                       "    local    a = header.e_entry;"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 0x08048074);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(strip)(void)
{
    int              r    = 0;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"ABCDEF", 6);
    const char*      prog = "proc {"
                            "    disable_print();"
                            "    local a = printable(\"  ciao  \t\n\");"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_STRING_EQ(r, v, "ciao");

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(strip_nonascii)(void)
{
    int              r    = 0;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"ABCDEF", 6);
    const char*      prog = "proc {"
                            "    disable_print();"
                            "    local a = printable(\"  cia\x01o  \t\n\");"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_STRING_EQ(r, v, "ciao");

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(fn_1)(void)
{

    const char* prog = "fn test() {"
                       "    result = 42;"
                       "}"
                       "proc {"
                       "    disable_print();"
                       "    local a = test();"
                       "}";

    int    r     = 0;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    if (scope)
        Scope_free(scope);
    return r;
}

int TEST(fn_2)(void)
{

    const char* prog = "fn test(a) {"
                       "    result = u32(42 + a);"
                       "}"
                       "proc {"
                       "    disable_print();"
                       "    local a = test(42);"
                       "}";

    int    r     = 0;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 84);

end:
    if (scope)
        Scope_free(scope);
    return r;
}

int TEST(fn_3)(void)
{

    const char* prog = "fn test(a, b) {"
                       "    result = u32(42 + a + b);"
                       "}"
                       "proc {"
                       "    disable_print();"
                       "    local a = test(42, 42);"
                       "}";

    int    r     = 0;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 42 * 3);

end:
    if (scope)
        Scope_free(scope);
    return r;
}

int TEST(comment_line_1)(void)
{
    const char* prog = "fn test(a, b) {"
                       "    // this is a comment and should be skipped\n"
                       "    result = u32(42 + a + b);"
                       "}"
                       "proc {"
                       "    disable_print();"
                       "    local a = test(42, 42);"
                       "}";

    int    r     = 0;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 42 * 3);

end:
    if (scope)
        Scope_free(scope);
    return r;
}

int TEST(comment_multiline_1)(void)
{
    const char* prog = "fn test(a, b) {"
                       "    /* this is a comment and should be skipped */"
                       "    result = u32(42 + a + b);"
                       "}"
                       "proc {"
                       "    disable_print();"
                       "    local a = test(42, 42);"
                       "}";

    int    r     = 0;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 42 * 3);

end:
    if (scope)
        Scope_free(scope);
    return r;
}

int TEST(comment_multiline_2)(void)
{
    const char* prog =
        "fn test(a, b) {"
        "    result = u32(42 + a + b /* this is a comment and should "
        "be skipped */);"
        "}"
        "proc {"
        "    disable_print();"
        "    local a = /* this is a comment and should be skipped */ "
        "test(42, 42);"
        "}";

    int    r     = 0;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 42 * 3);

end:
    if (scope)
        Scope_free(scope);
    return r;
}

int TEST(enum_const)(void)
{
    const char* prog = "enum MyEnum : u8"
                       "{"
                       "    A = 42,"
                       "    B = 44"
                       "}"
                       "proc {"
                       "    disable_print();"
                       "    local a = MyEnum::A + MyEnum::B + 16u8;"
                       "}";

    int    r     = 0;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 42 + 44 + 16);

end:
    if (scope)
        Scope_free(scope);
    return r;
}

int TEST(syntax_error)(void)
{
    // clang-format off
    const char* expected =
        "[  ERROR  ] syntax error, unexpected invalid token @ line 1, column 1\n"
        "[  ERROR  ] 001: @,,\n"
        "[  ERROR  ]      ^\n"
        "[  ERROR  ] parsing failed\n";
    // clang-format on

    const char* prog = "@,,";

    int    r     = TEST_FAILED;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope != NULL)
        goto end;

    char* out = strbuilder_reset(err_sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    if (scope)
        Scope_free(scope);
    return r;
}

int TEST(interpreter_error_invalid_op_1)(void)
{
    // clang-format off
    const char* expected =
        "[  ERROR  ] 001: proc { local a = 1u8 * \"a\"; }\n"
        "[  ERROR  ]      __________________________^\n"
        "[  ERROR  ] Exception @ line 1, col 27 > mul undefined for types unum and string\n";
    // clang-format on

    const char* prog = "proc { local a = 1u8 * \"a\"; }";

    int    r     = TEST_FAILED;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope != NULL)
        goto end;

    char* out = strbuilder_reset(err_sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    if (scope)
        Scope_free(scope);
    return r;
}

int TEST(find_forward_match)(void)
{
    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)"AAAAciaoBBBB", 12);
    const char* prog = "proc {"
                       "    local a = find(\"ciao\");"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    BHEngineValue* v = Scope_get_local(scope, "a");
    ASSERT_TENGINE_UNUM_EQ(v, 1);
    ASSERT(tfb->fb->off == 4);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(find_forward_no_match)(void)
{
    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(answer_to_universe, sizeof(answer_to_universe));
    fb_seek(tfb->fb, tfb->fb->size);
    const char* prog = "proc {"
                       "    local a = find(\"ciao\");"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    BHEngineValue* v = Scope_get_local(scope, "a");
    ASSERT_TENGINE_UNUM_EQ(v, 0);
    ASSERT(tfb->fb->off == tfb->fb->size);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(find_backward_match)(void)
{
    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)"AAAAciaoBBBB", 12);
    fb_seek(tfb->fb, 12);

    const char* prog = "proc {"
                       "    local a = find(\"ciao\", 1);"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    BHEngineValue* v = Scope_get_local(scope, "a");
    ASSERT_TENGINE_UNUM_EQ(v, 1);
    ASSERT(tfb->fb->off == 4);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(find_backward_no_match)(void)
{
    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(answer_to_universe, sizeof(answer_to_universe));
    fb_seek(tfb->fb, tfb->fb->size);

    const char* prog = "proc {"
                       "    local a = find(\"ugo\", 1);"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    BHEngineValue* v = Scope_get_local(scope, "a");
    ASSERT_TENGINE_UNUM_EQ(v, 0);
    ASSERT(tfb->fb->off == tfb->fb->size);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(exit_in_struct)(void)
{
    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(answer_to_universe, sizeof(answer_to_universe));
    fb_seek(tfb->fb, tfb->fb->size);

    const char* prog = "struct A { exit(); }"
                       "proc {"
                       "    local a = 1u16;"
                       "    A var;"
                       "    local b = 2u16;"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    BHEngineValue* va = Scope_get_local(scope, "a");
    ASSERT_TENGINE_UNUM_EQ(va, 1);
    BHEngineValue* vb = Scope_get_local(scope, "b");
    ASSERT(vb == NULL);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(saved_quiet_mode)(void)
{
    // clang-format off
    const char* expected =
        "b+00000001  b: 42\n"
        "b+00000003  b: 44";
    // clang-format on

    int              r   = TEST_SUCCEEDED;
    char*            out = NULL;
    DummyFilebuffer* tfb = dummyfilebuffer_create((u8_t*)"ABCD", 4);
    fb_seek(tfb->fb, 0);

    const char* prog = "fn a() { disable_print(); u8 a; }"
                       "fn b() { u8 b; }"
                       "proc {"
                       "    a();"
                       "    b();"
                       "    a();"
                       "    b();"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    out = strbuilder_reset(sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    bhex_free(out);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(read_outside_boundaries)(void)
{
    // clang-format off
    const char* expected =
        "[  ERROR  ] too many bytes to read: 1\n"
        "[  ERROR  ] 001: fn a() { disable_print(); u8 a; }\n"
        "[  ERROR  ]      ______________________________^\n"
        "[  ERROR  ] 002: fn b() { u8 b; }\n"
        "[  ERROR  ] 003: proc {\n"
        "[  ERROR  ] Exception @ line 1, col 31 > RUNTIME ERROR\n";
    // clang-format on

    int              r   = TEST_SUCCEEDED;
    char*            out = NULL;
    DummyFilebuffer* tfb = dummyfilebuffer_create((u8_t*)"ABCD", 4);
    fb_seek(tfb->fb, 4);

    const char* prog = "fn a() { disable_print(); u8 a; }\n"
                       "fn b() { u8 b; }\n"
                       "proc {\n"
                       "    a();\n"
                       "    b();\n"
                       "    a();\n"
                       "    b();\n"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope == NULL);

    out = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    bhex_free(out);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(wchars)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000  a: A\n"
        "b+00000002  b: B\n"
        "b+00000004  c: '\\u0201'";
    // clang-format on

    int              r      = TEST_SUCCEEDED;
    char*            out    = NULL;
    u8_t             data[] = {'A', 0, 'B', 0, 1, 2};
    DummyFilebuffer* tfb    = dummyfilebuffer_create(data, sizeof(data));
    fb_seek(tfb->fb, 0);

    const char* prog = "proc {"
                       "    wchar a;"
                       "    wchar b;"
                       "    wchar c;"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    out = strbuilder_reset(sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    bhex_free(out);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(wchar_array)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000  c: 'AB\\u0201C'";
    // clang-format on

    int              r      = TEST_SUCCEEDED;
    char*            out    = NULL;
    u8_t             data[] = {'A', 0, 'B', 0, 1, 2, 'C', 0};
    DummyFilebuffer* tfb    = dummyfilebuffer_create(data, sizeof(data));
    fb_seek(tfb->fb, 0);

    const char* prog = "proc {"
                       "    wchar c[4];"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    out = strbuilder_reset(sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    bhex_free(out);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(wstring_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000  str: 'ABCD'";
    // clang-format on

    int              r      = TEST_SUCCEEDED;
    char*            out    = NULL;
    u8_t             data[] = {'A', 0, 'B', 0, 'C', 0, 'D', 0, 0, 0};
    DummyFilebuffer* tfb    = dummyfilebuffer_create(data, sizeof(data));
    fb_seek(tfb->fb, 0);

    const char* prog = "proc {"
                       "    wstring str;"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    out = strbuilder_reset(sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    bhex_free(out);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(wstring_2)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000  str: 'ABCD\\u0101'";
    // clang-format on

    int              r      = TEST_SUCCEEDED;
    char*            out    = NULL;
    u8_t             data[] = {'A', 0, 'B', 0, 'C', 0, 'D', 0, 1, 1, 0, 0};
    DummyFilebuffer* tfb    = dummyfilebuffer_create(data, sizeof(data));
    fb_seek(tfb->fb, 0);

    const char* prog = "proc {"
                       "    wstring str;"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    out = strbuilder_reset(sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    bhex_free(out);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(wstrings_eq)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000  str1: 'AB'\n"
        "b+00000006  str2: 'AB'\n"
        "b+0000000c  str3: 'AD'\n"
        "yes 1\n";
    // clang-format on

    int              r      = TEST_SUCCEEDED;
    char*            out    = NULL;
    u8_t             data[] = {'A', 0, 'B', 0,   0, 0,   'A', 0, 'B',
                               0,   0, 0,   'A', 0, 'D', 0,   0, 0};
    DummyFilebuffer* tfb    = dummyfilebuffer_create(data, sizeof(data));
    fb_seek(tfb->fb, 0);

    const char* prog = "proc {"
                       "    wstring str1;"
                       "    wstring str2;"
                       "    wstring str3;"
                       "    if (str1 == str2) { print(\"yes 1\"); }"
                       "    if (str1 == str3) { print(\"yes 2\"); }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    out = strbuilder_reset(sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    bhex_free(out);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(string_to_wstring)(void)
{
    const char* prog = "proc { "
                       "    local a = \"abcd\";"
                       "    local b = wstring(\"abcd\");"
                       "    local c = wstring(\"abcd\");"
                       "    local d = a == b;"
                       "    local e = b == c;"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope != NULL);

    int            r  = TEST_SUCCEEDED;
    BHEngineValue* vd = Scope_get_local(scope, "d");
    ASSERT_TENGINE_UNUM_EQ(vd, 0);
    BHEngineValue* ve = Scope_get_local(scope, "e");
    ASSERT_TENGINE_UNUM_EQ(ve, 1);

end:
    if (scope)
        Scope_free(scope);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(syntax_error_with_newlines)(void)
{
    // clang-format off
    const char* expected =
        "[  ERROR  ] syntax error, unexpected invalid token, expecting TIDENTIFIER @ line 6, column 9\n"
        "[  ERROR  ] 004:     \n"
        "[  ERROR  ] 005:     \n"
        "[  ERROR  ] 006:     abcd@@\n"
        "[  ERROR  ]      ________^\n"
        "[  ERROR  ] 007: }\n"
        "[  ERROR  ] parsing failed\n";
    // clang-format on

    const char* prog = "proc { "
                       "    \n"
                       "    \n"
                       "    \n"
                       "    \n"
                       "    \n"
                       "    abcd@@\n"
                       "}";
    char*       out  = NULL;

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);

    int r = TEST_SUCCEEDED;
    out   = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    bhex_free(out);
    if (scope)
        Scope_free(scope);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(to_int)(void)
{
    const char* prog = "proc { "
                       "    local a = to_int(\"1234\");"
                       "}";

    int    r     = TEST_SUCCEEDED;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope != NULL);
    BHEngineValue* v = Scope_get_local(scope, "a");
    ASSERT_TENGINE_SNUM_EQ(v, 1234);

end:
    if (scope)
        Scope_free(scope);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(strlen)(void)
{
    const char* prog = "proc { "
                       "    local a = strlen(\"1234\");"
                       "}";

    int    r     = TEST_SUCCEEDED;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope != NULL);
    BHEngineValue* v = Scope_get_local(scope, "a");
    ASSERT_TENGINE_UNUM_EQ(v, 4);

end:
    if (scope)
        Scope_free(scope);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(fwd_1)(void)
{
    const char* prog = "proc { "
                       "    local a = off();"
                       "    fwd(10);"
                       "    a = off() - a;"
                       "}";

    int    r     = TEST_SUCCEEDED;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope != NULL);
    BHEngineValue* v = Scope_get_local(scope, "a");
    ASSERT_TENGINE_UNUM_EQ(v, 10);

end:
    if (scope)
        Scope_free(scope);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(fwd_2)(void)
{
    // clang-format off
    const char* expected =
    "[  ERROR  ] 001: proc {     fwd(99999999);}\n"
    "[  ERROR  ]      _______________________^\n"
    "[  ERROR  ] Exception @ line 1, col 24 > fwd: unable to go forward by '99999999' bytes\n";
    // clang-format on

    const char* prog = "proc { "
                       "    fwd(99999999);"
                       "}";
    char*       out  = NULL;

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);

    int r = TEST_SUCCEEDED;
    out   = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    bhex_free(out);
    if (scope)
        Scope_free(scope);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(fwd_3)(void)
{
    // clang-format off
    const char* expected =
    "[  ERROR  ] 001: proc {     fwd(\"abc\");}\n"
    "[  ERROR  ]      ____________________^\n"
    "[  ERROR  ] Exception @ line 1, col 21 > string is not a numeric type, fwd: parameter 1 is not a number\n";
    // clang-format on

    const char* prog = "proc { "
                       "    fwd(\"abc\");"
                       "}";
    char*       out  = NULL;

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);

    int r = TEST_SUCCEEDED;
    out   = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    bhex_free(out);
    if (scope)
        Scope_free(scope);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(fwd_4)(void)
{
    // clang-format off
    const char* expected =
    "[  ERROR  ] 001: proc {     fwd();}\n"
    "[  ERROR  ]      _______________^\n"
    "[  ERROR  ] Exception @ line 1, col 16 > fwd: expected 1 parameter, got 0\n";
    // clang-format on

    const char* prog = "proc { "
                       "    fwd();"
                       "}";
    char*       out  = NULL;

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);

    int r = TEST_SUCCEEDED;
    out   = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    bhex_free(out);
    if (scope)
        Scope_free(scope);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(fwd_5)(void)
{
    // clang-format off
    const char* expected =
    "[  ERROR  ] 001: proc {     fwd(-10);}\n"
    "[  ERROR  ]      __________________^\n"
    "[  ERROR  ] Exception @ line 1, col 19 > fwd: unable to go forward by '18446744073709551606' bytes\n";
    // clang-format on

    const char* prog = "proc { "
                       "    fwd(-10);"
                       "}";
    char*       out  = NULL;

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);

    int r = TEST_SUCCEEDED;
    out   = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    bhex_free(out);
    if (scope)
        Scope_free(scope);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(bwd_1)(void)
{
    const char* prog = "proc { "
                       "    seek(10);"
                       "    local a = off();"
                       "    bwd(10);"
                       "    a = a - off();"
                       "}";

    int    r     = TEST_SUCCEEDED;
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope != NULL);
    BHEngineValue* v = Scope_get_local(scope, "a");
    ASSERT_TENGINE_UNUM_EQ(v, 10);

end:
    if (scope)
        Scope_free(scope);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(bwd_2)(void)
{
    // clang-format off
    const char* expected =
    "[  ERROR  ] 001: proc {     bwd();}\n"
    "[  ERROR  ]      _______________^\n"
    "[  ERROR  ] Exception @ line 1, col 16 > bwd: expected 1 parameter, got 0\n";
    // clang-format on

    const char* prog = "proc { "
                       "    bwd();"
                       "}";
    char*       out  = NULL;

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);

    int r = TEST_SUCCEEDED;
    out   = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    bhex_free(out);
    if (scope)
        Scope_free(scope);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(bwd_3)(void)
{
    // clang-format off
    const char* expected =
    "[  ERROR  ] 001: proc {     bwd(\"\");}\n"
    "[  ERROR  ]      _________________^\n"
    "[  ERROR  ] Exception @ line 1, col 18 > string is not a numeric type, bwd: parameter 1 is not a number\n";
    // clang-format on

    const char* prog = "proc { "
                       "    bwd(\"\");"
                       "}";
    char*       out  = NULL;

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);

    int r = TEST_SUCCEEDED;
    out   = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    bhex_free(out);
    if (scope)
        Scope_free(scope);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(char_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000  a: 'Hello'";
    // clang-format on

    int              r      = TEST_SUCCEEDED;
    char*            out    = NULL;
    u8_t             data[] = {'H', 'e', 'l', 'l', 'o'};
    DummyFilebuffer* tfb    = dummyfilebuffer_create(data, sizeof(data));
    fb_seek(tfb->fb, 0);

    const char* prog = "proc {"
                       "    char a[5];"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    out = strbuilder_reset(sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    bhex_free(out);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(big_endian_wchar)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000  a: A\n"
        "b+00000002  b: B";
    // clang-format on

    int              r      = TEST_SUCCEEDED;
    char*            out    = NULL;
    u8_t             data[] = {0, 'A', 0, 'B'};
    DummyFilebuffer* tfb    = dummyfilebuffer_create(data, sizeof(data));
    fb_seek(tfb->fb, 0);

    const char* prog = "proc {"
                       "    big_endian();"
                       "    wchar a;"
                       "    wchar b;"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    out = strbuilder_reset(sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    bhex_free(out);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(big_endian_wchar_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000  a: A\n"
        "b+00000002  b: B";
    // clang-format on

    int              r      = TEST_SUCCEEDED;
    char*            out    = NULL;
    u8_t             data[] = {0, 'A', 0, 'B'};
    DummyFilebuffer* tfb    = dummyfilebuffer_create(data, sizeof(data));
    fb_seek(tfb->fb, 0);

    const char* prog = "proc {"
                       "    big_endian();"
                       "    wchar a;"
                       "    wchar b;"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    out = strbuilder_reset(sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    bhex_free(out);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(enable_disable_print)(void)
{
    // Only b should appear - a is printed with print disabled
    // clang-format off
    const char* expected =
        "b+00000004  b: 4748504a";
    // clang-format on

    const char* prog = "proc {"
                       "    disable_print();"
                       "    u32 a;"
                       "    enable_print();"
                       "    u32 b;"
                       "}";
    char*       out  = NULL;

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(pseudo_random, sizeof(pseudo_random));
    fb_seek(tfb->fb, 0);

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    out = strbuilder_reset(sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    bhex_free(out);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(bwd_4)(void)
{
    // clang-format off
    const char* expected =
    "[  ERROR  ] 001: proc {     bwd(10);}\n"
    "[  ERROR  ]      _________________^\n"
    "[  ERROR  ] Exception @ line 1, col 18 > bwd: '10' is greater that current offset\n";
    // clang-format on

    const char* prog = "proc { "
                       "    bwd(10);"
                       "}";
    char*       out  = NULL;

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);

    int r = TEST_SUCCEEDED;
    out   = strbuilder_reset(err_sb);
    ASSERT(compare_strings_ignoring_X(expected, out));

end:
    bhex_free(out);
    if (scope)
        Scope_free(scope);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(filevar_byref_memory)(void)
{
    // With pass-by-reference, assigning a large file_var to N locals must NOT
    // allocate N copies of the data.
    //
    // Strategy: use bhex_alloc_track_start/stop to count all live heap
    // allocations while a scope is alive.  With 1 local the count is
    // "live_1"; with N=1000 locals it must not grow by more than O(N) (just
    // the map cells for the extra variable names).  The old pass-by-value code
    // would add O(N * ARRAY_SIZE) extra BHEngineValue objects.
    //
    // Threshold: live_n - live_1 < N * ARRAY_SIZE / 4
    //   new code: ~(N-1) extra map cells              ~  999  (passes)
    //   old code: ~(N-1)*(ARRAY_SIZE+2) extra objects ~ 43956 (would fail)

#define PERF_N          1000
#define PERF_ARRAY_SIZE 42
    /* ^^^ defines scoped to this test by convention; #undef'd below */

    u8_t data[PERF_ARRAY_SIZE * 2];
    for (int i = 0; i < PERF_ARRAY_SIZE * 2; i++)
        data[i] = (u8_t)(i + 1);

    // --- 1 local copy ---
    DummyFilebuffer* tfb1  = dummyfilebuffer_create(data, sizeof(data));
    const char*      prog1 = "proc {"
                             "    disable_print();"
                             "    u16 arr[42];"
                             "    local a0 = arr;"
                             "}";

    bhex_alloc_track_start();
    Scope* scope1 = bhengine_interpreter_run_on_string(tfb1->fb, prog1);
    size_t live_1 = bhex_alloc_live_count();
    if (scope1)
        Scope_free(scope1);
    bhex_alloc_track_stop();
    dummyfilebuffer_destroy(tfb1);

    // --- PERF_N local copies ---
    DummyFilebuffer* tfb2 = dummyfilebuffer_create(data, sizeof(data));
    StringBuilder*   sb   = strbuilder_new();
    strbuilder_append(sb, "proc { disable_print(); u16 arr[42];");
    for (int i = 0; i < PERF_N; i++)
        strbuilder_appendf(sb, " local a%d = arr;", i);
    strbuilder_append(sb, " }");
    char* prog_n = strbuilder_finalize(sb);

    bhex_alloc_track_start();
    Scope* scope_n = bhengine_interpreter_run_on_string(tfb2->fb, prog_n);
    size_t live_n  = bhex_alloc_live_count();
    if (scope_n)
        Scope_free(scope_n);
    bhex_alloc_track_stop();
    bhex_free(prog_n);
    dummyfilebuffer_destroy(tfb2);

    size_t threshold = (size_t)(PERF_N * PERF_ARRAY_SIZE / 4);
    if (live_n < live_1 || live_n - live_1 >= threshold) {
        printf("[!] live_1=%zu  live_n=%zu  threshold=%zu\n", live_1, live_n,
               threshold);
        return TEST_FAILED;
    }
    return TEST_SUCCEEDED;
#undef PERF_N
#undef PERF_ARRAY_SIZE
}

int TEST(filevar_to_local)(void)
{
    // EXPR_VAR for a file_var retains instead of copying
    int              r    = 0;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"\x42\x43", 2);
    const char*      prog = "proc {"
                            "    disable_print();"
                            "    u8 fv;"
                            "    local a = fv;"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 0x42);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(filevar_to_multiple_locals)(void)
{
    // Same file_var retained by two locals; both must read correctly
    // and no double-free when scope is released
    int              r    = 0;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"\x42\x43", 2);
    const char*      prog = "proc {"
                            "    disable_print();"
                            "    u8 fv;"
                            "    local a = fv;"
                            "    local b = fv;"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* va = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, va, 0x42);
    BHEngineValue* vb = Scope_get_local(scope, "b");
    IS_TENGINE_UNUM_EQ(r, vb, 0x42);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(filevar_struct_field_to_local)(void)
{
    // EXPR_SUBSCR retains the field value instead of copying
    int              r    = 0;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"\x10\x20", 2);
    const char*      prog = "struct S { u8 x; u8 y; }"
                            "proc {"
                            "    disable_print();"
                            "    S sv;"
                            "    local a = sv.x;"
                            "    local b = sv.y;"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* va = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, va, 0x10);
    BHEngineValue* vb = Scope_get_local(scope, "b");
    IS_TENGINE_UNUM_EQ(r, vb, 0x20);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(filevar_passed_to_fn)(void)
{
    // file_var passed to a function is retained, not copied
    int              r    = 0;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"\x07\x00", 2);
    const char*      prog = "fn double(x) { result = u32(x + x); }"
                            "proc {"
                            "    disable_print();"
                            "    u8 fv;"
                            "    local a = double(fv);"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 14);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(filevar_struct_passed_to_fn)(void)
{
    // struct file_var passed to a function; field accessed inside
    int              r    = 0;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"\x05\x0A", 2);
    const char*      prog = "struct S { u8 x; u8 y; }"
                            "fn get_x(s) { result = u8(s.x); }"
                            "proc {"
                            "    disable_print();"
                            "    S sv;"
                            "    local r = get_x(sv);"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "r");
    IS_TENGINE_UNUM_EQ(r, v, 5);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(filevar_array_element_to_local)(void)
{
    // array file_var element retained via BHEngineValue_array_sub
    int              r = 0;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)"\x01\x02\x03\x04\x05", 5);
    const char* prog = "proc {"
                       "    disable_print();"
                       "    u8 arr[5];"
                       "    local a = arr[0];"
                       "    local b = arr[4];"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* va = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, va, 1);
    BHEngineValue* vb = Scope_get_local(scope, "b");
    IS_TENGINE_UNUM_EQ(r, vb, 5);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(filevar_reused_after_fn_call)(void)
{
    // file_var refcount is restored after function call; still accessible
    int              r    = 0;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"\x09\x00", 2);
    const char*      prog = "fn inc(x) { result = u32(x + 1); }"
                            "proc {"
                            "    disable_print();"
                            "    u8 fv;"
                            "    local a = inc(fv);"
                            "    local b = fv;"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* va = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, va, 10);
    BHEngineValue* vb = Scope_get_local(scope, "b");
    IS_TENGINE_UNUM_EQ(r, vb, 9);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(filevar_struct_field_passed_to_fn)(void)
{
    // field obtained via EXPR_SUBSCR (retained) then passed to a function
    int              r    = 0;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"\x06\x00", 2);
    const char*      prog = "struct S { u8 x; }"
                            "fn triple(v) { result = u32(v + v + v); }"
                            "proc {"
                            "    disable_print();"
                            "    S sv;"
                            "    local r = triple(sv.x);"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "r");
    IS_TENGINE_UNUM_EQ(r, v, 18);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(scope_if_no_leak)(void)
{
    // a variable declared inside an if block must not be visible in the outer
    // scope
    const char* prog = "proc {"
                       "  local a = 1;"
                       "  if (a) {"
                       "    local inner = 42;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int r = 1;
    if (Scope_get_local(scope, "inner") != NULL)
        r = 0;

    Scope_free(scope);
    return r;
}

int TEST(scope_while_no_leak)(void)
{
    // a variable declared inside a while block must not be visible in the outer
    // scope
    const char* prog = "proc {"
                       "  local i = 0;"
                       "  while (i < 3) {"
                       "    local inner = 99;"
                       "    i = i + 1;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int r = 1;
    if (Scope_get_local(scope, "inner") != NULL)
        r = 0;

    Scope_free(scope);
    return r;
}

int TEST(scope_if_outer_var_modified)(void)
{
    // a variable declared in the outer scope must be modifiable from inside an
    // if block
    const char* prog = "proc {"
                       "  local a = 10;"
                       "  local b = 0;"
                       "  if (a) {"
                       "    b = 42;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    Scope_free(scope);
    return r;
}

int TEST(scope_while_outer_var_modified)(void)
{
    // a variable declared in the outer scope must be modifiable from inside a
    // while block
    const char* prog = "proc {"
                       "  local a = 0;"
                       "  local b = 0;"
                       "  while (a < 5) {"
                       "    b = b + a;"
                       "    a = a + 1;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 10);

end:
    Scope_free(scope);
    return r;
}

int TEST(scope_else_no_leak)(void)
{
    // a variable declared in an else block must not be visible outside
    const char* prog = "proc {"
                       "  local a = 0;"
                       "  if (a) {"
                       "    local x = 1;"
                       "  } else {"
                       "    local y = 2;"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int r = 1;
    if (Scope_get_local(scope, "x") != NULL)
        r = 0;
    if (Scope_get_local(scope, "y") != NULL)
        r = 0;

    Scope_free(scope);
    return r;
}

int TEST(scope_nested_if_while_no_leak)(void)
{
    // deeply nested declarations must not escape to the outer proc scope
    const char* prog = "proc {"
                       "  local a = 1;"
                       "  local b = 0;"
                       "  if (a) {"
                       "    local c = 0;"
                       "    while (c < 3) {"
                       "      local d = c;"
                       "      b = b + d;"
                       "      c = c + 1;"
                       "    }"
                       "  }"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int r = 1;
    // b must have been updated (0+1+2 = 3)
    BHEngineValue* vb = Scope_get_local(scope, "b");
    if (vb == NULL || vb->snum != 3)
        r = 0;
    // c and d must not have leaked
    if (Scope_get_local(scope, "c") != NULL)
        r = 0;
    if (Scope_get_local(scope, "d") != NULL)
        r = 0;

    Scope_free(scope);
    return r;
}

int TEST(scope_if_no_access_after)(void)
{
    // accessing a variable declared inside a previous if block must raise an
    // error
    const char* prog = "proc {"
                       "  local a = 1;"
                       "  if (a) { local inner = 5; }"
                       "  local b = inner;"
                       "}";

    // The interpreter should fail (inner is not in scope)
    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    int    r     = (scope == NULL) ? 1 : 0;
    if (scope)
        Scope_free(scope);
    return r;
}

int TEST(tostring_unum)(void)
{
    const char* prog = "proc {"
                       "  nums_in(10);"
                       "  local a = 42u8;"
                       "  local b = tostring(a);"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_STRING_EQ(r, v, "42");

end:
    Scope_free(scope);
    return r;
}

int TEST(tostring_snum)(void)
{
    const char* prog = "proc {"
                       "  nums_in(10);"
                       "  local a = -123;"
                       "  local b = tostring(a);"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_STRING_EQ(r, v, "-123");

end:
    Scope_free(scope);
    return r;
}

int TEST(tostring_string)(void)
{
    const char* prog = "proc {"
                       "  local a = \"hello\";"
                       "  local b = tostring(a);"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_STRING_EQ(r, v, "hello");

end:
    Scope_free(scope);
    return r;
}

int TEST(tostring_enum)(void)
{
    DummyFilebuffer* tfb = dummyfilebuffer_create((const u8_t*)"\x04\x00", 2);

    const char* prog = "enum MyEnum : u16 { A = 1, B = 2, C = 4 }"
                       "proc {"
                       "  MyEnum v;"
                       "  local s = tostring(v);"
                       "}";

    int    r     = 0;
    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "s");
    IS_TENGINE_STRING_EQ(r, v, "C");

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(tostring_enum_single)(void)
{
    DummyFilebuffer* tfb = dummyfilebuffer_create((const u8_t*)"\x01\x00", 2);

    const char* prog = "enum MyEnum : u16 { A = 1, B = 2, C = 4 }"
                       "proc {"
                       "  MyEnum v;"
                       "  local s = tostring(v);"
                       "}";

    int    r     = 0;
    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "s");
    IS_TENGINE_STRING_EQ(r, v, "A");

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(tostring_hex)(void)
{
    const char* prog = "proc {"
                       "  nums_in(16);"
                       "  local a = 255u8;"
                       "  local b = tostring(a);"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_STRING_EQ(r, v, "ff");

end:
    Scope_free(scope);
    return r;
}

int TEST(tostring_orenum)(void)
{
    DummyFilebuffer* tfb = dummyfilebuffer_create((const u8_t*)"\x03\x00", 2);

    const char* prog = "orenum MyFlags : u16 { A = 1, B = 2, C = 4 }"
                       "proc {"
                       "  MyFlags v;"
                       "  local s = tostring(v);"
                       "}";

    int    r     = 0;
    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    BHEngineValue* v = Scope_get_local(scope, "s");
    IS_TENGINE_STRING_EQ(r, v, "A | B");

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;
}

// --- Crash-resilience regression tests ---
//
// Each of these used to abort the process (SEGV / SIGFPE / stack overflow /
// panic()); they must now fail cleanly, i.e. return a NULL scope after raising
// an exception, without taking the whole program down.

int TEST(crash_error_with_non_string_arg)(void)
{
    // error() used to format an integer as a char*, dereferencing it.
    const char* prog = "proc { error(1); }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);
    return TEST_SUCCEEDED;
fail:
    if (scope)
        Scope_free(scope);
    return TEST_FAILED;
}

int TEST(crash_find_empty_needle)(void)
{
    // A needle starting with an escaped NUL byte made what_len 0, so
    // "what_len - 1" underflowed to 0xFFFFFFFF and read out of bounds. The
    // needle is now used as the lexer decoded it, so this is a plain 4 byte
    // search that finds nothing.
    int              r    = TEST_SUCCEEDED;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"ABCD", 4);
    const char*      prog = "proc { local r = find(\"\\x00abc\", 1); }";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "r"), 0);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// An empty literal is still rejected: it would match everywhere and nowhere
int TEST(find_empty_needle_raises)(void)
{
    int              r    = TEST_SUCCEEDED;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"ABCD", 4);
    const char*      prog = "proc { local r = find(\"\"); }";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope == NULL);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// The matcher used to reset its state to zero on a mismatch, so it missed any
// needle whose prefix repeats inside itself: "aab" was not found in "aaab".
int TEST(find_repeated_prefix_forward)(void)
{
    int              r    = TEST_SUCCEEDED;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"aaab", 4);
    const char*      prog = "proc { local a = find(\"aab\"); }";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "a"), 1);
    ASSERT(tfb->fb->off == 1);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// The backward search declared a match one byte too early, so it reported a
// hit at an offset where the needle is not: "baa" "found" at "aaa".
int TEST(find_repeated_suffix_backward)(void)
{
    int              r   = TEST_SUCCEEDED;
    DummyFilebuffer* tfb = dummyfilebuffer_create((const u8_t*)"zbaaa", 5);
    fb_seek(tfb->fb, 5);
    const char* prog = "proc { local a = find(\"baa\", 1); }";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "a"), 1);
    ASSERT(tfb->fb->off == 1);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// A match must be found even when it straddles two read blocks
int TEST(find_across_block_boundary)(void)
{
    int    r    = TEST_SUCCEEDED;
    size_t size = fb_block_size + 16;
    u8_t*  data = bhex_malloc(size);
    memset(data, 'x', size);
    memcpy(data + fb_block_size - 2, "MARK", 4);

    DummyFilebuffer* tfb  = dummyfilebuffer_create(data, size);
    const char*      prog = "proc { local a = find(\"MARK\"); }";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "a"), 1);
    ASSERT(tfb->fb->off == fb_block_size - 2);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    bhex_free(data);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// find_next() reports the offset and leaves the cursor alone
int TEST(find_next_does_not_move)(void)
{
    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)"AAAAciaoBBBB", 12);
    const char* prog = "proc {"
                       "    local a = find_next(\"ciao\");"
                       "    local b = find_next(\"nope\");"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "a"), 4);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "b"), -1);
    ASSERT(tfb->fb->off == 0);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(crash_div_int64_min_by_minus_one)(void)
{
    // INT64_MIN / -1 overflows and raises SIGFPE on x86.
    const char* prog = "proc { local a = 0s8 - 9223372036854775808; "
                       "local b = 0s8 - 1; local x = a / b; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    // either a clean exception or a well-defined result, but never a crash
    if (scope)
        Scope_free(scope);
    return TEST_SUCCEEDED;
}

int TEST(crash_shift_out_of_range)(void)
{
    // Shifting by >= 64 is undefined behavior.
    const char* prog = "proc { local x = 1 << 200; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);
    return TEST_SUCCEEDED;
fail:
    if (scope)
        Scope_free(scope);
    return TEST_FAILED;
}

int TEST(crash_array_used_as_number)(void)
{
    // as_u64() used to panic() (exit(1)) on a buf/array value.
    const char* prog = "proc { u8 b[2]; if (b) { local x = 1; } }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);
    return TEST_SUCCEEDED;
fail:
    if (scope)
        Scope_free(scope);
    return TEST_FAILED;
}

int TEST(crash_infinite_recursion)(void)
{
    // Unbounded call depth used to exhaust the stack.
    const char* prog = "fn f() { f(); } proc { f(); }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);
    return TEST_SUCCEEDED;
fail:
    if (scope)
        Scope_free(scope);
    return TEST_FAILED;
}

int TEST(crash_self_referential_struct)(void)
{
    // A struct containing itself consumes no bytes and never terminates.
    const char* prog = "struct A { A x; } proc { A a; }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    ASSERT(scope == NULL);
    return TEST_SUCCEEDED;
fail:
    if (scope)
        Scope_free(scope);
    return TEST_FAILED;
}

int TEST(recursion_within_limit_still_works)(void)
{
    // The depth limit must not break legitimate recursion.
    const char* prog = "fn fact(n) {"
                       "  if (n <= 1) { result = 1; return; }"
                       "  result = n * fact(n - 1);"
                       "}"
                       "proc { local a = fact(10); }";

    Scope* scope = bhengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return TEST_FAILED;

    int            r = 0;
    BHEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 3628800);

end:
    Scope_free(scope);
    return r;
}

/*
    Builtins added to let a template parse text-oriented formats without
    hand-rolling a helper function for every primitive
*/

// peek() and peek_u8() read without consuming, read() consumes
int TEST(peek_and_read)(void)
{
    int              r    = TEST_SUCCEEDED;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"ABCDEFGH", 8);
    const char*      prog = "proc {"
                            "    local a = peek(4);"
                            "    local b = off();"
                            "    local c = peek_u8();"
                            "    local d = read(4);"
                            "    local e = off();"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    int ok = 0;
    IS_TENGINE_STRING_EQ(ok, Scope_get_local(scope, "a"), "ABCD");
    ASSERT(ok);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "b"), 0);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "c"), 'A');
    ok = 0;
    IS_TENGINE_STRING_EQ(ok, Scope_get_local(scope, "d"), "ABCD");
    ASSERT(ok);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "e"), 4);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// peek() is clamped to what is left, and peek_u8() reports the end of the file
int TEST(peek_at_end_of_file)(void)
{
    int              r    = TEST_SUCCEEDED;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"AB", 2);
    const char*      prog = "proc {"
                            "    local a = peek(8);"
                            "    seek(2);"
                            "    local b = peek_u8();"
                            "    local c = peek(4);"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    int ok = 0;
    IS_TENGINE_STRING_EQ(ok, Scope_get_local(scope, "a"), "AB");
    ASSERT(ok);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "b"), -1);
    ok = 0;
    IS_TENGINE_STRING_EQ(ok, Scope_get_local(scope, "c"), "");
    ASSERT(ok);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// scan_* measure a run of bytes, skip_* consume it
int TEST(scan_and_skip)(void)
{
    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)"1234 \t\nabc", 10);
    const char* prog = "proc {"
                       "    local digits = scan_while(\"0123456789\");"
                       "    local here = off();"
                       "    local to_space = scan_until(\" \");"
                       "    local skipped = skip_while(\"0123456789\");"
                       "    local after = off();"
                       "    local ws = skip_while(\" \\t\\n\");"
                       "    local rest = peek(3);"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "digits"), 4);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "here"), 0);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "to_space"), 4);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "skipped"), 4);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "after"), 4);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "ws"), 3);

    int ok = 0;
    IS_TENGINE_STRING_EQ(ok, Scope_get_local(scope, "rest"), "abc");
    ASSERT(ok);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// A zero-padded decimal is not octal: str_to_int64 used base 0, so
// to_int("0000000063") used to be 51, and "0000000009" an error
int TEST(to_int_bases)(void)
{
    int              r    = TEST_SUCCEEDED;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"AB", 2);
    const char*      prog = "proc {"
                            "    local a = to_int(\"0000000063\");"
                            "    local b = to_int(\"0000000009\");"
                            "    local c = to_int(\"0755\", 8);"
                            "    local d = to_int(\"ff\", 16);"
                            "    local e = to_int(\"-42\");"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "a"), 63);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "b"), 9);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "c"), 493);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "d"), 255);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "e"), -42);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// to_int() returned a value declaring a size of 64 *bytes*, which printed as
// 128 hex digits
int TEST(to_int_result_size)(void)
{
    int              r    = TEST_SUCCEEDED;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"AB", 2);
    const char*      prog = "proc { local a = to_int(\"42\"); }";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    BHEngineValue* v = Scope_get_local(scope, "a");
    ASSERT(v != NULL);
    ASSERT(v->t == TENGINE_SNUM);
    ASSERT(v->snum_size == 8);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(string_builtins)(void)
{
    int              r    = TEST_SUCCEEDED;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"AB", 2);
    const char*      prog = "proc {"
                            "    local a = trim(\"  hi \\t\\r\\n\");"
                            "    local b = printable(\" a b\\tc \");"
                            "    local c = substr(\"hello world\", 6);"
                            "    local d = substr(\"hello world\", 0, 5);"
                            "    local e = starts_with(\"hello\", \"he\");"
                            "    local f = starts_with(\"hello\", \"xx\");"
                            "    local g = index_of(\"hello world\", \"world\");"
                            "    local h = index_of(\"hello\", \"z\");"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    int ok = 0;
    IS_TENGINE_STRING_EQ(ok, Scope_get_local(scope, "a"), "hi");
    ASSERT(ok);
    ok = 0;
    IS_TENGINE_STRING_EQ(ok, Scope_get_local(scope, "b"), "abc");
    ASSERT(ok);
    ok = 0;
    IS_TENGINE_STRING_EQ(ok, Scope_get_local(scope, "c"), "world");
    ASSERT(ok);
    ok = 0;
    IS_TENGINE_STRING_EQ(ok, Scope_get_local(scope, "d"), "hello");
    ASSERT(ok);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "e"), 1);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "f"), 0);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "g"), 6);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "h"), -1);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(math_builtins)(void)
{
    int              r    = TEST_SUCCEEDED;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"AB", 2);
    const char*      prog = "proc {"
                            "    local a = min(3, 1, 2);"
                            "    local b = max(3, 1, 2);"
                            "    local c = abs(-7);"
                            "    local d = align_up(13, 8);"
                            "    local e = align_up(16, 8);"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "a"), 1);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "b"), 3);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "c"), 7);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "d"), 16);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "e"), 16);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(align_up_zero_alignment)(void)
{
    int              r    = TEST_SUCCEEDED;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"AB", 2);
    const char*      prog = "proc { local a = align_up(13, 0); }";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope == NULL);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// assert() lets a template state a format invariant in one statement
int TEST(assert_passes)(void)
{
    int              r    = TEST_SUCCEEDED;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"AB", 2);
    const char*      prog = "proc { assert(1 == 1, \"never\"); local a = 7; }";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "a"), 7);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(assert_fails)(void)
{
    int              r    = TEST_SUCCEEDED;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"AB", 2);
    const char*      prog = "proc { assert(0, \"bad magic\"); }";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope == NULL);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// '&&' and '||' evaluate their right hand side only when it can change the
// result, so that a bound check can guard a call that would raise
int TEST(boolean_operators_short_circuit)(void)
{
    int              r    = TEST_SUCCEEDED;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"AB", 2);
    const char*      prog = "proc {"
                            "    local a = 0 && peek_u32(1000) == 0;"
                            "    local b = 1 || peek_u32(1000) == 0;"
                            "    local c = 2 && 3;"
                            "    local d = 0 || 0;"
                            "    local e = 0;"
                            "    if (remaining_size() >= 4 && peek(4, 4) == \"\") {"
                            "        e = 1;"
                            "    }"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "a"), 0);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "b"), 1);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "c"), 1);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "d"), 0);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "e"), 0);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// the right hand side is still evaluated, and can still raise, when the left
// one does not decide the result on its own
int TEST(boolean_operators_evaluate_rhs_when_needed)(void)
{
    int              r    = TEST_SUCCEEDED;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"AB", 2);
    const char*      prog = "proc { local a = 1 && peek_u32(1000) == 0; }";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope == NULL);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// fwd() with a negative value wrapped around and seeked *backwards*
int TEST(fwd_negative_is_rejected)(void)
{
    int              r    = TEST_SUCCEEDED;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"ABCDEFGH", 8);
    const char*      prog = "proc { seek(4); fwd(-2); }";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope == NULL);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// The arity of every builtin is checked in one place, before it runs
int TEST(builtin_arity_is_checked)(void)
{
    int              r   = TEST_SUCCEEDED;
    DummyFilebuffer* tfb = dummyfilebuffer_create((const u8_t*)"AB", 2);

    const char* bad_progs[] = {
        "proc { off(1); }",            // 0 parameters expected
        "proc { seek(); }",            // 1 expected, none given
        "proc { seek(0, 1); }",        // 1 expected, two given
        "proc { find(\"a\", 1, 2); }", // at most 2
        "proc { print(); }",           // at least 1
        "proc { min(1); }",            // at least 2
    };

    for (size_t i = 0; i < sizeof(bad_progs) / sizeof(bad_progs[0]); ++i) {
        Scope* scope =
            bhengine_interpreter_run_on_string(tfb->fb, bad_progs[i]);
        if (scope != NULL) {
            printf("[!] no exception for: %s\n", bad_progs[i]);
            Scope_free(scope);
            goto fail;
        }
    }

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// The same engines used by the 'cr', 'cs' and 'hh' commands
int TEST(integrity_builtins)(void)
{
    int              r    = TEST_SUCCEEDED;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"123456789", 9);
    const char*      prog = "proc {"
                            "    local a = crc(\"CRC-32/ISO-HDLC\");"
                            "    local b = checksum(\"ADLER-32\");"
                            "    local c = hash(\"md5\");"
                            "    local d = entropy();"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    // the check value every CRC catalogue lists for the "123456789" string
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "a"), 0xcbf43926);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "b"), 0x091e01de);

    int ok = 0;
    IS_TENGINE_STRING_EQ(ok, Scope_get_local(scope, "c"),
                         "25f9e794323b453885f5181f1b624d0b");
    ASSERT(ok);
    // 9 distinct bytes out of 9, i.e. the 3.165 that the 'e' command prints
    // for the same data (_log2 is an approximation, the exact value is 3.1699)
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "d"), 3165);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(integrity_builtins_unknown_name)(void)
{
    int              r   = TEST_SUCCEEDED;
    DummyFilebuffer* tfb = dummyfilebuffer_create((const u8_t*)"AB", 2);

    const char* bad_progs[] = {
        "proc { local a = crc(\"nosuch\"); }",
        "proc { local a = checksum(\"nosuch\"); }",
        "proc { local a = hash(\"nosuch\"); }",
        "proc { local a = crc(\"CRC-32/ISO-HDLC\", 99); }",
    };

    for (size_t i = 0; i < sizeof(bad_progs) / sizeof(bad_progs[0]); ++i) {
        Scope* scope =
            bhengine_interpreter_run_on_string(tfb->fb, bad_progs[i]);
        if (scope != NULL) {
            printf("[!] no exception for: %s\n", bad_progs[i]);
            Scope_free(scope);
            goto fail;
        }
    }

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// peek_uN reads a number without consuming it, honoring the endianness, and
// takes an optional relative offset (which may be negative)
int TEST(peek_numbers)(void)
{
    int              r   = TEST_SUCCEEDED;
    DummyFilebuffer* tfb = dummyfilebuffer_create(
        (const u8_t*)"\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    const char* prog = "proc {"
                       "    local a = peek_u8();"
                       "    local b = peek_u16();"
                       "    local c = peek_u32();"
                       "    big_endian();"
                       "    local d = peek_u16();"
                       "    local e = peek_u16(2);"
                       "    seek(4);"
                       "    local f = peek_u16(-4);"
                       "    local g = off();"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "a"), 0x01);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "b"), 0x0201);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "c"), 0x04030201);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "d"), 0x0102);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "e"), 0x0304);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "f"), 0x0102);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "g"), 4);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(peek_numbers_past_the_end)(void)
{
    int              r    = TEST_SUCCEEDED;
    DummyFilebuffer* tfb  = dummyfilebuffer_create((const u8_t*)"\x01\x02", 2);
    const char*      prog = "proc {"
                            "    local a = peek_u16();"
                            "    local b = peek_u32();"
                            "    seek(2);"
                            "    local c = peek_u8();"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "a"), 0x0201);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "b"), -1);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "c"), -1);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// peek(n, off) and the byte-oriented string builtins must survive NUL bytes,
// which is what binary data read with peek() is full of
int TEST(peek_and_slice_binary_data)(void)
{
    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)"\x00\x00\x00\x0dIHDR", 8);
    const char* prog = "proc {"
                       "    local a = peek(4, 4);"
                       "    local b = substr(peek(8), 4, 4);"
                       "    local c = index_of(peek(8), \"IHDR\");"
                       "    local d = starts_with(peek(8), \"\\x00\\x00\");"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    int ok = 0;
    IS_TENGINE_STRING_EQ(ok, Scope_get_local(scope, "a"), "IHDR");
    ASSERT(ok);
    ok = 0;
    IS_TENGINE_STRING_EQ(ok, Scope_get_local(scope, "b"), "IHDR");
    ASSERT(ok);
    ASSERT_TENGINE_SNUM_EQ(Scope_get_local(scope, "c"), 4);
    ASSERT_TENGINE_UNUM_EQ(Scope_get_local(scope, "d"), 1);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// max_array_print(n) truncates the *printed* elements of an array of structs,
// but every element is still parsed: `after` has to land past all five of them
int TEST(max_array_print_truncates_struct_array)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000  entries: [ \n"
        "                  [0]\n"
        "b+00000000          a: 30\n"
        "b+00000001          b: 31\n"
        "                  [1]\n"
        "b+00000002          a: 32\n"
        "b+00000003          b: 33\n"
        "                ... 3 more elements (5 in total) ]\n"
        "b+0000000a  after: 41";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)"0123456789A", 11);
    const char* prog = "struct entry_t { u8 a; u8 b; }"
                       "proc {"
                       "    max_array_print(2);"
                       "    entry_t entries[5];"
                       "    u8 after;"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// max_array_print(0) means "no limit", and the setting is restored when the
// struct that changed it ends, exactly like disable_print()
int TEST(max_array_print_scope_and_no_limit)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000    capped: \n"
        "b+00000000           els: [ \n"
        "                         [0]\n"
        "b+00000000                 v: 30\n"
        "                    ... 2 more elements (3 in total) ]\n"
        "b+00000003  uncapped: \n"
        "b+00000003           els: [ \n"
        "                         [0]\n"
        "b+00000003                 v: 33\n"
        "                         [1]\n"
        "b+00000004                 v: 34\n"
        "                         [2]\n"
        "b+00000005                 v: 35 ]";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)"0123456789A", 11);
    const char* prog = "struct el_t { u8 v; }"
                       "struct capped_t { max_array_print(1); el_t els[3]; }"
                       "struct uncapped_t { el_t els[3]; }"
                       "proc {"
                       "    capped_t capped;"
                       "    uncapped_t uncapped;"
                       "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// a truncated array of a builtin type must not swallow the values of the
// variables that follow it
int TEST(truncated_builtin_array_does_not_hide_next_var)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000   many: [ 0000, 0101, 0202, 0303, 0404, 0505, 0606, 0707, 0808, 0909, 0a0a, 0b0b, 0c0c, 0d0d, 0e0e, 0f0f, ... ]\n"
        "b+00000028  after: 15151414";
    // clang-format on

    int  r = TEST_SUCCEEDED;
    u8_t data[64];
    for (u32_t i = 0; i < sizeof(data); ++i)
        data[i] = (u8_t)(i / 2);
    DummyFilebuffer* tfb  = dummyfilebuffer_create(data, sizeof(data));
    const char*      prog = "proc {"
                            "    u16 many[20];"
                            "    u32 after;"
                            "}";

    Scope* scope = bhengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    if (scope)
        Scope_free(scope);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}
