#include <string.h>
#include <alloc.h>
#include <log.h>
#include <defs.h>

#include "data/big_buffers.h"
#include "../tengine/interpreter.h"
#include "../tengine/scope.h"
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

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(const_s8)(void)
{
    const char* prog = "proc { local a = 42s8; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    Scope_free(scope);
    return r;
}

int TEST(const_s16)(void)
{
    const char* prog = "proc { local a = 42s16; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    Scope_free(scope);
    return r;
}

int TEST(const_s32)(void)
{
    const char* prog = "proc { local a = 42s32; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    Scope_free(scope);
    return r;
}

int TEST(const_u8)(void)
{
    const char* prog = "proc { local a = 16u8; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 16);

end:
    Scope_free(scope);
    return r;
}

int TEST(const_u16)(void)
{
    const char* prog = "proc { local a = 300u16; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 300);

end:
    Scope_free(scope);
    return r;
}

int TEST(const_u32)(void)
{
    const char* prog = "proc { local a = 100000u32; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 100000);

end:
    Scope_free(scope);
    return r;
}

int TEST(const_u64)(void)
{
    const char* prog = "proc { local a = 1099511627537u64; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 1099511627537ull);

end:
    Scope_free(scope);
    return r;
}

int TEST(hex_const)(void)
{
    const char* prog = "proc { local a = 0xdeadbeef; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 0xdeadbeef);

end:
    Scope_free(scope);
    return r;
}

int TEST(hex_const_u8)(void)
{
    const char* prog = "proc { local a = 0xffu8; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 255);

end:
    Scope_free(scope);
    return r;
}

int TEST(hex_const_u16)(void)
{
    const char* prog = "proc { local a = 0xfffu16; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 0xfff);

end:
    Scope_free(scope);
    return r;
}

int TEST(hex_const_u32)(void)
{
    const char* prog = "proc { local a = 0xffffffu32; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 0xffffff);

end:
    Scope_free(scope);
    return r;
}

int TEST(hex_const_u64)(void)
{
    const char* prog = "proc { local a = 0xffffffffffu64; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
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

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
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

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -1);

end:
    Scope_free(scope);
    return r;
}

int TEST(const_limit_1)(void)
{
    const char* prog = "proc { local a = 0x7fffffffffffffff; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 0x7fffffffffffffffl);

end:
    Scope_free(scope);
    return r;
}

int TEST(const_limit_2)(void)
{
    const char* prog = "proc { local a = -0x7fffffffffffffff-1; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, (int64_t)-0x8000000000000000l);

end:
    Scope_free(scope);
    return r;
}

int TEST(neg_const)(void)
{
    const char* prog = "proc { local a = -42; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, -42);

end:
    Scope_free(scope);
    return r;
}

int TEST(str_const_1)(void)
{
    const char* prog = "proc { local a = \"ciao\"; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_STRING_EQ(r, v, "ciao");

end:
    Scope_free(scope);
    return r;
}

int TEST(str_const_2)(void)
{
    const char* prog = "proc { local a = \"ciao\xde\xad\xbe\xef\"; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_STRING_EQ(r, v, "ciao\xde\xad\xbe\xef");

end:
    Scope_free(scope);
    return r;
}

int TEST(eq_str)(void)
{
    const char* prog =
        "proc { local a = \"ciao\"; local b = \"ciao\"; local c = a == b; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "c");
    IS_TENGINE_UNUM_EQ(r, v, 1);

end:
    Scope_free(scope);
    return r;
}

int TEST(sub)(void)
{
    const char* prog = "proc { local a = 4; local b = a - 5; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -1);

end:
    Scope_free(scope);
    return r;
}

int TEST(sub_no_space)(void)
{
    const char* prog = "proc { local a = 4; local b = a-5; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -1);

end:
    print_err_sb();
    Scope_free(scope);
    return r;
}

int TEST(add)(void)
{
    const char* prog = "proc { local a = 4; local b = a + 10; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 14);

end:
    Scope_free(scope);
    return r;
}

int TEST(add_no_space)(void)
{
    const char* prog = "proc { local a = 4; local b = a+10; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 14);

end:
    Scope_free(scope);
    return r;
}

int TEST(add_wrap_s8)(void)
{
    const char* prog = "proc { local a = 127s8; local b = a + 1s8; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -0x80);

end:
    Scope_free(scope);
    return r;
}

int TEST(add_wrap_s16)(void)
{
    const char* prog = "proc { local a = 0x7fffs16; local b = a + 1s16; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -0x8000);

end:
    Scope_free(scope);
    return r;
}

int TEST(add_wrap_s32)(void)
{
    const char* prog = "proc { local a = 0x7fffffffs32; local b = a + 1s32; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -0x80000000ll);

end:
    Scope_free(scope);
    return r;
}

int TEST(add_wrap_u8)(void)
{
    const char* prog = "proc { local a = 250u8; local b = a + 6u8; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(add_wrap_u16)(void)
{
    const char* prog = "proc { local a = 0xffffu16; local b = a + 1u16; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(add_wrap_u32)(void)
{
    const char* prog = "proc { local a = 0xffffffffu32; local b = a + 1u32; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(add_wrap_u64)(void)
{
    const char* prog =
        "proc { local a = 0xffffffffffffffffu64; local b = a + 1u64; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(mul)(void)
{
    const char* prog = "proc { local a = 4; local b = a * 10; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 40);

end:
    Scope_free(scope);
    return r;
}

int TEST(div_1)(void)
{
    const char* prog = "proc { local a = 44; local b = a / 10; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 4);

end:
    Scope_free(scope);
    return r;
}

int TEST(div_2)(void)
{
    const char* prog = "proc { local a = 16; local b = a / 4; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 4);

end:
    Scope_free(scope);
    return r;
}

int TEST(mod_1)(void)
{
    const char* prog = "proc { local a = 43; local b = a % 10; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 3);

end:
    Scope_free(scope);
    return r;
}

int TEST(mod_2)(void)
{
    const char* prog = "proc { local a = 16; local b = a % 4; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(and)(void)
{
    const char* prog = "proc { local a = 0xffff; local b = a & 0xf0f0; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0xf0f0);

end:
    Scope_free(scope);
    return r;
}

int TEST(or)(void)
{
    const char* prog = "proc { local a = 0xf0f0; local b = a | 0x0f0f; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0xffff);

end:
    Scope_free(scope);
    return r;
}

int TEST(xor)(void)
{
    const char* prog = "proc { local a = 0xff; local b = a ^ 0xf0; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0x0f);

end:
    Scope_free(scope);
    return r;
}

int TEST(shr_1)(void)
{
    const char* prog = "proc { local a = 0xff; local b = a >> 1; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0xff >> 1);

end:
    Scope_free(scope);
    return r;
}

int TEST(shr_2)(void)
{
    const char* prog = "proc { local a = 0xff; local b = a >> 2; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0xff >> 2);

end:
    Scope_free(scope);
    return r;
}

int TEST(shr_3)(void)
{
    const char* prog = "proc { local a = 0xff; local b = a >> 10; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(shl_1)(void)
{
    const char* prog = "proc { local a = 1; local b = a << 1; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 1 << 1);

end:
    Scope_free(scope);
    return r;
}

int TEST(shl_2)(void)
{
    const char* prog = "proc { local a = 1; local b = a << 2; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 1 << 2);

end:
    Scope_free(scope);
    return r;
}

int TEST(shl_3)(void)
{
    const char* prog = "proc { local a = 1u8; local b = a << 10u8; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(neg_1)(void)
{
    const char* prog = "proc { local a = -(42+16); }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, -58);

end:
    Scope_free(scope);
    return r;
}

int TEST(neg_2)(void)
{
    const char* prog = "proc { local a = 43 + -(42+16); }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
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

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "c");
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

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "c");
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

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "c");
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

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "c");
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

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
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

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
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

    Scope* scope = tengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "res");
    IS_TENGINE_SNUM_EQ(r, v, 47);

end:
    dummyfilebuffer_destroy(tfb);
    Scope_free(scope);
    return r;
}

int TEST(precedence_op_1)(void)
{
    const char* prog = "proc { local a = 4 + 3 * 8; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r     = 0;
    TEngineValue* v     = Scope_get_local(scope, "a");
    char*         str_v = TEngineValue_tostring(v, 0);
    bhex_free(str_v);
    IS_TENGINE_SNUM_EQ(r, v, 28);

end:
    Scope_free(scope);
    return r;
}

int TEST(precedence_op_2)(void)
{
    const char* prog = "proc { local a = 4 - 3 * 8; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, -20);

end:
    Scope_free(scope);
    return r;
}

int TEST(precedence_op_3)(void)
{
    const char* prog = "proc { local a = 4 - 3 + 3 * 2; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 7);

end:
    Scope_free(scope);
    return r;
}

int TEST(precedence_op_4)(void)
{
    const char* prog = "proc { local a = 4 * 3 - 1; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 11);

end:
    Scope_free(scope);
    return r;
}

int TEST(precedence_op_5)(void)
{
    const char* prog = "proc { local a = (4 + 3) * 8; }";

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r     = 0;
    TEngineValue* v     = Scope_get_local(scope, "a");
    char*         str_v = TEngineValue_tostring(v, 0);
    bhex_free(str_v);
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

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
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

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
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

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
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

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
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

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 47);

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

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
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

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
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

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 6);

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

    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0);

end:
    Scope_free(scope);
    return r;
}

int TEST(invalid_break)(void)
{
    // clang-format off
    const char* expected =
        "[  ERROR  ] Exception @ line 1, col 10 > unexpected break\n";
    // clang-format on

    const char* prog = "proc { "
                       "  break;"
                       "}";

    int    r     = 1;
    char*  out   = NULL;
    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
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

    Scope* scope = tengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(scope, "a");
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

    Scope* scope = tengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    TEngineValue* va = Scope_get_local(scope, "a");
    IS_TENGINE_UNUM_EQ(r, va, ((u32_t)'B' << 8) | 'A');

    TEngineValue* vb = Scope_get_local(scope, "b");
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
                       "    endianess_be();"
                       "    u16 buf[5];"
                       "    local a = buf[4];"
                       "}";

    Scope* scope = tengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(scope, "a");
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
        "\n"
        "b+00000000    data: [ \n"
        "               [0]\n"
        "b+00000000          n1: 41\n"
        "b+00000001          n2: 42\n"
        "b+00000002          n3: 43\n"
        "               [1]\n"
        "b+00000003          n1: 44\n"
        "b+00000004          n2: 45\n"
        "b+00000005          n3: 46 ]";
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

    Scope* scope = tengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(scope, "a");
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
        "\n"
        "b+00000000        v: \n"
        "b+00000000           n1: 41\n"
        "b+00000001           n2: 42\n"
        "b+00000002           n3: [ 4443, 4645, 4847, 4a49 ]\n"
        "b+0000000a           n4: 4b";
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

    Scope* scope = tengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(scope, "a");
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

    Scope* scope = tengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(scope, "a");
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
        "\n"    
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

    Scope* scope = tengine_interpreter_run_on_string(tfb->fb, prog);
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

    Scope* scope = tengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(scope, "a");
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
                            "    local a = strip(\"  ciao  \t\n\");"
                            "}";

    Scope* scope = tengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(scope, "a");
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
                            "    local a = strip(\"  cia\x01o  \t\n\");"
                            "}";

    Scope* scope = tengine_interpreter_run_on_string(tfb->fb, prog);
    if (scope == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(scope, "a");
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
    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(scope, "a");
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
    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(scope, "a");
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
    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(scope, "a");
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
    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(scope, "a");
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
    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(scope, "a");
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
    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(scope, "a");
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
    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (scope == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(scope, "a");
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
    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
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
        "[  ERROR  ] Exception @ line 1, col 27 > mul undefined for types unum and string\n";
    // clang-format on

    const char* prog = "proc { local a = 1u8 * \"a\"; }";

    int    r     = TEST_FAILED;
    Scope* scope = tengine_interpreter_run_on_string(elf_fb->fb, prog);
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

    Scope* scope = tengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    TEngineValue* v = Scope_get_local(scope, "a");
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

    Scope* scope = tengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    TEngineValue* v = Scope_get_local(scope, "a");
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

    Scope* scope = tengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    TEngineValue* v = Scope_get_local(scope, "a");
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

    Scope* scope = tengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    TEngineValue* v = Scope_get_local(scope, "a");
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

    Scope* scope = tengine_interpreter_run_on_string(tfb->fb, prog);
    ASSERT(scope != NULL);

    TEngineValue* va = Scope_get_local(scope, "a");
    ASSERT_TENGINE_UNUM_EQ(va, 1);
    TEngineValue* vb = Scope_get_local(scope, "b");
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
