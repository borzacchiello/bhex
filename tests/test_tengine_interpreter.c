#include <string.h>
#include <alloc.h>
#include <log.h>
#include <defs.h>

#include "dummy_filebuffer.h"
#include "../tengine/interpreter.h"
#include "../tengine/scope.h"
#include "elf_not_kitty.h"
#include "strbuilder.h"
#include "t.h"
#include "t_cmd_common.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

static void delete_interpreter(TEngineInterpreter* e)
{
    tengine_interpreter_deinit(e);
    bhex_free(e);
}

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

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 0);

end:
    delete_interpreter(e);
    return r;
}

int TEST(const_s8)(void)
{
    const char* prog = "proc { local a = 42s8; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    delete_interpreter(e);
    return r;
}

int TEST(const_s16)(void)
{
    const char* prog = "proc { local a = 42s16; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    delete_interpreter(e);
    return r;
}

int TEST(const_s32)(void)
{
    const char* prog = "proc { local a = 42s32; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    delete_interpreter(e);
    return r;
}

int TEST(const_u8)(void)
{
    const char* prog = "proc { local a = 16u8; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 16);

end:
    delete_interpreter(e);
    return r;
}

int TEST(const_u16)(void)
{
    const char* prog = "proc { local a = 300u16; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 300);

end:
    delete_interpreter(e);
    return r;
}

int TEST(const_u32)(void)
{
    const char* prog = "proc { local a = 100000u32; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 100000);

end:
    delete_interpreter(e);
    return r;
}

int TEST(const_u64)(void)
{
    const char* prog = "proc { local a = 1099511627537u64; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 1099511627537ull);

end:
    delete_interpreter(e);
    return r;
}

int TEST(hex_const)(void)
{
    const char* prog = "proc { local a = 0xdeadbeef; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 0xdeadbeef);

end:
    delete_interpreter(e);
    return r;
}

int TEST(hex_const_u8)(void)
{
    const char* prog = "proc { local a = 0xffu8; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 255);

end:
    delete_interpreter(e);
    return r;
}

int TEST(hex_const_u16)(void)
{
    const char* prog = "proc { local a = 0xfffu16; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 0xfff);

end:
    delete_interpreter(e);
    return r;
}

int TEST(hex_const_u32)(void)
{
    const char* prog = "proc { local a = 0xffffffu32; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 0xffffff);

end:
    delete_interpreter(e);
    return r;
}

int TEST(hex_const_u64)(void)
{
    const char* prog = "proc { local a = 0xffffffffffu64; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 0xffffffffffull);

end:
    delete_interpreter(e);
    return r;
}

int TEST(cast_u8)(void)
{
    const char* prog = "proc { "
                       "  local a = 0xffff;"
                       "  local b = u8(a);"
                       "}";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0xff);

end:
    delete_interpreter(e);
    return r;
}

int TEST(cast_i8)(void)
{
    const char* prog = "proc { "
                       "  local a = 0xffff;"
                       "  local b = i8(a);"
                       "}";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -1);

end:
    delete_interpreter(e);
    return r;
}

int TEST(const_limit_1)(void)
{
    const char* prog = "proc { local a = 0x7fffffffffffffff; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 0x7fffffffffffffffl);

end:
    delete_interpreter(e);
    return r;
}

int TEST(const_limit_2)(void)
{
    const char* prog = "proc { local a = -0x8000000000000000; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, -0x8000000000000000l);

end:
    delete_interpreter(e);
    return r;
}

int TEST(neg_const)(void)
{
    const char* prog = "proc { local a = -42; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, -42);

end:
    delete_interpreter(e);
    return r;
}

int TEST(str_const_1)(void)
{
    const char* prog = "proc { local a = \"ciao\"; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_STRING_EQ(r, v, "ciao");

end:
    delete_interpreter(e);
    return r;
}

int TEST(str_const_2)(void)
{
    const char* prog = "proc { local a = \"ciao\xde\xad\xbe\xef\"; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_STRING_EQ(r, v, "ciao\xde\xad\xbe\xef");

end:
    delete_interpreter(e);
    return r;
}

int TEST(eq_str)(void)
{
    const char* prog =
        "proc { local a = \"ciao\"; local b = \"ciao\"; local c = a == b; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "c");
    IS_TENGINE_UNUM_EQ(r, v, 1);

end:
    delete_interpreter(e);
    return r;
}

int TEST(sub)(void)
{
    const char* prog = "proc { local a = 4; local b = a - 5; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -1);

end:
    delete_interpreter(e);
    return r;
}

int TEST(add)(void)
{
    const char* prog = "proc { local a = 4; local b = a + 10; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 14);

end:
    delete_interpreter(e);
    return r;
}

int TEST(add_no_space)(void)
{
    const char* prog = "proc { local a = 4; local b = a+10; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 14);

end:
    delete_interpreter(e);
    return r;
}

int TEST(add_wrap_s8)(void)
{
    const char* prog = "proc { local a = 127s8; local b = a + 1s8; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -0x80);

end:
    delete_interpreter(e);
    return r;
}

int TEST(add_wrap_s16)(void)
{
    const char* prog = "proc { local a = 0x7fffs16; local b = a + 1s16; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -0x8000);

end:
    delete_interpreter(e);
    return r;
}

int TEST(add_wrap_s32)(void)
{
    const char* prog = "proc { local a = 0x7fffffffs32; local b = a + 1s32; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -0x80000000ll);

end:
    delete_interpreter(e);
    return r;
}

int TEST(add_wrap_u8)(void)
{
    const char* prog = "proc { local a = 250u8; local b = a + 6u8; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0);

end:
    delete_interpreter(e);
    return r;
}

int TEST(add_wrap_u16)(void)
{
    const char* prog = "proc { local a = 0xffffu16; local b = a + 1u16; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0);

end:
    delete_interpreter(e);
    return r;
}

int TEST(add_wrap_u32)(void)
{
    const char* prog = "proc { local a = 0xffffffffu32; local b = a + 1u32; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0);

end:
    delete_interpreter(e);
    return r;
}

int TEST(add_wrap_u64)(void)
{
    const char* prog =
        "proc { local a = 0xffffffffffffffffu64; local b = a + 1u64; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0);

end:
    delete_interpreter(e);
    return r;
}

int TEST(mul)(void)
{
    const char* prog = "proc { local a = 4; local b = a * 10; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 40);

end:
    delete_interpreter(e);
    return r;
}

int TEST(div_1)(void)
{
    const char* prog = "proc { local a = 44; local b = a / 10; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 4);

end:
    delete_interpreter(e);
    return r;
}

int TEST(div_2)(void)
{
    const char* prog = "proc { local a = 16; local b = a / 4; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 4);

end:
    delete_interpreter(e);
    return r;
}

int TEST(mod_1)(void)
{
    const char* prog = "proc { local a = 43; local b = a % 10; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 3);

end:
    delete_interpreter(e);
    return r;
}

int TEST(mod_2)(void)
{
    const char* prog = "proc { local a = 16; local b = a % 4; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0);

end:
    delete_interpreter(e);
    return r;
}

int TEST(and)(void)
{
    const char* prog = "proc { local a = 0xffff; local b = a & 0xf0f0; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0xf0f0);

end:
    delete_interpreter(e);
    return r;
}

int TEST(or)(void)
{
    const char* prog = "proc { local a = 0xf0f0; local b = a | 0x0f0f; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0xffff);

end:
    delete_interpreter(e);
    return r;
}

int TEST(xor)(void)
{
    const char* prog = "proc { local a = 0xff; local b = a ^ 0xf0; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0x0f);

end:
    delete_interpreter(e);
    return r;
}

int TEST(neg_1)(void)
{
    const char* prog = "proc { local a = -(42+16); }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, -58);

end:
    delete_interpreter(e);
    return r;
}

int TEST(neg_2)(void)
{
    const char* prog = "proc { local a = 43 + -(42+16); }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, -58 + 43);

end:
    delete_interpreter(e);
    return r;
}

int TEST(band_1)(void)
{
    const char* prog = "proc {"
                       "  local a = 1;"
                       "  local b = 0;"
                       "  local c = a && b;"
                       "}";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "c");
    IS_TENGINE_BOOL_EQ(r, v, 0);

end:
    delete_interpreter(e);
    return r;
}

int TEST(band_2)(void)
{
    const char* prog = "proc {"
                       "  local a = 1;"
                       "  local b = 1;"
                       "  local c = a && b;"
                       "}";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "c");
    IS_TENGINE_BOOL_EQ(r, v, 1);

end:
    delete_interpreter(e);
    return r;
}

int TEST(bor_1)(void)
{
    const char* prog = "proc {"
                       "  local a = 1;"
                       "  local b = 0;"
                       "  local c = a || b;"
                       "}";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "c");
    IS_TENGINE_BOOL_EQ(r, v, 1);

end:
    delete_interpreter(e);
    return r;
}

int TEST(bor_2)(void)
{
    const char* prog = "proc {"
                       "  local a = 0;"
                       "  local b = 0;"
                       "  local c = a || b;"
                       "}";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "c");
    IS_TENGINE_BOOL_EQ(r, v, 0);

end:
    delete_interpreter(e);
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

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    delete_interpreter(e);
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

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    delete_interpreter(e);
    return r;
}

int TEST(precedence_op_1)(void)
{
    const char* prog = "proc { local a = 4 + 3 * 8; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r     = 0;
    TEngineValue* v     = Scope_get_local(e->proc_scope, "a");
    char*         str_v = TEngineValue_tostring(v, 0);
    bhex_free(str_v);
    IS_TENGINE_SNUM_EQ(r, v, 28);

end:
    delete_interpreter(e);
    return r;
}

int TEST(precedence_op_2)(void)
{
    const char* prog = "proc { local a = 4 - 3 * 8; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, -20);

end:
    delete_interpreter(e);
    return r;
}

int TEST(precedence_op_3)(void)
{
    const char* prog = "proc { local a = 4 - 3 + 3 * 2; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 7);

end:
    delete_interpreter(e);
    return r;
}

int TEST(precedence_op_4)(void)
{
    const char* prog = "proc { local a = 4 * 3 - 1; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 11);

end:
    delete_interpreter(e);
    return r;
}

int TEST(precedence_op_5)(void)
{
    const char* prog = "proc { local a = (4 + 3) * 8; }";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r     = 0;
    TEngineValue* v     = Scope_get_local(e->proc_scope, "a");
    char*         str_v = TEngineValue_tostring(v, 0);
    bhex_free(str_v);
    IS_TENGINE_SNUM_EQ(r, v, 56);

end:
    delete_interpreter(e);
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

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 45);

end:
    delete_interpreter(e);
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

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 3);

end:
    delete_interpreter(e);
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

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 46);

end:
    delete_interpreter(e);
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

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 3);

end:
    delete_interpreter(e);
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

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 47);

end:
    delete_interpreter(e);
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

    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 90);

end:
    delete_interpreter(e);
    return r;
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

    TEngineInterpreter* e = tengine_interpreter_run_on_string(tfb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 'B');

end:
    if (e)
        delete_interpreter(e);
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

    TEngineInterpreter* e = tengine_interpreter_run_on_string(tfb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* va = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, va, ((u32_t)'B' << 8) | 'A');

    TEngineValue* vb = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_UNUM_EQ(r, vb, 'C');

end:
    if (e)
        delete_interpreter(e);
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

    TEngineInterpreter* e = tengine_interpreter_run_on_string(tfb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, ((u32_t)'A' << 8) | 'B');

end:
    if (e)
        delete_interpreter(e);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(array_4)(void)
{
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

    TEngineInterpreter* e = tengine_interpreter_run_on_string(tfb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 'E');

end:
    if (e)
        delete_interpreter(e);
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(array_5)(void)
{
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
                       "    disable_print();"
                       "    AStruct v;"
                       "    local   a = v.n4;"
                       "}";

    TEngineInterpreter* e = tengine_interpreter_run_on_string(tfb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 'K');

end:
    if (e)
        delete_interpreter(e);
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

    TEngineInterpreter* e = tengine_interpreter_run_on_string(tfb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 0x08048074);

end:
    if (e)
        delete_interpreter(e);
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

    TEngineInterpreter* e = tengine_interpreter_run_on_string(tfb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_STRING_EQ(r, v, "ciao");

end:
    if (e)
        delete_interpreter(e);
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

    int                 r = 0;
    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    if (e)
        delete_interpreter(e);
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

    int                 r = 0;
    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 84);

end:
    if (e)
        delete_interpreter(e);
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

    int                 r = 0;
    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 42 * 3);

end:
    if (e)
        delete_interpreter(e);
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

    int                 r = 0;
    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 42 * 3);

end:
    if (e)
        delete_interpreter(e);
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

    int                 r = 0;
    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 42 * 3);

end:
    if (e)
        delete_interpreter(e);
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

    int                 r = 0;
    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 42 * 3);

end:
    if (e)
        delete_interpreter(e);
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

    int                 r = 0;
    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 42 + 44 + 16);

end:
    if (e)
        delete_interpreter(e);
    return r;
}

int TEST(syntax_error)(void)
{
    // clang-format off
    const char* expected =
        "[  ERROR  ] [tengine lexer] unknown token\n"
        "[  ERROR  ] [tengine parser] syntax error @ line 7 [near token '@']\n"
        "[  ERROR  ] parsing failed\n";
    // clang-format on

    // just in case
    bhex_free(strbuilder_reset(err_sb));

    const char* prog = "@,,";

    int                 r = TEST_FAILED;
    TEngineInterpreter* e = tengine_interpreter_run_on_string(elf_fb->fb, prog);
    if (e != NULL)
        goto end;

    char* out = strbuilder_reset(err_sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    if (e)
        delete_interpreter(e);
    return r;
}
