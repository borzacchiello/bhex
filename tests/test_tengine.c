#include "defs.h"
#include "test.h"

#include <string.h>
#include <alloc.h>
#include <log.h>

#include "elf_not_kitty.h"
#include "test_filebuffer.h"
#include "../tengine/scope.h"
#include "../tengine/tengine.h"

FileBuffer* fb;

__attribute__((constructor)) static void init_fb()
{
    fb = filebuffer_create("/bin/bash", 1);
    if (!fb)
        panic("unable to open /bin/bash");
}

static void delete_tengine(TEngine* e)
{
    TEngine_deinit(e);
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

static int test_const()
{
    char* prog = "proc { local a = 0; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 0);

end:
    delete_tengine(e);
    return r;
}

static int test_const_s8()
{
    char* prog = "proc { local a = 42s8; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    delete_tengine(e);
    return r;
}

static int test_const_s16()
{
    char* prog = "proc { local a = 42s16; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    delete_tengine(e);
    return r;
}

static int test_const_s32()
{
    char* prog = "proc { local a = 42s32; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    delete_tengine(e);
    return r;
}

static int test_const_u8()
{
    char* prog = "proc { local a = 16u8; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 16);

end:
    delete_tengine(e);
    return r;
}

static int test_const_u16()
{
    char* prog = "proc { local a = 300u16; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 300);

end:
    delete_tengine(e);
    return r;
}

static int test_const_u32()
{
    char* prog = "proc { local a = 100000u32; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 100000);

end:
    delete_tengine(e);
    return r;
}

static int test_const_u64()
{
    char* prog = "proc { local a = 1099511627537u64; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 1099511627537);

end:
    delete_tengine(e);
    return r;
}

static int test_hex_const()
{
    char* prog = "proc { local a = 0xdeadbeef; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 0xdeadbeef);

end:
    delete_tengine(e);
    return r;
}

static int test_hex_const_u8()
{
    char* prog = "proc { local a = 0xffu8; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 255);

end:
    delete_tengine(e);
    return r;
}

static int test_hex_const_u16()
{
    char* prog = "proc { local a = 0xfffu16; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 0xfff);

end:
    delete_tengine(e);
    return r;
}

static int test_hex_const_u32()
{
    char* prog = "proc { local a = 0xffffffu32; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 0xffffff);

end:
    delete_tengine(e);
    return r;
}

static int test_hex_const_u64()
{
    char* prog = "proc { local a = 0xffffffffffu64; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 0xffffffffff);

end:
    delete_tengine(e);
    return r;
}

static int test_cast_u8()
{
    char* prog = "proc { "
                 "  local a = 0xffff;"
                 "  local b = u8(a);"
                 "}";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0xff);

end:
    delete_tengine(e);
    return r;
}

static int test_cast_i8()
{
    char* prog = "proc { "
                 "  local a = 0xffff;"
                 "  local b = i8(a);"
                 "}";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -1);

end:
    delete_tengine(e);
    return r;
}

static int test_const_limit_1()
{
    char* prog = "proc { local a = 0x7fffffffffffffff; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 0x7fffffffffffffffl);

end:
    delete_tengine(e);
    return r;
}

static int test_const_limit_2()
{
    char* prog = "proc { local a = -0x8000000000000000; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, -0x8000000000000000l);

end:
    delete_tengine(e);
    return r;
}

static int test_neg_const()
{
    char* prog = "proc { local a = -42; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, -42);

end:
    delete_tengine(e);
    return r;
}

static int test_str_const_1()
{
    char* prog = "proc { local a = \"ciao\"; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_STRING_EQ(r, v, "ciao");

end:
    delete_tengine(e);
    return r;
}

static int test_str_const_2()
{
    char* prog = "proc { local a = \"ciao\xde\xad\xbe\xef\"; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_STRING_EQ(r, v, "ciao\xde\xad\xbe\xef");

end:
    delete_tengine(e);
    return r;
}

static int test_eq_str()
{
    char* prog =
        "proc { local a = \"ciao\"; local b = \"ciao\"; local c = a == b; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "c");
    IS_TENGINE_UNUM_EQ(r, v, 1);

end:
    delete_tengine(e);
    return r;
}

static int test_sub()
{
    char* prog = "proc { local a = 4; local b = a - 5; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -1);

end:
    delete_tengine(e);
    return r;
}

static int test_add()
{
    char* prog = "proc { local a = 4; local b = a + 10; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 14);

end:
    delete_tengine(e);
    return r;
}

static int test_add_no_space()
{
    char* prog = "proc { local a = 4; local b = a+10; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 14);

end:
    delete_tengine(e);
    return r;
}

static int test_add_wrap_s8()
{
    char* prog = "proc { local a = 127s8; local b = a + 1s8; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -0x80);

end:
    delete_tengine(e);
    return r;
}

static int test_add_wrap_s16()
{
    char* prog = "proc { local a = 0x7fffs16; local b = a + 1s16; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -0x8000);

end:
    delete_tengine(e);
    return r;
}

static int test_add_wrap_s32()
{
    char* prog = "proc { local a = 0x7fffffffs32; local b = a + 1s32; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -0x80000000l);

end:
    delete_tengine(e);
    return r;
}

static int test_add_wrap_u8()
{
    char* prog = "proc { local a = 250u8; local b = a + 6u8; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0);

end:
    delete_tengine(e);
    return r;
}

static int test_add_wrap_u16()
{
    char* prog = "proc { local a = 0xffffu16; local b = a + 1u16; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0);

end:
    delete_tengine(e);
    return r;
}

static int test_add_wrap_u32()
{
    char* prog = "proc { local a = 0xffffffffu32; local b = a + 1u32; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0);

end:
    delete_tengine(e);
    return r;
}

static int test_add_wrap_u64()
{
    char* prog =
        "proc { local a = 0xffffffffffffffffu64; local b = a + 1u64; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_UNUM_EQ(r, v, 0);

end:
    delete_tengine(e);
    return r;
}

static int test_mul()
{
    char* prog = "proc { local a = 4; local b = a * 10; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 40);

end:
    delete_tengine(e);
    return r;
}

static int test_div_1()
{
    char* prog = "proc { local a = 44; local b = a / 10; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 4);

end:
    delete_tengine(e);
    return r;
}

static int test_div_2()
{
    char* prog = "proc { local a = 16; local b = a / 4; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 4);

end:
    delete_tengine(e);
    return r;
}

static int test_mod_1()
{
    char* prog = "proc { local a = 43; local b = a % 10; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 3);

end:
    delete_tengine(e);
    return r;
}

static int test_mod_2()
{
    char* prog = "proc { local a = 16; local b = a % 4; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0);

end:
    delete_tengine(e);
    return r;
}

static int test_and()
{
    char* prog = "proc { local a = 0xffff; local b = a & 0xf0f0; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0xf0f0);

end:
    delete_tengine(e);
    return r;
}

static int test_or()
{
    char* prog = "proc { local a = 0xf0f0; local b = a | 0x0f0f; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0xffff);

end:
    delete_tengine(e);
    return r;
}

static int test_xor()
{
    char* prog = "proc { local a = 0xff; local b = a ^ 0xf0; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 0x0f);

end:
    delete_tengine(e);
    return r;
}

static int test_neg_1()
{
    char* prog = "proc { local a = -(42+16); }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, -58);

end:
    delete_tengine(e);
    return r;
}

static int test_neg_2()
{
    char* prog = "proc { local a = 43 + -(42+16); }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, -58 + 43);

end:
    delete_tengine(e);
    return r;
}

static int test_band_1()
{
    char* prog = "proc {"
                 "  local a = 1;"
                 "  local b = 0;"
                 "  local c = a && b;"
                 "}";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "c");
    IS_TENGINE_BOOL_EQ(r, v, 0);

end:
    delete_tengine(e);
    return r;
}

static int test_band_2()
{
    char* prog = "proc {"
                 "  local a = 1;"
                 "  local b = 1;"
                 "  local c = a && b;"
                 "}";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "c");
    IS_TENGINE_BOOL_EQ(r, v, 1);

end:
    delete_tengine(e);
    return r;
}

static int test_bor_1()
{
    char* prog = "proc {"
                 "  local a = 1;"
                 "  local b = 0;"
                 "  local c = a || b;"
                 "}";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "c");
    IS_TENGINE_BOOL_EQ(r, v, 1);

end:
    delete_tengine(e);
    return r;
}

static int test_bor_2()
{
    char* prog = "proc {"
                 "  local a = 0;"
                 "  local b = 0;"
                 "  local c = a || b;"
                 "}";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "c");
    IS_TENGINE_BOOL_EQ(r, v, 0);

end:
    delete_tengine(e);
    return r;
}

static int test_bneq_1()
{
    char* prog = "proc {"
                 "  local a = 0;"
                 "  local b = 1;"
                 "  if (a != 42) {"
                 "    b = b + 41;"
                 "  }"
                 "}";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    delete_tengine(e);
    return r;
}

static int test_bnot_1()
{
    char* prog = "proc {"
                 "  local a = 0;"
                 "  local b = 1;"
                 "  if (!(a == 42)) {"
                 "    b = b + 41;"
                 "  }"
                 "}";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    delete_tengine(e);
    return r;
}

static int test_precedence_op_1()
{
    char* prog = "proc { local a = 4 + 3 * 8; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r     = 0;
    TEngineValue* v     = Scope_get_local(e->proc_scope, "a");
    char*         str_v = TEngineValue_tostring(v, 0);
    bhex_free(str_v);
    IS_TENGINE_SNUM_EQ(r, v, 28);

end:
    delete_tengine(e);
    return r;
}

static int test_precedence_op_2()
{
    char* prog = "proc { local a = 4 - 3 * 8; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, -20);

end:
    delete_tengine(e);
    return r;
}

static int test_precedence_op_3()
{
    char* prog = "proc { local a = 4 - 3 + 3 * 2; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 7);

end:
    delete_tengine(e);
    return r;
}

static int test_precedence_op_4()
{
    char* prog = "proc { local a = 4 * 3 - 1; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 11);

end:
    delete_tengine(e);
    return r;
}

static int test_precedence_op_5()
{
    char* prog = "proc { local a = (4 + 3) * 8; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r     = 0;
    TEngineValue* v     = Scope_get_local(e->proc_scope, "a");
    char*         str_v = TEngineValue_tostring(v, 0);
    bhex_free(str_v);
    IS_TENGINE_SNUM_EQ(r, v, 56);

end:
    delete_tengine(e);
    return r;
}

static int test_if_1()
{
    char* prog = "proc {"
                 "  local a = 4;"
                 "  local b = 3;"
                 "  if (a - 3 > 0) {"
                 "    b = b + 42;"
                 "  }"
                 "}";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 45);

end:
    delete_tengine(e);
    return r;
}

static int test_if_2()
{
    char* prog = "proc {"
                 "  local a = 4;"
                 "  local b = 3;"
                 "  if (a - 5 > 0) {"
                 "    b = b + 42;"
                 "  }"
                 "}";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 3);

end:
    delete_tengine(e);
    return r;
}

static int test_if_3()
{
    char* prog = "proc {"
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

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 46);

end:
    delete_tengine(e);
    return r;
}

static int test_if_4()
{
    char* prog = "proc { "
                 "  local a = 8;"
                 "  local b = 3;"
                 "  if (a == 1) {"
                 "    b = b + 42;"
                 "  } elif (a == 4) {"
                 "    b = b + 43;"
                 "  }"
                 "}";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 3);

end:
    delete_tengine(e);
    return r;
}

static int test_if_5()
{
    char* prog = "proc { "
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

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 47);

end:
    delete_tengine(e);
    return r;
}

static int test_while_1()
{
    char* prog = "proc { "
                 "  local a = 0;"
                 "  local b = 0;"
                 "  while (a < 10) {"
                 "    b = b + (2*a);"
                 "    a = a + 1;"
                 "  }"
                 "}";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, 90);

end:
    delete_tengine(e);
    return r;
}

static int test_array_1()
{
    int             r    = 0;
    TestFilebuffer* tfb  = testfilebuffer_create((const u8_t*)"AAAAAAAAAB", 10);
    char*           prog = "proc {"
                           "    disable_print();"
                           "    u8 buf[10];"
                           "    local a = buf[9];"
                           "}";

    TEngine* e = TEngine_run_on_string(tfb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 'B');

end:
    if (e)
        delete_tengine(e);
    testfilebuffer_destroy(tfb);
    return r;
}

static int test_array_2()
{
    int             r    = 0;
    TestFilebuffer* tfb  = testfilebuffer_create((const u8_t*)"AAAAAAAAAB", 10);
    char*           prog = "proc {"
                           "    disable_print();"
                           "    u16 buf[5];"
                           "    local a = buf[4];"
                           "}";

    TEngine* e = TEngine_run_on_string(tfb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, ((u32_t)'B' << 8) | 'A');

end:
    if (e)
        delete_tengine(e);
    testfilebuffer_destroy(tfb);
    return r;
}

static int test_array_3()
{
    int             r    = 0;
    TestFilebuffer* tfb  = testfilebuffer_create((const u8_t*)"AAAAAAAAAB", 10);
    char*           prog = "proc {"
                           "    disable_print();"
                           "    endianess_be();"
                           "    u16 buf[5];"
                           "    local a = buf[4];"
                           "}";

    TEngine* e = TEngine_run_on_string(tfb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, ((u32_t)'A' << 8) | 'B');

end:
    if (e)
        delete_tengine(e);
    testfilebuffer_destroy(tfb);
    return r;
}

static int test_array_4()
{
    int             r    = 0;
    TestFilebuffer* tfb  = testfilebuffer_create((const u8_t*)"ABCDEF", 6);
    char*           prog = "struct Triple {"
                           "   u8 n1;"
                           "   u8 n2;"
                           "   u8 n3;"
                           "}\n"
                           "proc {"
                           "    disable_print();"
                           "    Triple data[2];"
                           "    local  a = data[1].n2;"
                           "}";

    TEngine* e = TEngine_run_on_string(tfb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 'E');

end:
    if (e)
        delete_tengine(e);
    testfilebuffer_destroy(tfb);
    return r;
}

static int test_elf_1()
{
    int             r = 0;
    TestFilebuffer* tfb =
        testfilebuffer_create(elf_not_kitty, sizeof(elf_not_kitty));
    char* prog = "struct ElfIdent {"
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

    TEngine* e = TEngine_run_on_string(tfb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 0x08048074);

end:
    if (e)
        delete_tengine(e);
    testfilebuffer_destroy(tfb);
    return r;
}

static int test_strip()
{
    int             r    = 0;
    TestFilebuffer* tfb  = testfilebuffer_create((const u8_t*)"ABCDEF", 6);
    char*           prog = "proc {"
                           "    disable_print();"
                           "    local a = strip(\"  ciao  \t\n\");"
                           "}";

    TEngine* e = TEngine_run_on_string(tfb->fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_STRING_EQ(r, v, "ciao");

end:
    if (e)
        delete_tengine(e);
    testfilebuffer_destroy(tfb);
    return r;
}

static int test_fn_1()
{

    char* prog = "fn test() {"
                 "    result = 42;"
                 "}"
                 "proc {"
                 "    disable_print();"
                 "    local a = test();"
                 "}";

    int      r = 0;
    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_SNUM_EQ(r, v, 42);

end:
    if (e)
        delete_tengine(e);
    return r;
}

static int test_fn_2()
{

    char* prog = "fn test(a) {"
                 "    result = u32(42 + a);"
                 "}"
                 "proc {"
                 "    disable_print();"
                 "    local a = test(42);"
                 "}";

    int      r = 0;
    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 84);

end:
    if (e)
        delete_tengine(e);
    return r;
}

static int test_fn_3()
{

    char* prog = "fn test(a, b) {"
                 "    result = u32(42 + a + b);"
                 "}"
                 "proc {"
                 "    disable_print();"
                 "    local a = test(42, 42);"
                 "}";

    int      r = 0;
    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 42*3);

end:
    if (e)
        delete_tengine(e);
    return r;
}

static test_t tests[] = {
    {"const", &test_const},
    {"const_s8", &test_const_s8},
    {"const_s16", &test_const_s16},
    {"const_s32", &test_const_s32},
    {"const_u8", &test_const_u8},
    {"const_u16", &test_const_u16},
    {"const_u32", &test_const_u32},
    {"const_u64", &test_const_u64},
    {"hex_const", &test_hex_const},
    {"hex_const_u8", &test_hex_const_u8},
    {"hex_const_u16", &test_hex_const_u16},
    {"hex_const_u32", &test_hex_const_u32},
    {"hex_const_u64", &test_hex_const_u64},
    {"cast_u8", &test_cast_u8},
    {"cast_i8", &test_cast_i8},
    {"const_limit_1", &test_const_limit_1},
    {"const_limit_2", &test_const_limit_2},
    {"neg_const", &test_neg_const},
    {"str_const_1", &test_str_const_1},
    {"str_const_2", &test_str_const_2},
    {"eq_str", &test_eq_str},
    {"add", &test_add},
    {"add_no_space", &test_add_no_space},
    {"add_wrap_s8", &test_add_wrap_s8},
    {"add_wrap_s16", &test_add_wrap_s16},
    {"add_wrap_s32", &test_add_wrap_s32},
    {"add_wrap_u8", &test_add_wrap_u8},
    {"add_wrap_u16", &test_add_wrap_u16},
    {"add_wrap_u32", &test_add_wrap_u32},
    {"add_wrap_u64", &test_add_wrap_u64},
    {"sub", &test_sub},
    {"mul", &test_mul},
    {"div_1", &test_div_1},
    {"div_2", &test_div_2},
    {"mod_1", &test_mod_1},
    {"mod_2", &test_mod_2},
    {"and", &test_and},
    {"or", &test_or},
    {"xor", &test_xor},
    {"neg_1", &test_neg_1},
    {"neg_2", &test_neg_2},
    {"band_1", &test_band_1},
    {"band_2", &test_band_2},
    {"bor_1", &test_bor_1},
    {"bor_2", &test_bor_2},
    {"bneq_1", &test_bneq_1},
    {"bnot_1", &test_bnot_1},
    {"precedence_op_1", &test_precedence_op_1},
    {"precedence_op_2", &test_precedence_op_2},
    {"precedence_op_3", &test_precedence_op_3},
    {"precedence_op_4", &test_precedence_op_4},
    {"precedence_op_5", &test_precedence_op_5},
    {"if_1", &test_if_1},
    {"if_2", &test_if_2},
    {"if_3", &test_if_3},
    {"if_4", &test_if_4},
    {"if_5", &test_if_5},
    {"while_1", &test_while_1},
    {"array_1", &test_array_1},
    {"array_2", &test_array_2},
    {"array_3", &test_array_3},
    {"array_4", &test_array_4},
    {"elf_1", &test_elf_1},
    {"strip", &test_strip},
    {"fn_1", &test_fn_1},
    {"fn_2", &test_fn_2},
    {"fn_3", &test_fn_3},
};

int main(int argc, char const* argv[])
{
    RUN_TESTS(tests);
    return 0;
}
