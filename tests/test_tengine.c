#include "defs.h"

#include <string.h>
#include <alloc.h>
#include <log.h>

#include "elf_not_kitty.h"
#include "dummy_filebuffer.h"
#include "../tengine/scope.h"
#include "../tengine/tengine.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

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

int TEST(const)()
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

int TEST(const_s8)()
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

int TEST(const_s16)()
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

int TEST(const_s32)()
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

int TEST(const_u8)()
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

int TEST(const_u16)()
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

int TEST(const_u32)()
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

int TEST(const_u64)()
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

int TEST(hex_const)()
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

int TEST(hex_const_u8)()
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

int TEST(hex_const_u16)()
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

int TEST(hex_const_u32)()
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

int TEST(hex_const_u64)()
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

int TEST(cast_u8)()
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

int TEST(cast_i8)()
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

int TEST(const_limit_1)()
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

int TEST(const_limit_2)()
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

int TEST(neg_const)()
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

int TEST(str_const_1)()
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

int TEST(str_const_2)()
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

int TEST(eq_str)()
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

int TEST(sub)()
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

int TEST(add)()
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

int TEST(add_no_space)()
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

int TEST(add_wrap_s8)()
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

int TEST(add_wrap_s16)()
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

int TEST(add_wrap_s32)()
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

int TEST(add_wrap_u8)()
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

int TEST(add_wrap_u16)()
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

int TEST(add_wrap_u32)()
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

int TEST(add_wrap_u64)()
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

int TEST(mul)()
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

int TEST(div_1)()
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

int TEST(div_2)()
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

int TEST(mod_1)()
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

int TEST(mod_2)()
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

int TEST(and)()
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

int TEST(or)()
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

int TEST(xor)()
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

int TEST(neg_1)()
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

int TEST(neg_2)()
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

int TEST(band_1)()
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

int TEST(band_2)()
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

int TEST(bor_1)()
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

int TEST(bor_2)()
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

int TEST(bneq_1)()
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

int TEST(bnot_1)()
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

int TEST(precedence_op_1)()
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

int TEST(precedence_op_2)()
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

int TEST(precedence_op_3)()
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

int TEST(precedence_op_4)()
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

int TEST(precedence_op_5)()
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

int TEST(if_1)()
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

int TEST(if_2)()
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

int TEST(if_3)()
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

int TEST(if_4)()
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

int TEST(if_5)()
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

int TEST(while_1)()
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

int TEST(array_1)()
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

int TEST(array_2)()
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

int TEST(array_3)()
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

int TEST(array_4)()
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

int TEST(elf_1)()
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

int TEST(strip)()
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

int TEST(fn_1)()
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

int TEST(fn_2)()
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

int TEST(fn_3)()
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
    IS_TENGINE_UNUM_EQ(r, v, 42 * 3);

end:
    if (e)
        delete_tengine(e);
    return r;
}

int TEST(comment_line_1)()
{
    char* prog = "fn test(a, b) {"
                 "    // this is a comment and should be skipped\n"
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
    IS_TENGINE_UNUM_EQ(r, v, 42 * 3);

end:
    if (e)
        delete_tengine(e);
    return r;
}

int TEST(comment_multiline_1)()
{
    char* prog = "fn test(a, b) {"
                 "    /* this is a comment and should be skipped */"
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
    IS_TENGINE_UNUM_EQ(r, v, 42 * 3);

end:
    if (e)
        delete_tengine(e);
    return r;
}

int TEST(comment_multiline_2)()
{
    char* prog = "fn test(a, b) {"
                 "    result = u32(42 + a + b /* this is a comment and should "
                 "be skipped */);"
                 "}"
                 "proc {"
                 "    disable_print();"
                 "    local a = /* this is a comment and should be skipped */ "
                 "test(42, 42);"
                 "}";

    int      r = 0;
    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        goto end;

    TEngineValue* v = Scope_get_local(e->proc_scope, "a");
    IS_TENGINE_UNUM_EQ(r, v, 42 * 3);

end:
    if (e)
        delete_tengine(e);
    return r;
}
