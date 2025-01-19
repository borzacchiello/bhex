#include "test.h"

#include <string.h>
#include <alloc.h>
#include <log.h>

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
    char* prog = "proc { local a = \"ciao\"; local b = \"ciao\"; local c = a == b; }";

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

static int test_add_wrap()
{
    char* prog = "proc { local a = 0x7fffffffffffffff; local b = a + 1; }";

    TEngine* e = TEngine_run_on_string(fb, prog);
    if (e == NULL)
        return 0;

    int           r = 0;
    TEngineValue* v = Scope_get_local(e->proc_scope, "b");
    IS_TENGINE_SNUM_EQ(r, v, -0x8000000000000000l);

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

static int test_if_1()
{
    char* prog =
        "proc { local a = 4; local b = 3; if (a - 3 > 0) { b = b + 42; }; }";

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
    char* prog =
        "proc { local a = 4; local b = 3; if (a - 5 > 0) { b = b + 42; }; }";

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

static int test_while_1()
{
    char* prog = "proc { local a = 0; local b = 0; while (a < 10) { b = b + "
                 "(2*a); a = a + 1; }; }";

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
    {"const_limit_1", &test_const_limit_1},
    {"const_limit_2", &test_const_limit_2},
    {"neg_const", &test_neg_const},
    {"str_const_1", &test_str_const_1},
    {"str_const_2", &test_str_const_2},
    {"eq_str", &test_eq_str},
    {"add", &test_add},
    {"add_wrap", &test_add_wrap},
    {"add_wrap_s8", &test_add_wrap_s8},
    {"add_wrap_s16", &test_add_wrap_s16},
    {"add_wrap_s32", &test_add_wrap_s32},
    {"add_wrap_u8", &test_add_wrap_u8},
    {"add_wrap_u16", &test_add_wrap_u16},
    {"add_wrap_u32", &test_add_wrap_u32},
    {"add_wrap_u64", &test_add_wrap_u64},
    {"sub", &test_sub},
    {"mul", &test_mul},
    {"precedence_op_1", &test_precedence_op_1},
    {"precedence_op_2", &test_precedence_op_2},
    {"precedence_op_3", &test_precedence_op_3},
    {"precedence_op_4", &test_precedence_op_4},
    {"if_1", &test_if_1},
    {"if_2", &test_if_2},
    {"while_1", &test_while_1},
};

int main(int argc, char const* argv[])
{
    RUN_TESTS(tests);
    return 0;
}
