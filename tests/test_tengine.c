#include "test.h"

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

#define IS_SNUM_EQ(r, v, n)                                                    \
    if ((v) == NULL)                                                           \
        goto end;                                                              \
    if ((v)->t != SNUM)                                                        \
        goto end;                                                              \
    if ((v)->snum != (n))                                                      \
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
    IS_SNUM_EQ(r, v, 0);

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
    IS_SNUM_EQ(r, v, 0xdeadbeef);

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
    IS_SNUM_EQ(r, v, 0x7fffffffffffffffl);

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
    IS_SNUM_EQ(r, v, -0x8000000000000000l);

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
    IS_SNUM_EQ(r, v, -42);

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
    IS_SNUM_EQ(r, v, -1);

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
    IS_SNUM_EQ(r, v, 14);

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
    IS_SNUM_EQ(r, v, -0x8000000000000000l);

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
    IS_SNUM_EQ(r, v, 40);

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
    IS_SNUM_EQ(r, v, 45);

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
    IS_SNUM_EQ(r, v, 3);

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
    IS_SNUM_EQ(r, v, 90);

end:
    delete_tengine(e);
    return r;
}

static test_t tests[] = {
    {"const", &test_const},
    {"hex_const", &test_hex_const},
    {"neg_const", &test_neg_const},
    {"const_limit_1", &test_const_limit_1},
    {"const_limit_2", &test_const_limit_2},
    {"add", &test_add},
    {"add_wrap", &test_add_wrap},
    {"sub", &test_sub},
    {"mul", &test_mul},
    {"if_1", &test_if_1},
    {"if_2", &test_if_2},
    {"while_1", &test_while_1},
};

int main(int argc, char const* argv[])
{
    RUN_TESTS(tests);
    return 0;
}
