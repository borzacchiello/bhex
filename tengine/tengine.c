#include <string.h>

#include "../log.h"
#include "../alloc.h"
#include "tengine.h"
#include "ast.h"
#include "map.h"

#define engine_printf(e, ...)                                                  \
    do {                                                                       \
        if (!e->quiet_mode) {                                                  \
            printf(__VA_ARGS__);                                               \
        }                                                                      \
    } while (0)

extern int  yyparse(void);
extern void yyset_in(FILE*);
extern void yyset_ctx(ASTCtx*);
extern int  yymax_ident_len;

#define MAX_ARR_PRINT_SIZE 16

typedef struct ProcessContext {
    FileBuffer* fb;
    TEngine*    engine;
    u64_t       initial_off;
    int         print_off;
} ProcessContext;

struct Scope;
static int process_stmt(ProcessContext ctx, Stmt* stmt, struct Scope* scope);

/*
 * Variables Values
 */

typedef enum TEngineVarType {
    UNUM = 500,
    SNUM,
    CHAR,
    STRING,
    CUSTOM_TYPE,
    ENUM_VALUE,
} TEngineVarType;

typedef struct TEngineVarValue {
    TEngineVarType t;
    char*          name;
    union {
        struct {
            // UNUM
            u64_t unum;
            u32_t unum_size;
        };
        struct {
            // SNUM
            s64_t snum;
            u32_t snum_size;
        };
        struct {
            // CHAR
            char c;
        };
        struct {
            // STRING
            char* str;
        };
        struct {
            // CUSTOM_TYPE
            map* subvals;
        };
        struct {
            // ENUM_VALUE
            char* enum_value;
            u64_t enum_const;
        };
    };
} TEngineVarValue;

TEngineVarValue* TEngineVarValue_UNUM_new(const char* name, u64_t v, u32_t size)
{
    TEngineVarValue* r = bhex_calloc(sizeof(TEngineVarValue));
    r->name            = bhex_strdup(name);
    r->t               = UNUM;
    r->unum            = v;
    r->unum_size       = size;
    return r;
}

TEngineVarValue* TEngine_CHAR_new(const char* name, char c)
{
    TEngineVarValue* r = bhex_calloc(sizeof(TEngineVarValue));
    r->name            = bhex_strdup(name);
    r->t               = CHAR;
    r->c               = c;
    return r;
}

TEngineVarValue* TEngine_STRING_new(const char* name, const char* str)
{
    TEngineVarValue* r = bhex_calloc(sizeof(TEngineVarValue));
    r->name            = bhex_strdup(name);
    r->t               = STRING;
    r->str             = bhex_strdup(str);
    return r;
}

TEngineVarValue* TEngineVarValue_SNUM_new(const char* name, s64_t v, u32_t size)
{
    TEngineVarValue* r = bhex_calloc(sizeof(TEngineVarValue));
    r->name            = bhex_strdup(name);
    r->t               = SNUM;
    r->snum            = v;
    r->snum_size       = size;
    return r;
}

TEngineVarValue* TEngineVarValue_CUSTOM_TYPE_new(const char* name, map* subvals)
{
    TEngineVarValue* r = bhex_calloc(sizeof(TEngineVarValue));
    r->name            = bhex_strdup(name);
    r->t               = CUSTOM_TYPE;
    r->subvals         = subvals;
    return r;
}

TEngineVarValue* TEngineVarValue_ENUM_VALUE_new(const char* name,
                                                const char* ename, u64_t econst)
{
    TEngineVarValue* r = bhex_calloc(sizeof(TEngineVarValue));
    r->name            = bhex_strdup(name);
    r->t               = ENUM_VALUE;
    r->enum_value      = bhex_strdup(ename);
    r->enum_const      = econst;
    return r;
}

int TEngineVarValue_get_num(TEngineVarValue* v, s64_t* onum)
{
    switch (v->t) {
        case UNUM:
            if ((v->unum >> 63) != 0) {
                error("TEngineVarValue_get_num: the number '%llu' is too big "
                      "to fit a TEngine num",
                      v->unum);
                return 1;
            }
            *onum = (s64_t)v->unum;
            return 0;
        case SNUM:
            *onum = v->snum;
            return 0;
        case CHAR:
            *onum = (s64_t)v->c;
            return 0;
        case ENUM_VALUE:
            *onum = (s64_t)v->enum_const;
            return 0;
        case STRING:
        case CUSTOM_TYPE:
            error("[tengine] not a numeric type");
            return 1;
        default:
            panic("invalid type in TEngineVarValue_get_num");
    }
    return 1;
}

void TEngineVarValue_free(TEngineVarValue* v)
{
    if (!v)
        return;

    switch (v->t) {
        case UNUM:
        case SNUM:
        case CHAR:
            break;
        case STRING:
            bhex_free(v->str);
            break;
        case ENUM_VALUE:
            bhex_free(v->enum_value);
            break;
        case CUSTOM_TYPE:
            map_destroy(v->subvals);
            break;
        default:
            panic("invalid type in TEngineVarValue_free");
    }
    bhex_free(v->name);
    bhex_free(v);
}

void TEngineVarValue_pp(TEngine* e, TEngineVarValue* v, int print_off)
{
    switch (v->t) {
        case UNUM:
            if (e->print_in_hex)
                engine_printf(e, "%0*llx", v->unum_size * 2, v->unum);
            else
                engine_printf(e, "%llu", v->unum);
            break;
        case SNUM:
            if (e->print_in_hex)
                engine_printf(e, "%0*llx", v->unum_size * 2, v->unum);
            else
                engine_printf(e, "%lld", v->snum);
            break;
        case CHAR:
            engine_printf(e, "%c", v->c);
            return;
        case STRING:
            engine_printf(e, "'%s'", v->str);
            break;
        case ENUM_VALUE: {
            engine_printf(e, "%s", v->enum_value);
            break;
        }
        case CUSTOM_TYPE: {
            engine_printf(e, "\n");
            for (const char* key = map_first(v->subvals); key != NULL;
                 key             = map_next(v->subvals, key)) {
                for (int i = 0; i < print_off + 4; ++i)
                    engine_printf(e, " ");
                engine_printf(e, ".%.*s: ", yymax_ident_len, key);
                TEngineVarValue* nv = map_get(v->subvals, key);
                TEngineVarValue_pp(e, nv, print_off + 4);
                engine_printf(e, "\n");
            }
            break;
        }
        default:
            panic("invalid type in TEngineVarValue_pp");
    }
}

/*
 * Embedded Types Valorizers
 */

typedef struct TEngineEmbeddedType {
    const char name[MAX_IDENT_SIZE];
    TEngineVarValue* (*process)(TEngine*, const char*, FileBuffer*);
} TEngineEmbeddedType;

static TEngineVarValue* string_process(TEngine* e, const char* name,
                                       FileBuffer* fb)
{
    u64_t tmp_capacity = 8;
    u64_t tmp_size     = 0;
    char* tmp          = bhex_calloc(tmp_capacity);

#define enlarge_tmp                                                            \
    if (tmp_size == tmp_capacity) {                                            \
        tmp_capacity *= 2;                                                     \
        tmp = bhex_realloc(tmp, tmp_capacity);                                 \
    }

    const uint8_t* buf = fb_read(fb, 1);
    if (buf == NULL)
        return NULL;

    TEngineVarValue* r = NULL;
    while (*buf) {
        enlarge_tmp;

        tmp[tmp_size++] = (char)*buf;
        if (fb_seek(fb, fb->off + 1) != 0)
            goto end;
        buf = fb_read(fb, 1);
    }

    enlarge_tmp;
    tmp[tmp_size] = '\0';
    r             = TEngine_STRING_new(name, tmp);

end:
    bhex_free(tmp);
    return r;
}

static TEngineVarValue* char_process(TEngine* e, const char* name,
                                     FileBuffer* fb)
{
    const uint8_t* buf = fb_read(fb, 1);
    if (buf == NULL)
        return NULL;
    if (fb_seek(fb, fb->off + 1) != 0)
        return NULL;
    return TEngine_CHAR_new(name, *buf);
}

static TEngineVarValue* uint_process(TEngine* e, const char* name,
                                     const u8_t* buf, u32_t size)
{
    u64_t v = 0;
    for (u32_t i = 0; i < size; ++i) {
        v |= (u64_t)buf[i] << ((e->endianess == TE_BIG_ENDIAN)
                                   ? ((size - i - 1) * 8)
                                   : (i * 8));
    }
    return TEngineVarValue_UNUM_new(name, v, size);
}

static TEngineVarValue* int_process(TEngine* e, const char* name,
                                    const u8_t* buf, u32_t size)
{
    u64_t v = 0;
    for (u32_t i = 0; i < size; ++i) {
        v |= (u64_t)buf[i] << ((e->endianess == TE_BIG_ENDIAN)
                                   ? ((size - i - 1) * 8)
                                   : (i * 8));
    }

    s64_t sv = 0;
    switch (size) {
        case 1:
            sv = (s64_t)(s8_t)v;
            break;
        case 2:
            sv = (s64_t)(s16_t)v;
            break;
        case 4:
            sv = (s64_t)(s32_t)v;
            break;
        case 8:
            sv = (s64_t)(s64_t)v;
            break;
        default:
            panic("invalid size (%u) in 'int_print'", size);
    }
    return TEngineVarValue_SNUM_new(name, sv, size);
}

#define GEN_INT_PRINT(name, size, signed)                                      \
    static TEngineVarValue* name##_process(                                    \
        TEngine* engine, const char* varname, FileBuffer* fb)                  \
    {                                                                          \
        const u8_t* buf = fb_read(fb, size);                                   \
        fb_seek(fb, fb->off + size);                                           \
        if (buf == NULL)                                                       \
            return NULL;                                                       \
        if (!signed)                                                           \
            return uint_process(engine, varname, buf, size);                   \
        return int_process(engine, varname, buf, size);                        \
    }

GEN_INT_PRINT(uint64_t, 8, 0)
GEN_INT_PRINT(uint32_t, 4, 0)
GEN_INT_PRINT(uint16_t, 2, 0)
GEN_INT_PRINT(uint8_t, 1, 0)
GEN_INT_PRINT(int64_t, 8, 1)
GEN_INT_PRINT(int32_t, 4, 1)
GEN_INT_PRINT(int16_t, 2, 1)
GEN_INT_PRINT(int8_t, 1, 1)

static TEngineEmbeddedType embedded_types[] = {
    {"uint64_t", uint64_t_process}, {"uint32_t", uint32_t_process},
    {"uint16_t", uint16_t_process}, {"uint8_t", uint8_t_process},
    {"int64_t", int64_t_process},   {"int32_t", int32_t_process},
    {"int16_t", int16_t_process},   {"int8_t", int8_t_process},
    {"char", char_process},         {"string_t", string_process},
};

/*
 * Scope Object
 */

typedef struct Scope {
    map* filevars;
    map* locals;
} Scope;

Scope* Scope_new()
{
    Scope* s    = bhex_calloc(sizeof(Scope));
    s->locals   = map_create();
    s->filevars = map_create();
    map_set_dispose(s->locals, (void (*)(void*))TEngineVarValue_free);
    map_set_dispose(s->filevars, (void (*)(void*))TEngineVarValue_free);
    return s;
}

void Scope_free(Scope* s)
{
    if (!s)
        return;

    map_destroy(s->locals);
    map_destroy(s->filevars);
    bhex_free(s);
}

TEngineVarValue* Scope_get_filevar(Scope* s, const char* name)
{
    if (!map_contains(s->filevars, name))
        return NULL;
    return map_get(s->filevars, name);
}

TEngineVarValue* Scope_get_local(Scope* s, const char* name)
{
    if (!map_contains(s->locals, name))
        return NULL;
    return map_get(s->locals, name);
}

TEngineVarValue* Scope_get_anyvar(Scope* s, const char* name)
{
    TEngineVarValue* v = Scope_get_filevar(s, name);
    if (v == NULL)
        return Scope_get_local(s, name);
    return v;
}

void Scope_add_filevar(Scope* s, const char* name, TEngineVarValue* value)
{
    map_set(s->filevars, name, value);
}

void Scope_add_local(Scope* s, const char* name, TEngineVarValue* value)
{
    map_set(s->locals, name, value);
}

map* Scope_free_and_get_filevars(Scope* s)
{
    // Destroy only the locals
    map_destroy(s->locals);
    map* r = s->filevars;
    bhex_free(s);
    return r;
}

/*
 * TEngine Object
 */

static const TEngineEmbeddedType* find_embedded_type(const char* type)
{
    for (u64_t i = 0; i < sizeof(embedded_types) / sizeof(TEngineEmbeddedType);
         ++i) {
        TEngineEmbeddedType* t = &embedded_types[i];
        if (strcmp(t->name, type) == 0) {
            return t;
        }
    }
    return NULL;
}

static Block* get_custom_type_body(TEngine* e, const char* name)
{
    for (const char* key = map_first(e->ast->structs); key != NULL;
         key             = map_next(e->ast->structs, key)) {
        if (strcmp(name, key) != 0)
            continue;
        return map_get(e->ast->structs, key);
    }
    return NULL;
}

static Enum* get_enum(TEngine* e, const char* name)
{
    for (const char* key = map_first(e->ast->enums); key != NULL;
         key             = map_next(e->ast->enums, key)) {
        if (strcmp(name, key) != 0)
            continue;
        return map_get(e->ast->enums, key);
    }
    return NULL;
}

static map* process_custom_type(ProcessContext ctx, const char* type)
{
    Block* body = get_custom_type_body(ctx.engine, type);
    if (body == NULL)
        return NULL;

    Scope* scope = Scope_new();

    engine_printf(ctx.engine, "\n");
    ctx.print_off += 4;
    for (u64_t i = 0; i < body->stmts->size; ++i) {
        Stmt* stmt = (Stmt*)body->stmts->data[i];
        if (process_stmt(ctx, stmt, scope) != 0) {
            Scope_free(scope);
            return NULL;
        }
    }
    return Scope_free_and_get_filevars(scope);
}

static const char* process_enum_type(ProcessContext ctx, const char* type,
                                     u64_t* econst)
{
    Enum* e = get_enum(ctx.engine, type);
    if (e == NULL)
        return NULL;

    const TEngineEmbeddedType* t = find_embedded_type(e->type);
    if (t == NULL) {
        error("[tengine] Enum %s has an invalid source type [%s]", type,
              e->type);
        return NULL;
    }

    TEngineVarValue* v = t->process(ctx.engine, e->type, ctx.fb);
    if (v == NULL)
        return NULL;

    u64_t val = v->t == UNUM ? v->unum : (u64_t)v->snum;
    if (econst)
        *econst = val;
    TEngineVarValue_free(v);

    const char* name = Enum_find_const(e, val);
    if (name == NULL) {
        warning("[tengine] Enum %s has no value %llu", type, val);
        static char tmpbuf[1024];
        memset(tmpbuf, 0, sizeof(tmpbuf));
        snprintf(tmpbuf, sizeof(tmpbuf) - 1, "UNK [%llu ~ 0x%llx]", val, val);
        return tmpbuf;
    }
    return name;
}

static TEngineVarValue* process_type(ProcessContext ctx, const char* varname,
                                     const char* type, Scope* scope)
{
    const TEngineEmbeddedType* t = find_embedded_type(type);
    if (t != NULL) {
        TEngineVarValue* r = t->process(ctx.engine, varname, ctx.fb);
        if (r == NULL)
            return NULL;

        TEngineVarValue_pp(ctx.engine, r, ctx.print_off);
        engine_printf(ctx.engine, "\n");
        return r;
    }

    map* custom_type_vars = process_custom_type(ctx, type);
    if (custom_type_vars != NULL) {
        TEngineVarValue* v =
            TEngineVarValue_CUSTOM_TYPE_new(varname, custom_type_vars);
        return v;
    }

    u64_t       econst;
    const char* enum_var = process_enum_type(ctx, type, &econst);
    if (enum_var != NULL) {
        TEngineVarValue* v =
            TEngineVarValue_ENUM_VALUE_new(varname, enum_var, econst);
        TEngineVarValue_pp(ctx.engine, v, ctx.print_off);
        engine_printf(ctx.engine, "\n");
        return v;
    }

    error("[tengine] unknown type %s", type);
    return NULL;
}

static int process_builtin_expr_func_call(ProcessContext ctx, Scope* scope,
                                          const char* fname, DList* params,
                                          s64_t* oval)
{
#define REQUIRE_EXPR_CALL_VOID                                                 \
    if (params != NULL) {                                                      \
        error("[tengine] invalid expr call '%s', no param expected", fname);   \
        return 1;                                                              \
    }

    // TODO: factor out build-ins to an array, do it also for void calls (stmts)
    if (strcmp(fname, "curroff") == 0) {
        REQUIRE_EXPR_CALL_VOID

        // TODO: I'm assuming that the offset fits in 63 bits
        *oval = (s64_t)ctx.fb->off;
        return 0;
    }

    error("[tengine] no such non-void function '%s'", fname);
    return 1;
}

static int evaluate_num_expr(ProcessContext ctx, Scope* scope, Expr* e,
                             s64_t* oval)
{
    switch (e->t) {
        case EXPR_CONST:
            *oval = e->value;
            return 0;
        case EXPR_VAR: {
            TEngineVarValue* value = Scope_get_anyvar(scope, e->name);
            if (!value) {
                error("[tengine] no such variable '%s'", e->name);
                return 1;
            }
            if (TEngineVarValue_get_num(value, oval) != 0)
                return 1;
            return 0;
        }
        case EXPR_VARCHAIN: {
            if (e->chain->size == 0) {
                error("[tengine] varchain with size zero");
                return 1;
            }

            // Only FILEVARS can have custom types
            TEngineVarValue* val = Scope_get_filevar(scope, e->chain->data[0]);
            u64_t            i   = 1;
            if (val->t == CUSTOM_TYPE) {
                map* vars = val->subvals;
                for (; i < e->chain->size; ++i) {
                    char* n = e->chain->data[i];
                    if (!map_contains(vars, n)) {
                        error("[tengine] no such variable (in chain) '%s'", n);
                        return 1;
                    }
                    val = map_get(vars, n);
                    if (val->t != CUSTOM_TYPE)
                        break;
                    vars = val->subvals;
                }
            }
            if (val == NULL || i != e->chain->size - 1) {
                error("[tengine] invalid chain");
                return 1;
            }
            if (TEngineVarValue_get_num(val, oval) != 0)
                return 1;
            return 0;
        }
        case EXPR_FUN_CALL:
            return process_builtin_expr_func_call(ctx, scope, e->fname,
                                                  e->params, oval);
        case EXPR_ADD: {
            s64_t lhs, rhs;
            if (evaluate_num_expr(ctx, scope, e->lhs, &lhs) != 0)
                return 1;
            if (evaluate_num_expr(ctx, scope, e->rhs, &rhs) != 0)
                return 1;
            *oval = lhs + rhs;
            return 0;
        }
        case EXPR_SUB: {
            s64_t lhs, rhs;
            if (evaluate_num_expr(ctx, scope, e->lhs, &lhs) != 0)
                return 1;
            if (evaluate_num_expr(ctx, scope, e->rhs, &rhs) != 0)
                return 1;
            *oval = lhs - rhs;
            return 0;
        }
        case EXPR_MUL: {
            s64_t lhs, rhs;
            if (evaluate_num_expr(ctx, scope, e->lhs, &lhs) != 0)
                return 1;
            if (evaluate_num_expr(ctx, scope, e->rhs, &rhs) != 0)
                return 1;
            *oval = lhs * rhs;
            return 0;
        }
        case EXPR_BEQ: {
            s64_t lhs, rhs;
            if (evaluate_num_expr(ctx, scope, e->lhs, &lhs) != 0)
                return 1;
            if (evaluate_num_expr(ctx, scope, e->rhs, &rhs) != 0)
                return 1;
            *oval = (lhs == rhs) ? 1 : 0;
            return 0;
        }
        case EXPR_BLT: {
            s64_t lhs, rhs;
            if (evaluate_num_expr(ctx, scope, e->lhs, &lhs) != 0)
                return 1;
            if (evaluate_num_expr(ctx, scope, e->rhs, &rhs) != 0)
                return 1;
            *oval = (lhs < rhs) ? 1 : 0;
            return 0;
        }
        case EXPR_BLE: {
            s64_t lhs, rhs;
            if (evaluate_num_expr(ctx, scope, e->lhs, &lhs) != 0)
                return 1;
            if (evaluate_num_expr(ctx, scope, e->rhs, &rhs) != 0)
                return 1;
            *oval = (lhs <= rhs) ? 1 : 0;
            return 0;
        }
        case EXPR_BGT: {
            s64_t lhs, rhs;
            if (evaluate_num_expr(ctx, scope, e->lhs, &lhs) != 0)
                return 1;
            if (evaluate_num_expr(ctx, scope, e->rhs, &rhs) != 0)
                return 1;
            *oval = (lhs > rhs) ? 1 : 0;
            return 0;
        }
        case EXPR_BGE: {
            s64_t lhs, rhs;
            if (evaluate_num_expr(ctx, scope, e->lhs, &lhs) != 0)
                return 1;
            if (evaluate_num_expr(ctx, scope, e->rhs, &rhs) != 0)
                return 1;
            *oval = (lhs >= rhs) ? 1 : 0;
            return 0;
        }
        default:
            panic("unimplemented eval for expr %d", e->t);
    }
    return 1;
}

static int process_array_type(ProcessContext ctx, const char* varname,
                              const char* type, Expr* esize, Scope* scope)
{
    s64_t size;
    if (evaluate_num_expr(ctx, scope, esize, &size) != 0)
        return 1;
    if (size < 0) {
        error("[tengine] invalid array size: %lld", size);
        return 1;
    }
    if ((u64_t)size > ctx.fb->size - ctx.fb->off) {
        error("[tengine] invalid array size: %lld, it is bigger than the "
              "remaining file size",
              size);
        return 1;
    }

    u64_t final_off = ctx.fb->off + (u64_t)size;

    // Let's threat uint8_t arrays as byte arrays, we will print them in hex
    int is_uint8 = strcmp(type, "uint8_t") == 0;

    const TEngineEmbeddedType* t       = find_embedded_type(type);
    s64_t                      printed = 0;
    if (t != NULL) {
        if (!is_uint8)
            engine_printf(ctx.engine, "[ ");
        while (printed < size) {
            TEngineVarValue* val = t->process(ctx.engine, varname, ctx.fb);
            if (val == NULL)
                return 1;
            if (is_uint8) {
                int tmp = ctx.engine->print_in_hex;
                TEngineVarValue_pp(ctx.engine, val, ctx.print_off);
                ctx.engine->print_in_hex = tmp;
            } else {
                TEngineVarValue_pp(ctx.engine, val, ctx.print_off);
                if (printed < size - 1)
                    engine_printf(ctx.engine, ", ");
            }
            // TODO save the value!
            TEngineVarValue_free(val);
            if (printed++ >= MAX_ARR_PRINT_SIZE) {
                engine_printf(ctx.engine, "...");
                break;
            }
        }
        if (!is_uint8)
            engine_printf(ctx.engine, " ]");
        engine_printf(ctx.engine, "\n");

        fb_seek(ctx.fb, final_off);
        return 0;
    }

    // Array of custom type
    engine_printf(ctx.engine, "\n");
    for (int i = 0; i < ctx.print_off + 11 + yymax_ident_len; ++i)
        engine_printf(ctx.engine, " ");
    engine_printf(ctx.engine, "[%lld]", printed);
    for (printed = 0; printed < size; ++printed) {
        map* custom_type_vars = process_custom_type(ctx, type);
        if (custom_type_vars == NULL) {
            error("[tengine] unknown type %s", type);
            return 1;
        }
        if (printed < size - 1) {
            for (int i = 0; i < ctx.print_off + 11 + yymax_ident_len; ++i)
                engine_printf(ctx.engine, " ");
            engine_printf(ctx.engine, "[%lld]", printed + 1);
        }
        // TODO save the array!
        map_destroy(custom_type_vars);
    }
    return 0;
}

static int process_FILE_VAR_DECL(ProcessContext ctx, Stmt* stmt, Scope* scope)
{
    engine_printf(ctx.engine, "b+%08llx ", ctx.fb->off - ctx.initial_off);
    for (int i = 0; i < ctx.print_off; ++i)
        engine_printf(ctx.engine, " ");
    engine_printf(ctx.engine, " %*s: ", yymax_ident_len, stmt->name);

    if (stmt->arr_size == NULL) {
        // Not an array
        TEngineVarValue* val = process_type(ctx, stmt->name, stmt->type, scope);
        if (val == NULL)
            return 1;
        Scope_add_filevar(scope, stmt->name, val);
    } else {
        // Array type
        if (process_array_type(ctx, stmt->name, stmt->type, stmt->arr_size,
                               scope) != 0)
            return 1;
        // TODO: valorize TEngineVarValue
    }
    return 0;
}

static int process_LOCAL_VAR_DECL(ProcessContext ctx, Stmt* stmt, Scope* scope)
{
    s64_t num;
    if (evaluate_num_expr(ctx, scope, stmt->local_value, &num) != 0)
        return 1;

    Scope_add_local(scope, stmt->local_name,
                    TEngineVarValue_SNUM_new(stmt->local_name, num, 8));
    return 0;
}

static int process_LOCAL_VAR_ASS(ProcessContext ctx, Stmt* stmt, Scope* scope)
{
    s64_t num;
    if (evaluate_num_expr(ctx, scope, stmt->local_value, &num) != 0)
        return 1;

    if (Scope_get_local(scope, stmt->local_name) == NULL) {
        error("[tengine] no such local variable '%s", stmt->local_name);
        return 1;
    }

    Scope_add_local(scope, stmt->local_name,
                    TEngineVarValue_SNUM_new(stmt->local_name, num, 8));
    return 0;
}

static int process_VOID_FUNC_CALL(ProcessContext ctx, Stmt* stmt, Scope* scope)
{
#define REQUIRE_VOID                                                           \
    if (stmt->params != NULL) {                                                \
        error("[tengine] invalid call '%s', no param expected", stmt->fname);  \
        return 1;                                                              \
    }

#define REQUIRE_ONE_PARAM                                                      \
    if (stmt->params == NULL || stmt->params->size != 1) {                     \
        error("[tengine] invalid call '%s', expected one parameter",           \
              stmt->fname);                                                    \
        return 1;                                                              \
    }

    // TODO: factor out build-in functions in an array
    if (strcmp(stmt->fname, "endianess_le") == 0) {
        REQUIRE_VOID
        ctx.engine->endianess = TE_LITTLE_ENDIAN;
        return 0;
    } else if (strcmp(stmt->fname, "endianess_be") == 0) {
        REQUIRE_VOID
        ctx.engine->endianess = TE_BIG_ENDIAN;
        return 0;
    } else if (strcmp(stmt->fname, "nums_in_hex") == 0) {
        REQUIRE_VOID
        ctx.engine->print_in_hex = 1;
        return 0;
    } else if (strcmp(stmt->fname, "nums_in_dec") == 0) {
        REQUIRE_VOID
        ctx.engine->print_in_hex = 0;
        return 0;
    } else if (strcmp(stmt->fname, "disable_print") == 0) {
        REQUIRE_VOID
        ctx.engine->quiet_mode = 1;
        return 0;
    } else if (strcmp(stmt->fname, "enable_print") == 0) {
        REQUIRE_VOID
        ctx.engine->quiet_mode = 0;
        return 0;
    } else if (strcmp(stmt->fname, "seek") == 0 ||
               strcmp(stmt->fname, "fwd") == 0) {
        REQUIRE_ONE_PARAM
        s64_t off;
        if (evaluate_num_expr(ctx, scope, stmt->params->data[0], &off) != 0)
            return 1;
        if (off < 0) {
            error("[tengine] negative seek/fwd offset '%lld'", off);
            return 1;
        }

        u64_t to_off = (u64_t)off;
        if (strcmp(stmt->fname, "fwd") == 0)
            to_off = to_off + ctx.fb->off;

        if (fb_seek(ctx.fb, (u64_t)off) != 0) {
            error("[tengine] unable to seek to offset '%lld'", off);
            return 1;
        }
        return 0;
    }

    error("[tengine] no such function '%s'", stmt->fname);
    return 1;
}

static int process_STMT_IF(ProcessContext ctx, Stmt* stmt, Scope* scope)
{
    s64_t cond;
    if (evaluate_num_expr(ctx, scope, stmt->cond, &cond) != 0)
        return 1;

    if (cond != 0) {
        // TODO: we are using the same context of the current block, to do the
        // things correctly we should define a new var context and delete the
        // new variables afterwards
        // Ex, this is currently correct (for now it is fine though):
        //   if (1) { uint8_t a; }
        //   if (a) { uint8_t b; }
        DList* stmts = stmt->body->stmts;
        for (u64_t i = 0; i < stmts->size; ++i) {
            Stmt* stmt = (Stmt*)stmts->data[i];
            if (process_stmt(ctx, stmt, scope) != 0)
                return 1;
        }
    }
    return 0;
}

static int process_STMT_IF_ELSE(ProcessContext ctx, Stmt* stmt, Scope* scope)
{
    s64_t cond;
    if (evaluate_num_expr(ctx, scope, stmt->if_else_cond, &cond) != 0)
        return 1;

    // TODO: same problem WRT STMT_IF
    DList* stmts = stmt->if_else_true_body->stmts;
    if (cond == 0)
        stmts = stmt->if_else_false_body->stmts;
    for (u64_t i = 0; i < stmts->size; ++i) {
        Stmt* stmt = (Stmt*)stmts->data[i];
        if (process_stmt(ctx, stmt, scope) != 0)
            return 1;
    }
    return 0;
}

static int process_STMT_WHILE(ProcessContext ctx, Stmt* stmt, Scope* scope)
{
    // TODO: same problem WRT STMT_IF

    s64_t cond;
    if (evaluate_num_expr(ctx, scope, stmt->cond, &cond) != 0)
        return 1;

    while (cond != 0) {
        DList* stmts = stmt->body->stmts;
        for (u64_t i = 0; i < stmts->size; ++i) {
            Stmt* stmt = (Stmt*)stmts->data[i];
            if (process_stmt(ctx, stmt, scope) != 0)
                return 1;
        }

        if (evaluate_num_expr(ctx, scope, stmt->cond, &cond) != 0)
            return 1;
    }
    return 0;
}

static int process_stmt(ProcessContext ctx, Stmt* stmt, Scope* scope)
{
    switch (stmt->t) {
        case FILE_VAR_DECL:
            return process_FILE_VAR_DECL(ctx, stmt, scope);
        case LOCAL_VAR_DECL:
            return process_LOCAL_VAR_DECL(ctx, stmt, scope);
        case LOCAL_VAR_ASS:
            return process_LOCAL_VAR_ASS(ctx, stmt, scope);
        case VOID_FUNC_CALL:
            return process_VOID_FUNC_CALL(ctx, stmt, scope);
        case STMT_IF:
            return process_STMT_IF(ctx, stmt, scope);
        case STMT_IF_ELSE:
            return process_STMT_IF_ELSE(ctx, stmt, scope);
        case STMT_WHILE:
            return process_STMT_WHILE(ctx, stmt, scope);
        default: {
            error("[tengine] invalid stmt type %d", stmt->t);
            break;
        }
    }
    return 1;
}

static int process_ast(TEngine* engine, FileBuffer* fb)
{
    if (!engine->ast->proc) {
        error("[tengine] no proc");
        return 1;
    }

    ProcessContext ctx   = {fb, engine, fb->off, 0};
    DList*         stmts = engine->ast->proc->stmts;
    for (u64_t i = 0; i < stmts->size; ++i) {
        Stmt* stmt = (Stmt*)stmts->data[i];
        if (process_stmt(ctx, stmt, engine->proc_scope) != 0)
            return 1;
    }
    return 0;
}

ASTCtx* TEngine_parse_filename(const char* bhe)
{
    FILE* f = fopen(bhe, "r");
    if (f == NULL) {
        error("unable to open template file '%s'", bhe);
        return NULL;
    }

    ASTCtx* ast = TEngine_parse_file(f);
    fclose(f);
    return ast;
}

ASTCtx* TEngine_parse_file(FILE* f)
{
    ASTCtx* ast = ASTCtx_new();

    yyset_in(f);
    yyset_ctx(ast);

    if (yyparse() != 0) {
        error("parsing failed");
        ASTCtx_delete(ast);
        return NULL;
    }
    return ast;
}

void TEngine_init(TEngine* engine, ASTCtx* ast)
{
    engine->ast          = ast;
    engine->proc_scope   = Scope_new();
    engine->endianess    = TE_LITTLE_ENDIAN;
    engine->print_in_hex = 1;
    engine->quiet_mode   = 0;
}

void TEngine_deinit(TEngine* engine) { Scope_free(engine->proc_scope); }

int TEngine_process_filename(FileBuffer* fb, const char* bhe)
{
    FILE* f = fopen(bhe, "r");
    if (f == NULL) {
        error("unable to open template file '%s'", bhe);
        return 1;
    }

    int r = TEngine_process_file(fb, f);
    fclose(f);
    return r;
}

int TEngine_process_file(FileBuffer* fb, FILE* f)
{
    ASTCtx* ast = TEngine_parse_file(f);
    if (ast == NULL) {
        fclose(f);
        return 1;
    }

    int r = TEngine_process_ast(fb, ast);
    ASTCtx_delete(ast);
    return r;
}

int TEngine_process_ast(FileBuffer* fb, ASTCtx* ast)
{
    TEngine eng;
    TEngine_init(&eng, ast);

    int r = process_ast(&eng, fb);
    TEngine_deinit(&eng);
    return r;
}

void TEngine_pp(TEngine* e)
{
    int orig_quiet_mode = e->quiet_mode;
    e->quiet_mode       = 0;

    printf("TEngine\n\n");
    ASTCtx_pp(e->ast);

    printf("\nProc File Variables\n");
    printf("=========\n");
    for (const char* key = map_first(e->proc_scope->filevars); key != NULL;
         key             = map_next(e->proc_scope->filevars, key)) {
        printf("%s ", key);
        TEngineVarValue* v = map_get(e->proc_scope->filevars, key);
        TEngineVarValue_pp(e, v, 0);
    }
    printf("\n");

    printf("\nProc Local Variables\n");
    printf("=========\n");
    for (const char* key = map_first(e->proc_scope->locals); key != NULL;
         key             = map_next(e->proc_scope->locals, key)) {
        printf("%s ", key);
        TEngineVarValue* v = map_get(e->proc_scope->locals, key);
        TEngineVarValue_pp(e, v, 0);
        printf("\n");
    }
    printf("\n");

    e->quiet_mode = orig_quiet_mode;
}
