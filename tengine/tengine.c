#include <string.h>

#include "../log.h"
#include "../alloc.h"
#include "tengine.h"
#include "ast.h"
#include "map.h"

extern int  yyparse(void);
extern void yyset_in(FILE*);
extern void yyset_ctx(ASTCtx*);
extern int  yymax_ident_len;

#define MAX_ARR_PRINT_SIZE 16

typedef struct ProcessContext {
    FileBuffer* fb;
    TEngine*    engine;
    int         print_off;
} ProcessContext;

static int process_stmt(ProcessContext ctx, Stmt* stmt, map* vars);

/*
 * Variables Values
 */

typedef enum TEngineVarType {
    UNUM = 500,
    SNUM,
    CUSTOM_TYPE,
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
            // CUSTOM_TYPE
            map* subvals;
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
                printf("%0*llx", v->unum_size * 2, v->unum);
            else
                printf("%llu", v->unum);
            break;
        case SNUM:
            if (e->print_in_hex)
                printf("%0*llx", v->unum_size * 2, v->unum);
            else
                printf("%lld", v->snum);
            break;
        case CUSTOM_TYPE: {
            printf("\n");
            for (const char* key = map_first(v->subvals); key != NULL;
                 key             = map_next(v->subvals, key)) {
                for (int i = 0; i < print_off + 4; ++i)
                    printf(" ");
                printf(".%.*s: ", yymax_ident_len, key);
                TEngineVarValue* nv = map_get(v->subvals, key);
                TEngineVarValue_pp(e, nv, print_off + 4);
                printf("\n");
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
};

/*
 * TEngine Object
 */

void TEngine_init(TEngine* engine)
{
    ASTCtx_init(&engine->ast);
    engine->proc_variables = map_create();
    engine->endianess      = TE_LITTLE_ENDIAN;
    engine->print_in_hex   = 1;

    map_set_dispose(engine->proc_variables,
                    (void (*)(void*))TEngineVarValue_free);
}

void TEngine_deinit(TEngine* engine)
{
    ASTCtx_deinit(&engine->ast);
    map_destroy(engine->proc_variables);
}

int TEngine_process_filename(TEngine* engine, FileBuffer* fb, const char* bhe)
{
    FILE* f = fopen(bhe, "r");
    if (f == NULL) {
        error("unable to open template file '%s'", bhe);
        return 1;
    }
    return TEngine_process_file(engine, fb, f);
}

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

static DList* get_custom_type_body(TEngine* e, const char* name)
{
    for (const char* key = map_first(e->ast.structs); key != NULL;
         key             = map_next(e->ast.structs, key)) {
        if (strcmp(name, key) != 0)
            continue;
        return map_get(e->ast.structs, key);
    }
    return NULL;
}

static map* process_custom_type(ProcessContext ctx, const char* type)
{
    DList* body = get_custom_type_body(ctx.engine, type);
    if (body == NULL) {
        error("[tengine] no such type '%s'", type);
        return NULL;
    }
    map* type_vars = map_create();
    map_set_dispose(type_vars, (void (*)(void*))TEngineVarValue_free);

    printf("\n");
    ctx.print_off += 4;
    for (u64_t i = 0; i < body->size; ++i) {
        Stmt* stmt = (Stmt*)body->data[i];
        if (process_stmt(ctx, stmt, type_vars) != 0) {
            map_destroy(type_vars);
            return NULL;
        }
    }
    return type_vars;
}

static TEngineVarValue* process_type(ProcessContext ctx, const char* varname,
                                     const char* type, map* vars)
{
    const TEngineEmbeddedType* t = find_embedded_type(type);
    if (t != NULL) {
        TEngineVarValue* r = t->process(ctx.engine, varname, ctx.fb);
        TEngineVarValue_pp(ctx.engine, r, ctx.print_off);
        printf("\n");
        return r;
    }

    map* custom_type_vars = process_custom_type(ctx, type);
    if (custom_type_vars == NULL) {
        error("[tengine] unknown type %s", type);
        return NULL;
    }

    TEngineVarValue* v =
        TEngineVarValue_CUSTOM_TYPE_new(varname, custom_type_vars);
    return v;
}

static int evaluate_num_expr(TEngine* engine, map* vars, NumExpr* e,
                             s64_t* oval)
{
    switch (e->t) {
        case NUMEXPR_CONST:
            *oval = e->value;
            return 0;
        case NUMEXPR_VAR: {
            if (!map_contains(vars, e->name)) {
                error("[tengine] no such variable '%s'", e->name);
                return 1;
            }
            TEngineVarValue* value = map_get(vars, e->name);
            if (TEngineVarValue_get_num(value, oval) != 0)
                return 1;
            return 0;
        }
        case NUMEXPR_ADD: {
            s64_t lhs, rhs;
            if (evaluate_num_expr(engine, vars, e->lhs, &lhs) != 0)
                return 1;
            if (evaluate_num_expr(engine, vars, e->rhs, &rhs) != 0)
                return 1;
            *oval = lhs + rhs;
            return 0;
        }
        default:
            panic("unimplemented eval for expr %d", e->t);
    }
    return 1;
}

static int process_array_type(ProcessContext ctx, const char* varname,
                              const char* type, NumExpr* esize, map* vars)
{
    s64_t size;
    if (evaluate_num_expr(ctx.engine, vars, esize, &size) != 0)
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
            printf("[ ");
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
                    printf(", ");
            }
            TEngineVarValue_free(val);
            if (printed++ >= MAX_ARR_PRINT_SIZE) {
                printf("...");
                break;
            }
        }
        if (!is_uint8)
            printf(" ]");
        printf("\n");

        fb_seek(ctx.fb, final_off);
        return 0;
    }

    // Array of custom type
    printf("[");
    for (printed = 0; printed < size; ++printed) {
        map* custom_type_vars = process_custom_type(ctx, type);
        if (custom_type_vars == NULL) {
            error("[tengine] unknown type %s", type);
            return 1;
        }
        if (printed < size - 1) {
            for (int i = 0; i < ctx.print_off + 4; ++i)
                printf(" ");
            printf(", ");
        }
        // TODO save the array!
        map_destroy(custom_type_vars);
    }
    printf("]\n");
    return 0;
}

static int process_FILE_VAR_DECL(ProcessContext ctx, Stmt* stmt, map* vars)
{
    for (int i = 0; i < ctx.print_off; ++i)
        printf(" ");
    printf("%*s: ", yymax_ident_len, stmt->name);

    if (stmt->arr_size == NULL) {
        // Not an array
        TEngineVarValue* val = process_type(ctx, stmt->name, stmt->type, vars);
        if (val == NULL)
            return 1;
        map_set(vars, stmt->name, val);
    } else {
        // Array type
        if (process_array_type(ctx, stmt->name, stmt->type, stmt->arr_size,
                               vars) != 0)
            return 1;
        // TODO: valorize TEngineVarValue
    }
    return 0;
}

static int process_FUNC_CALL(ProcessContext ctx, Stmt* stmt, map* vars)
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
    } else if (strcmp(stmt->fname, "seek") == 0 ||
               strcmp(stmt->fname, "fwd") == 0) {
        REQUIRE_ONE_PARAM
        s64_t off;
        if (evaluate_num_expr(ctx.engine, vars, stmt->params->data[0], &off) !=
            0)
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

static int process_stmt(ProcessContext ctx, Stmt* stmt, map* vars)
{
    switch (stmt->t) {
        case FILE_VAR_DECL:
            return process_FILE_VAR_DECL(ctx, stmt, vars);
        case FUNC_CALL:
            return process_FUNC_CALL(ctx, stmt, vars);
        default: {
            error("[tengine] invalid stmt type %d", stmt->t);
            break;
        }
    }
    return 1;
}

static int process_ast(TEngine* engine, FileBuffer* fb)
{
    if (!engine->ast.proc) {
        error("[tengine] no proc");
        return 1;
    }

    ProcessContext ctx   = {fb, engine, 0};
    DList*         stmts = engine->ast.proc;
    for (u64_t i = 0; i < stmts->size; ++i) {
        Stmt* stmt = (Stmt*)stmts->data[i];
        if (process_stmt(ctx, stmt, engine->proc_variables) != 0)
            return 1;
    }
    return 0;
}

int TEngine_process_file(TEngine* engine, FileBuffer* fb, FILE* f)
{
    yyset_in(f);
    yyset_ctx(&engine->ast);

    if (yyparse() != 0) {
        error("parsing failed");
        return 1;
    }

    return process_ast(engine, fb);
}

void TEngine_pp(TEngine* e)
{
    printf("TEngine\n\n");
    ASTCtx_pp(&e->ast);

    printf("\nProc Variables\n");
    printf("=========\n");
    for (const char* key = map_first(e->proc_variables); key != NULL;
         key             = map_next(e->proc_variables, key)) {
        printf("%s ", key);
        TEngineVarValue* v = map_get(e->proc_variables, key);
        TEngineVarValue_pp(e, v, 0);
    }
    printf("\n");
}
