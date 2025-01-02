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

/*
 * Variables Values
 */

typedef enum TEngineVarType {
    UNUM = 500,
    SNUM,
} TEngineVarType;

typedef struct TEngineVarValue {
    TEngineVarType t;
    union {
        struct {
            u64_t unum;
            u32_t unum_size;
        };
        struct {
            s64_t snum;
            u32_t snum_size;
        };
    };
} TEngineVarValue;

TEngineVarValue* TEngineVarValue_UNUM_new(u64_t v, u32_t size)
{
    TEngineVarValue* r = bhex_calloc(sizeof(TEngineVarValue));
    r->t               = UNUM;
    r->unum            = v;
    r->unum_size       = size;
    return r;
}

TEngineVarValue* TEngineVarValue_SNUM_new(s64_t v, u32_t size)
{
    TEngineVarValue* r = bhex_calloc(sizeof(TEngineVarValue));
    r->t               = SNUM;
    r->snum            = v;
    r->snum_size       = size;
    return r;
}

int TEngineVarValue_get_num(TEngineVarValue* v, s64_t* onum)
{
    switch (v->t) {
        case UNUM:
            if ((v->unum >> 63) != 0) {
                error("TEngineVarValue_get_num: the number '%llu' is too big "
                      "to fit a TEngine num\n",
                      v->unum);
                return 1;
            }
            *onum = (s64_t)v->unum;
            return 0;
        case SNUM:
            *onum = v->snum;
            return 0;
        default:
            panic("invalid type in TEngineVarValue_get_num");
    }
    return 1;
}

void TEngineVarValue_free(TEngineVarValue* v)
{
    switch (v->t) {
        case UNUM:
        case SNUM:
            break;
        default:
            panic("invalid type in TEngineVarValue_free");
    }
    bhex_free(v);
}

void TEngineVarValue_pp(TEngine* e, TEngineVarValue* v)
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
        default:
            panic("invalid type in TEngineVarValue_pp");
    }
}

/*
 * Embedded Types Valorizers
 */

typedef struct TEngineEmbeddedType {
    const char name[MAX_IDENT_SIZE];
    TEngineVarValue* (*process)(TEngine*, FileBuffer*);
} TEngineEmbeddedType;

static TEngineVarValue* uint_process(TEngine* engine, const u8_t* buf,
                                     u32_t size)
{
    u64_t v = 0;
    for (u32_t i = 0; i < size; ++i) {
        v |= (u64_t)buf[i] << ((engine->endianess == TE_BIG_ENDIAN)
                                   ? ((size - i - 1) * 8)
                                   : (i * 8));
    }
    return TEngineVarValue_UNUM_new(v, size);
}

static TEngineVarValue* int_process(TEngine* engine, const u8_t* buf,
                                    u32_t size)
{
    u64_t v = 0;
    for (u32_t i = 0; i < size; ++i) {
        v |= (u64_t)buf[i] << ((engine->endianess == TE_BIG_ENDIAN)
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
    return TEngineVarValue_SNUM_new(sv, size);
}

#define GEN_INT_PRINT(name, size, signed)                                      \
    static TEngineVarValue* name##_process(TEngine* engine, FileBuffer* fb)    \
    {                                                                          \
        const u8_t* buf = fb_read(fb, size);                                   \
        fb_seek(fb, fb->off + size);                                           \
        if (buf == NULL)                                                       \
            return NULL;                                                       \
        if (!signed)                                                           \
            return uint_process(engine, buf, size);                            \
        return int_process(engine, buf, size);                                 \
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
    engine->variables    = map_create();
    engine->endianess    = TE_LITTLE_ENDIAN;
    engine->print_in_hex = 1;

    map_set_disposte(engine->variables, (void (*)(void*))TEngineVarValue_free);
}

void TEngine_deinit(TEngine* engine)
{
    ASTCtx_deinit(&engine->ast);
    map_destroy(engine->variables);
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

static TEngineVarValue* process_type(TEngine* engine, const char* type,
                                     FileBuffer* fb)
{
    const TEngineEmbeddedType* t = find_embedded_type(type);
    if (t != NULL)
        return t->process(engine, fb);

    // TODO check custom types
    error("[tengine] unknown type %s\n", type);
    return NULL;
}

static int evaluate_num_expr(TEngine* engine, NumExpr* e, s64_t* oval)
{
    switch (e->t) {
        case NUMEXPR_CONST:
            *oval = e->value;
            return 0;
        case NUMEXPR_VAR: {
            if (!map_contains(engine->variables, e->name)) {
                error("[tengine] no such variable '%s'", e->name);
                return 1;
            }
            TEngineVarValue* value = map_get(engine->variables, e->name);
            if (TEngineVarValue_get_num(value, oval) != 0)
                return 1;
            return 0;
        }
        case NUMEXPR_ADD: {
            s64_t lhs, rhs;
            if (evaluate_num_expr(engine, e->lhs, &lhs) != 0)
                return 1;
            if (evaluate_num_expr(engine, e->rhs, &rhs) != 0)
                return 1;
            *oval = lhs + rhs;
            return 0;
        }
        default:
            panic("unimplemented eval for expr %d", e->t);
    }
    return 1;
}

static int process_array_type(TEngine* engine, const char* type, NumExpr* esize,
                              FileBuffer* fb)
{
    s64_t size;
    if (evaluate_num_expr(engine, esize, &size) != 0)
        return 1;
    if (size < 0) {
        error("[tengine] invalid array size: %lld", size);
        return 1;
    }
    if ((u64_t)size > fb->size - fb->off) {
        error("[tengine] invalid array size: %lld, it is bigger than the "
              "remaining file size",
              size);
        return 1;
    }

    u64_t final_off = fb->off + (u64_t)size;

    // Let's threat uint8_t arrays as byte arrays, we will print them in hex
    int is_uint8 = strcmp(type, "uint8_t") == 0;

    const TEngineEmbeddedType* t       = find_embedded_type(type);
    s64_t                      printed = 0;
    if (t != NULL) {
        if (!is_uint8)
            printf("[ ");
        while (printed < size) {
            TEngineVarValue* val = t->process(engine, fb);
            if (val == NULL)
                return 1;
            if (is_uint8) {
                int tmp = engine->print_in_hex;
                TEngineVarValue_pp(engine, val);
                engine->print_in_hex = tmp;
            } else {
                TEngineVarValue_pp(engine, val);
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

        fb_seek(fb, final_off);
        return 0;
    }

    // TODO check custom types
    error("[tengine] unknown type %s", type);
    return 1;
}

static int process_FILE_VAR_DECL(TEngine* engine, Stmt* stmt, FileBuffer* fb)
{
    printf("%*s: ", yymax_ident_len, stmt->name);
    if (stmt->arr_size == NULL) {
        // Not an array
        TEngineVarValue* val = process_type(engine, stmt->type, fb);
        if (val == NULL)
            return 1;
        TEngineVarValue_pp(engine, val);

        map_set(engine->variables, stmt->name, val);
    } else {
        // Array type
        if (process_array_type(engine, stmt->type, stmt->arr_size, fb) != 0)
            return 1;

        // TODO: valorize TEngineVarValue
    }
    printf("\n");
    return 0;
}

static int process_stmt(TEngine* engine, Stmt* stmt, FileBuffer* fb)
{
    switch (stmt->t) {
        case FILE_VAR_DECL:
            return process_FILE_VAR_DECL(engine, stmt, fb);
        default: {
            error("[tengine] invalid stmt type %d", stmt->t);
            break;
        }
    }
    return 1;
}

static int process_ast(TEngine* engine, FileBuffer* fb)
{
    if (engine->ast.proc) {
        DList* stmts = engine->ast.proc;
        for (u64_t i = 0; i < stmts->size; ++i) {
            Stmt* stmt = (Stmt*)stmts->data[i];
            if (process_stmt(engine, stmt, fb) != 0)
                return 1;
        }
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

    printf("\nVariables\n");
    printf("=========\n");
    for (const char* key = map_first(e->variables); key != NULL;
         key             = map_next(e->variables, key)) {
        printf("%s ", key);
        TEngineVarValue* v = map_get(e->variables, key);
        TEngineVarValue_pp(e, v);
        printf("\n");
    }
    printf("\n");
}
