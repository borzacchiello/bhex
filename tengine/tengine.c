#include <string.h>

#include "../log.h"
#include "tengine.h"
#include "ast.h"

extern int  yyparse();
extern void yyset_in(FILE*);
extern void yyset_ctx(ASTCtx*);
extern int  yymax_ident_len;

typedef struct TEngineEmbeddedType {
    const char name[MAX_IDENT_SIZE];
    int (*print)(TEngine*, FileBuffer*);
} TEngineEmbeddedType;

static void uint_print(TEngine* engine, const u8_t* buf, u32_t size)
{
    u64_t v = 0;
    for (u32_t i = 0; i < size; ++i) {
        v |= (u64_t)buf[i] << ((engine->endiness == BIG_ENDIAN)
                                   ? ((size - i - 1) * 8)
                                   : (i * 8));
    }
    printf("0x%llx", v);
}

static void int_print(TEngine* engine, const u8_t* buf, u32_t size)
{
    u64_t v = 0;
    for (u32_t i = 0; i < size; ++i) {
        v |= (u64_t)buf[i] << ((engine->endiness == BIG_ENDIAN)
                                   ? ((size - i - 1) * 8)
                                   : (i * 8));
    }
    switch (size) {
        case 1:
            printf("%d", (s8_t)v);
            break;
        case 2:
            printf("%d", (s16_t)v);
            break;
        case 4:
            printf("%d", (s32_t)v);
            break;
        case 8:
            printf("%lld", (s64_t)v);
            break;
        default:
            panic("invalid size (%u) in 'int_print'", size);
    }
}

#define GEN_INT_PRINT(name, size, signed)                                      \
    static int name##_process(TEngine* engine, FileBuffer* fb)                 \
    {                                                                          \
        const u8_t* buf = fb_read(fb, size);                                   \
        fb_seek(fb, fb->off + size);                                           \
        if (buf == NULL)                                                       \
            return 1;                                                          \
        if (!signed)                                                           \
            uint_print(engine, buf, size);                                     \
        else                                                                   \
            int_print(engine, buf, size);                                      \
        return 0;                                                              \
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

void TEngine_init(TEngine* engine)
{
    ASTCtx_init(&engine->ast);
    engine->endiness = LITTLE_ENDIAN;
}

void TEngine_deinit(TEngine* engine) { ASTCtx_deinit(&engine->ast); }

int TEngine_process_filename(TEngine* engine, FileBuffer* fb,
                             const char* template)
{
    FILE* f = fopen(template, "r");
    if (f == NULL) {
        error("unable to open template file '%s'", template);
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

static int process_type(TEngine* engine, const char* type, FileBuffer* fb)
{
    const TEngineEmbeddedType* t = find_embedded_type(type);
    if (t != NULL)
        return t->print(engine, fb);

    // TODO check custom types
    error("[tengine] unknown type %s\n", type);
    return 1;
}

static int process_array_type(TEngine* engine, const char* type, u32_t size,
                              FileBuffer* fb)
{
    const TEngineEmbeddedType* t = find_embedded_type(type);
    if (t != NULL) {
        printf("[ ");
        while (size != 0) {
            if (t->print(engine, fb) != 0)
                return 1;
            if (size-- != 1)
                printf(", ");
        }
        printf(" ]");
        return 0;
    }

    // TODO check custom types
    error("[tengine] unknown type %s\n", type);
    return 1;
}

static int process_FILE_VAR_DECL(TEngine* engine, Stmt* stmt, FileBuffer* fb)
{
    printf("%*s: ", yymax_ident_len, stmt->name);
    if (stmt->arr_size == 1) {
        // Not an array
        if (process_type(engine, stmt->type, fb) != 0)
            return 1;
    } else {
        // Array type
        if (process_array_type(engine, stmt->type, stmt->arr_size, fb) != 0)
            return 1;
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
