#include <stdio.h>
#include <string.h>

#include "ast.h"

#include "../alloc.h"
#include "../log.h"
#include "dlist.h"
#include "map.h"

Expr* Expr_CONST_new(s64_t v)
{
    Expr* e  = bhex_calloc(sizeof(Expr));
    e->t     = EXPR_CONST;
    e->value = v;
    return e;
}

Expr* Expr_VAR_new(const char* var)
{
    Expr* e = bhex_calloc(sizeof(Expr));
    e->t    = EXPR_VAR;
    e->name = bhex_strdup(var);
    return e;
}

Expr* Expr_VARCHAIN_new(DList* chain)
{
    if (chain->size < 2)
        panic("invalid EXPR_VARCHAIN chain size (%llu)", chain->size);

    Expr* e  = bhex_calloc(sizeof(Expr));
    e->t     = EXPR_VARCHAIN;
    e->chain = chain;
    return e;
}

Expr* Expr_ADD_new(Expr* lhs, Expr* rhs)
{
    Expr* e = bhex_calloc(sizeof(Expr));
    e->t    = EXPR_ADD;
    e->lhs  = lhs;
    e->rhs  = rhs;
    return e;
}

Expr* Expr_BEQ_new(Expr* lhs, Expr* rhs)
{
    Expr* e = bhex_calloc(sizeof(Expr));
    e->t    = EXPR_BEQ;
    e->lhs  = lhs;
    e->rhs  = rhs;
    return e;
}

Expr* Expr_dup(Expr* e)
{
    if (!e)
        return NULL;

    Expr* r = bhex_calloc(sizeof(Expr));
    r->t    = e->t;
    switch (e->t) {
        case EXPR_CONST:
            r->value = e->value;
            break;
        case EXPR_VAR:
            r->name = bhex_strdup(e->name);
            break;
        case EXPR_VARCHAIN:
            r->chain = DList_new();
            for (u64_t i = 0; i < e->chain->size; ++i)
                DList_add(r->chain, bhex_strdup(e->chain->data[i]));
            break;
        case EXPR_ADD:
        case EXPR_BEQ:
            r->lhs = Expr_dup(e->lhs);
            r->rhs = Expr_dup(e->rhs);
            break;
        default:
            panic("unknown expression type %d", e->t);
    }
    return r;
}

void Expr_free(Expr* e)
{
    if (!e)
        return;

    switch (e->t) {
        case EXPR_CONST:
            break;
        case EXPR_VAR:
            bhex_free(e->name);
            break;
        case EXPR_VARCHAIN:
            DList_foreach(e->chain, (void (*)(void*))bhex_free);
            DList_deinit(e->chain);
            break;
        case EXPR_ADD:
        case EXPR_BEQ:
            Expr_free(e->lhs);
            Expr_free(e->rhs);
            break;
        default:
            panic("unknown expression type %d", e->t);
    }
    memset(e, 0, sizeof(Expr));
    bhex_free(e);
}

void Expr_pp(Expr* e)
{
    switch (e->t) {
        case EXPR_CONST:
            printf("%lld", e->value);
            break;
        case EXPR_VAR:
            printf("%s", e->name);
            break;
        case EXPR_VARCHAIN: {
            if (e->chain->size < 2)
                panic("invalid EXPR_VARCHAIN chain size (%llu)",
                      e->chain->size);

            printf("%s", (char*)e->chain->data[0]);
            for (u64_t i = 1; i < e->chain->size; ++i)
                printf(".%s", (char*)e->chain->data[i]);
            break;
        }
        case EXPR_ADD:
            Expr_pp(e->lhs);
            printf(" + ");
            Expr_pp(e->rhs);
            break;
        case EXPR_BEQ:
            Expr_pp(e->lhs);
            printf(" == ");
            Expr_pp(e->rhs);
            break;
        default:
            panic("unknown expression type %d", e->t);
    }
}

Stmt* Stmt_FILE_VAR_DECL_new(const char* type, const char* name, Expr* size)
{
    Stmt* stmt     = bhex_calloc(sizeof(Stmt));
    stmt->t        = FILE_VAR_DECL;
    stmt->type     = bhex_strdup(type);
    stmt->name     = bhex_strdup(name);
    stmt->arr_size = size;
    return stmt;
}

Stmt* Stmt_VOID_FUNC_CALL_new(const char* name, DList* params)
{
    Stmt* stmt   = bhex_calloc(sizeof(Stmt));
    stmt->t      = VOID_FUNC_CALL;
    stmt->fname  = bhex_strdup(name);
    stmt->params = params;
    return stmt;
}

Stmt* Stmt_STMT_IF_new(Expr* cond, Block* b)
{
    Stmt* stmt    = bhex_calloc(sizeof(Stmt));
    stmt->t       = STMT_IF;
    stmt->cond    = cond;
    stmt->if_body = b;
    return stmt;
}

Stmt* Stmt_STMT_IF_ELSE_new(Expr* cond, struct Block* trueblock,
                            struct Block* falseblock)
{
    Stmt* stmt               = bhex_calloc(sizeof(Stmt));
    stmt->t                  = STMT_IF_ELSE;
    stmt->if_else_cond       = cond;
    stmt->if_else_true_body  = trueblock;
    stmt->if_else_false_body = falseblock;
    return stmt;
}

static void FILE_VAR_DECL_free(Stmt* stmt)
{
    bhex_free(stmt->type);
    bhex_free(stmt->name);
    if (stmt->arr_size)
        Expr_free(stmt->arr_size);
}

static void VOID_FUNC_CALL_free(Stmt* stmt)
{
    bhex_free(stmt->fname);
    if (stmt->params) {
        DList_foreach(stmt->params, (void (*)(void*))Expr_free);
        bhex_free(stmt->params);
    }
}

static void STMT_IF_free(Stmt* stmt)
{
    Expr_free(stmt->cond);
    Block_free(stmt->if_body);
}

static void STMT_IF_ELSE_free(Stmt* stmt)
{
    Expr_free(stmt->if_else_cond);
    Block_free(stmt->if_else_true_body);
    Block_free(stmt->if_else_false_body);
}

void Stmt_free(Stmt* stmt)
{
    if (!stmt)
        return;

    switch (stmt->t) {
        case FILE_VAR_DECL:
            FILE_VAR_DECL_free(stmt);
            break;
        case VOID_FUNC_CALL:
            VOID_FUNC_CALL_free(stmt);
            break;
        case STMT_IF:
            STMT_IF_free(stmt);
            break;
        case STMT_IF_ELSE:
            STMT_IF_ELSE_free(stmt);
            break;
        default:
            panic("unknown stmt type %d", stmt->t);
    }
    bhex_free(stmt);
}

void Stmt_pp(Stmt* stmt)
{
    switch (stmt->t) {
        case FILE_VAR_DECL:
            printf("  %s %s", stmt->type, stmt->name);
            if (stmt->arr_size != NULL) {
                printf("[");
                Expr_pp(stmt->arr_size);
                printf("]");
            }
            printf(";\n");
            break;
        case VOID_FUNC_CALL:
            printf("  %s(", stmt->fname);
            if (stmt->params) {
                for (u64_t i = 0; i < stmt->params->size; ++i) {
                    Expr* param = stmt->params->data[i];
                    Expr_pp(param);
                    if (i < stmt->params->size - 1)
                        printf(", ");
                }
            }
            printf(");\n");
            break;
        case STMT_IF:
            printf("if (");
            Expr_pp(stmt->cond);
            printf(")\n");
            Block_pp(stmt->if_body);
            break;
        case STMT_IF_ELSE:
            printf("if (");
            Expr_pp(stmt->if_else_cond);
            printf(")\n");
            Block_pp(stmt->if_else_true_body);
            printf("else");
            Block_pp(stmt->if_else_false_body);
            break;
        default:
            panic("unknown stmt type %d", stmt->t);
    }
}

static void dlist_stmts_free(DList* l)
{
    DList_foreach(l, (void (*)(void*))Stmt_free);
    DList_deinit(l);
}

Block* Block_new(DList* stmts)
{
    Block* b = bhex_calloc(sizeof(Block));
    b->stmts = stmts;
    return b;
}

void Block_free(Block* b)
{
    if (!b)
        return;
    dlist_stmts_free(b->stmts);
    bhex_free(b);
}

void Block_pp(Block* b)
{
    printf("{\n");
    DList_foreach(b->stmts, (void (*)(void*))Stmt_pp);
    printf("}\n");
}

EnumEntry* EnumEntry_new(const char* name, u64_t value)
{
    EnumEntry* ee = bhex_calloc(sizeof(EnumEntry));
    ee->name      = bhex_strdup(name);
    ee->value     = value;
    return ee;
}

void EnumEntry_free(EnumEntry* ee)
{
    if (!ee)
        return;
    bhex_free(ee->name);
    bhex_free(ee);
}

void EnumEntry_pp(EnumEntry* ee)
{
    printf("  %s = %llu\n", ee->name, ee->value);
}

static void dlist_enum_entry_free(DList* l)
{
    DList_foreach(l, (void (*)(void*))EnumEntry_free);
    DList_deinit(l);
}

Enum* Enum_new(const char* type, DList* entries)
{
    Enum* e    = bhex_calloc(sizeof(Enum));
    e->type    = bhex_strdup(type);
    e->entries = entries;
    return e;
}

const char* Enum_find_const(Enum* e, u64_t c)
{
    for (u64_t i = 0; i < e->entries->size; ++i) {
        EnumEntry* ee = e->entries->data[i];
        if (ee->value == c)
            return ee->name;
    }
    return NULL;
}

void Enum_free(Enum* e)
{
    if (!e)
        return;
    bhex_free(e->type);
    dlist_enum_entry_free(e->entries);
    bhex_free(e);
}

void ASTCtx_init(ASTCtx* ctx)
{
    ctx->proc    = NULL;
    ctx->structs = map_create();
    map_set_dispose(ctx->structs, (void (*)(void*))Block_free);
    ctx->enums = map_create();
    map_set_dispose(ctx->enums, (void (*)(void*))Enum_free);
}

void ASTCtx_deinit(ASTCtx* ctx)
{
    if (!ctx)
        return;

    if (ctx->proc)
        Block_free(ctx->proc);
    map_destroy(ctx->structs);
    map_destroy(ctx->enums);
}

void ASTCtx_pp(ASTCtx* ctx)
{
    printf("ASTCtx\n");
    printf("======\n");

    printf("\n");
    for (const char* key = map_first(ctx->enums); key != NULL;
         key             = map_next(ctx->enums, key)) {
        Enum* e = map_get(ctx->enums, key);
        printf("enum %s : %s\n{\n", key, e->type);
        DList_foreach(e->entries, (void (*)(void*))EnumEntry_pp);
        printf("}\n");
    }

    printf("\n");
    for (const char* key = map_first(ctx->structs); key != NULL;
         key             = map_next(ctx->structs, key)) {
        printf("struct %s\n", key);
        Block* b = map_get(ctx->structs, key);
        Block_pp(b);
    }

    printf("\n");
    printf("proc\n{\n");
    if (ctx->proc) {
        DList_foreach(ctx->proc->stmts, (void (*)(void*))Stmt_pp);
    }
    printf("}\n");
}
