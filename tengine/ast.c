#include <stdio.h>
#include <string.h>

#include "ast.h"

#include "../alloc.h"
#include "../log.h"
#include "map.h"

NumExpr* NumExpr_CONST_new(s64_t v)
{
    NumExpr* e = bhex_calloc(sizeof(NumExpr));
    e->t       = NUMEXPR_CONST;
    e->value   = v;
    return e;
}

NumExpr* NumExpr_VAR_new(const char* var)
{
    NumExpr* e = bhex_calloc(sizeof(NumExpr));
    e->t       = NUMEXPR_VAR;
    e->name    = bhex_strdup(var);
    return e;
}

NumExpr* NumExpr_ADD_new(NumExpr* lhs, NumExpr* rhs)
{
    NumExpr* e = bhex_calloc(sizeof(NumExpr));
    e->t       = NUMEXPR_ADD;
    e->lhs     = lhs;
    e->rhs     = rhs;
    return e;
}

NumExpr* NumExpr_dup(NumExpr* e)
{
    if (!e)
        return NULL;

    NumExpr* r = bhex_calloc(sizeof(NumExpr));
    switch (e->t) {
        case NUMEXPR_CONST:
            r->value = e->value;
            break;
        case NUMEXPR_VAR:
            r->name = bhex_strdup(e->name);
            break;
        case NUMEXPR_ADD:
            r->lhs = NumExpr_dup(e->lhs);
            r->rhs = NumExpr_dup(e->rhs);
            break;
        default:
            panic("unknown expression type %d", e->t);
    }
    return r;
}

void NumExpr_free(NumExpr* e)
{
    if (!e)
        return;

    switch (e->t) {
        case NUMEXPR_CONST:
            break;
        case NUMEXPR_VAR:
            bhex_free(e->name);
            break;
        case NUMEXPR_ADD:
            NumExpr_free(e->lhs);
            NumExpr_free(e->rhs);
            break;
        default:
            panic("unknown expression type %d", e->t);
    }
    memset(e, 0, sizeof(NumExpr));
    bhex_free(e);
}

void NumExpr_pp(NumExpr* e)
{
    switch (e->t) {
        case NUMEXPR_CONST:
            printf("%lld", e->value);
            break;
        case NUMEXPR_VAR:
            printf("%s", e->name);
            break;
        case NUMEXPR_ADD:
            NumExpr_pp(e->lhs);
            printf(" + ");
            NumExpr_pp(e->rhs);
            break;
        default:
            panic("unknown expression type %d", e->t);
    }
}

Stmt* Stmt_FILE_VAR_DECL_new(const char* type, const char* name, NumExpr* size)
{
    Stmt* stmt     = bhex_calloc(sizeof(Stmt));
    stmt->t        = FILE_VAR_DECL;
    stmt->type     = bhex_strdup(type);
    stmt->name     = bhex_strdup(name);
    stmt->arr_size = size;
    return stmt;
}

static void FILE_VAR_DECL_free(Stmt* stmt)
{
    bhex_free(stmt->type);
    bhex_free(stmt->name);
    if (stmt->arr_size)
        NumExpr_free(stmt->arr_size);
}

void Stmt_free(Stmt* stmt)
{
    if (!stmt)
        return;

    switch (stmt->t) {
        case FILE_VAR_DECL:
            FILE_VAR_DECL_free(stmt);
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
                NumExpr_pp(stmt->arr_size);
                printf("]");
            }
            printf(";\n");
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

void ASTCtx_init(ASTCtx* ctx)
{
    ctx->proc    = NULL;
    ctx->structs = map_create();
    map_set_dispose(ctx->structs, (void (*)(void*))dlist_stmts_free);
}

void ASTCtx_deinit(ASTCtx* ctx)
{
    if (!ctx)
        return;

    if (ctx->proc) {
        dlist_stmts_free(ctx->proc);
        bhex_free(ctx->proc);
    }
    map_destroy(ctx->structs);
}

void ASTCtx_pp(ASTCtx* ctx)
{
    printf("ASTCtx\n");
    printf("======\n");

    printf("\n");
    for (const char* key = map_first(ctx->structs); key != NULL;
         key             = map_next(ctx->structs, key)) {
        printf("struct %s\n{\n", key);
        DList* stmts = map_get(ctx->structs, key);
        DList_foreach(stmts, (void (*)(void*))Stmt_pp);
        printf("}\n");
    }
    printf("\n");

    printf("proc\n{\n");
    if (ctx->proc) {
        DList_foreach(ctx->proc, (void (*)(void*))Stmt_pp);
    }
    printf("}\n");
}
