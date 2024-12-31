#include <stdio.h>

#include "ast.h"

#include "../alloc.h"
#include "../log.h"

Stmt* Stmt_FILE_VAR_DECL_new(const char* type, const char* name, u32_t size)
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
}

void Stmt_free(Stmt* stmt)
{
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
            if (stmt->arr_size != 1)
                printf("[%u]", stmt->arr_size);
            printf(";\n");
            break;
        default:
            panic("unknown stmt type %d", stmt->t);
    }
}

void ASTCtx_init(ASTCtx* ctx) { ctx->proc = NULL; }

void ASTCtx_deinit(ASTCtx* ctx)
{
    if (ctx->proc) {
        DList_foreach(ctx->proc, (void (*)(void*))Stmt_free);
        DList_deinit(ctx->proc);
        bhex_free(ctx->proc);
    }
}

void ASTCtx_pp(ASTCtx* ctx)
{
    printf("ASTCtx\n");
    printf("======\n");

    printf("proc\n{\n");
    if (ctx->proc) {
        DList_foreach(ctx->proc, (void (*)(void*))Stmt_pp);
    }
    printf("}\n");
}
