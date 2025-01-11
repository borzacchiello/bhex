#include <stdio.h>
#include <string.h>

#include "ast.h"

#include <alloc.h>
#include <log.h>
#include <dlist.h>
#include <map.h>

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

Expr* Expr_FUN_CALL_new(const char* fname, DList* params)
{
    if (params && params->size < 1)
        panic("invalid FUNC_CALL, number of parameters is zero, param should "
              "be NULL");

    Expr* e   = bhex_calloc(sizeof(Expr));
    e->t      = EXPR_FUN_CALL;
    e->fname  = bhex_strdup(fname);
    e->params = params;
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

Expr* Expr_SUB_new(Expr* lhs, Expr* rhs)
{
    Expr* e = bhex_calloc(sizeof(Expr));
    e->t    = EXPR_SUB;
    e->lhs  = lhs;
    e->rhs  = rhs;
    return e;
}

Expr* Expr_MUL_new(Expr* lhs, Expr* rhs)
{
    Expr* e = bhex_calloc(sizeof(Expr));
    e->t    = EXPR_MUL;
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

Expr* Expr_BLT_new(Expr* lhs, Expr* rhs)
{
    Expr* e = bhex_calloc(sizeof(Expr));
    e->t    = EXPR_BLT;
    e->lhs  = lhs;
    e->rhs  = rhs;
    return e;
}

Expr* Expr_BLE_new(Expr* lhs, Expr* rhs)
{
    Expr* e = bhex_calloc(sizeof(Expr));
    e->t    = EXPR_BLE;
    e->lhs  = lhs;
    e->rhs  = rhs;
    return e;
}

Expr* Expr_BGT_new(Expr* lhs, Expr* rhs)
{
    Expr* e = bhex_calloc(sizeof(Expr));
    e->t    = EXPR_BGT;
    e->lhs  = lhs;
    e->rhs  = rhs;
    return e;
}

Expr* Expr_BGE_new(Expr* lhs, Expr* rhs)
{
    Expr* e = bhex_calloc(sizeof(Expr));
    e->t    = EXPR_BGE;
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
        case EXPR_FUN_CALL:
            r->fname = bhex_strdup(r->fname);
            if (e->params) {
                r->params = DList_new();
                for (u64_t i = 0; i < e->params->size; ++i)
                    DList_add(r->params, Expr_dup(e->params->data[i]));
            }
            break;
        case EXPR_VARCHAIN:
            r->chain = DList_new();
            for (u64_t i = 0; i < e->chain->size; ++i)
                DList_add(r->chain, bhex_strdup(e->chain->data[i]));
            break;
        case EXPR_ADD:
        case EXPR_SUB:
        case EXPR_MUL:
        case EXPR_BEQ:
        case EXPR_BLT:
        case EXPR_BLE:
        case EXPR_BGT:
        case EXPR_BGE:
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
            bhex_free(e->chain);
            break;
        case EXPR_FUN_CALL:
            if (e->params) {
                DList_foreach(e->params, (void (*)(void*))Expr_free);
                DList_deinit(e->params);
                bhex_free(e->params);
            }
            bhex_free(e->fname);
            break;
        case EXPR_ADD:
        case EXPR_SUB:
        case EXPR_MUL:
        case EXPR_BEQ:
        case EXPR_BLT:
        case EXPR_BLE:
        case EXPR_BGT:
        case EXPR_BGE:
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
        case EXPR_FUN_CALL:
            printf("%s(", e->fname);
            if (e->params && e->params->size > 0) {
                printf("%s", (char*)e->params->data[0]);
                for (u64_t i = 1; i < e->params->size; ++i)
                    printf(", %s", (char*)e->params->data[i]);
            }
            printf(")");
            break;
        case EXPR_ADD:
            printf("( ");
            Expr_pp(e->lhs);
            printf(" + ");
            Expr_pp(e->rhs);
            printf(" )");
            break;
        case EXPR_SUB:
            printf("( ");
            Expr_pp(e->lhs);
            printf(" - ");
            Expr_pp(e->rhs);
            printf(" )");
            break;
        case EXPR_MUL:
            printf("( ");
            Expr_pp(e->lhs);
            printf(" * ");
            Expr_pp(e->rhs);
            printf(" )");
            break;
        case EXPR_BEQ:
            printf("( ");
            Expr_pp(e->lhs);
            printf(" == ");
            Expr_pp(e->rhs);
            printf(" )");
            break;
        case EXPR_BLT:
            printf("( ");
            Expr_pp(e->lhs);
            printf(" < ");
            Expr_pp(e->rhs);
            printf(" )");
            break;
        case EXPR_BLE:
            printf("( ");
            Expr_pp(e->lhs);
            printf(" <= ");
            Expr_pp(e->rhs);
            printf(" )");
            break;
        case EXPR_BGT:
            printf("( ");
            Expr_pp(e->lhs);
            printf(" > ");
            Expr_pp(e->rhs);
            printf(" )");
            break;
        case EXPR_BGE:
            printf("( ");
            Expr_pp(e->lhs);
            printf(" >= ");
            Expr_pp(e->rhs);
            printf(" )");
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

Stmt* Stmt_LOCAL_VAR_DECL_new(const char* name, Expr* value)
{
    Stmt* stmt        = bhex_calloc(sizeof(Stmt));
    stmt->t           = LOCAL_VAR_DECL;
    stmt->local_name  = bhex_strdup(name);
    stmt->local_value = value;
    return stmt;
}

Stmt* Stmt_LOCAL_VAR_ASS_new(const char* name, Expr* value)
{
    Stmt* stmt = Stmt_LOCAL_VAR_DECL_new(name, value);
    stmt->t    = LOCAL_VAR_ASS;
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
    Stmt* stmt = bhex_calloc(sizeof(Stmt));
    stmt->t    = STMT_IF;
    stmt->cond = cond;
    stmt->body = b;
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

Stmt* Stmt_WHILE_new(Expr* cond, struct Block* b)
{
    Stmt* stmt = bhex_calloc(sizeof(Stmt));
    stmt->t    = STMT_WHILE;
    stmt->cond = cond;
    stmt->body = b;
    return stmt;
}

Stmt* Stmt_BREAK_new(void)
{
    Stmt* stmt = bhex_calloc(sizeof(Stmt));
    stmt->t    = STMT_BREAK;
    return stmt;
}

static void FILE_VAR_DECL_free(Stmt* stmt)
{
    bhex_free(stmt->type);
    bhex_free(stmt->name);
    if (stmt->arr_size)
        Expr_free(stmt->arr_size);
}

static void LOCAL_VAR_DECL_free(Stmt* stmt)
{
    bhex_free(stmt->local_name);
    Expr_free(stmt->local_value);
}

static void VOID_FUNC_CALL_free(Stmt* stmt)
{
    bhex_free(stmt->fname);
    if (stmt->params) {
        DList_foreach(stmt->params, (void (*)(void*))Expr_free);
        DList_deinit(stmt->params);
        bhex_free(stmt->params);
    }
}

static void STMT_IF_WHILE_free(Stmt* stmt)
{
    Expr_free(stmt->cond);
    Block_free(stmt->body);
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
        case LOCAL_VAR_DECL:
        case LOCAL_VAR_ASS:
            LOCAL_VAR_DECL_free(stmt);
            break;
        case VOID_FUNC_CALL:
            VOID_FUNC_CALL_free(stmt);
            break;
        case STMT_IF:
        case STMT_WHILE:
            STMT_IF_WHILE_free(stmt);
            break;
        case STMT_IF_ELSE:
            STMT_IF_ELSE_free(stmt);
            break;
        case STMT_BREAK:
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
        case LOCAL_VAR_DECL:
            printf("  local %s = ", stmt->local_name);
            Expr_pp(stmt->local_value);
            printf(";\n");
            break;
        case LOCAL_VAR_ASS:
            printf("  %s = ", stmt->local_name);
            Expr_pp(stmt->local_value);
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
            Block_pp(stmt->body);
            break;
        case STMT_IF_ELSE:
            printf("if (");
            Expr_pp(stmt->if_else_cond);
            printf(")\n");
            Block_pp(stmt->if_else_true_body);
            printf("else");
            Block_pp(stmt->if_else_false_body);
            break;
        case STMT_WHILE:
            printf("while (");
            Expr_pp(stmt->cond);
            printf(")\n");
            Block_pp(stmt->body);
            break;
        case STMT_BREAK:
            printf("break;");
            break;
        default:
            panic("unknown stmt type %d", stmt->t);
    }
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
    DList_foreach(b->stmts, (void (*)(void*))Stmt_free);
    DList_deinit(b->stmts);
    bhex_free(b->stmts);
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

Enum* Enum_new(const char* type, DList* entries, int isor)
{
    Enum* e    = bhex_calloc(sizeof(Enum));
    e->type    = bhex_strdup(type);
    e->entries = entries;
    e->isor    = isor;
    return e;
}

const char* Enum_find_const(Enum* e, u64_t c)
{
    if (!e->isor) {
        for (u64_t i = 0; i < e->entries->size; ++i) {
            EnumEntry* ee = e->entries->data[i];
            if (ee->value == c)
                return ee->name;
        }
    } else {
        if (c == 0)
            return "NONE";

        // TODO: fix this code, it is horrible
        static char  tmp[1024];
        static u64_t written = 0;
        memset(tmp, 0, sizeof(tmp));
        written = 0;

        for (u64_t i = 0; i < e->entries->size; ++i) {
            EnumEntry* ee = e->entries->data[i];
            if (ee->value & c) {
                u64_t n = strlen(ee->name);
                if (n + 3 + written > sizeof(tmp) - 5) {
                    written += 4;
                    strcat(tmp, " ...");
                    break;
                }
                if (written > 0) {
                    strcat(tmp, " | ");
                    written += 3;
                }
                strcat(tmp, ee->name);
                written += n;
            }
        }
        if (written == 0)
            return NULL;
        return tmp;
    }
    return NULL;
}

void Enum_free(Enum* e)
{
    if (!e)
        return;
    bhex_free(e->type);
    DList_foreach(e->entries, (void (*)(void*))EnumEntry_free);
    DList_deinit(e->entries);
    bhex_free(e->entries);
    bhex_free(e);
}

ASTCtx* ASTCtx_new(void)
{
    ASTCtx* ctx  = bhex_calloc(sizeof(ASTCtx));
    ctx->proc    = NULL;
    ctx->structs = map_create();
    map_set_dispose(ctx->structs, (void (*)(void*))Block_free);
    ctx->enums = map_create();
    map_set_dispose(ctx->enums, (void (*)(void*))Enum_free);
    return ctx;
}

void ASTCtx_delete(ASTCtx* ctx)
{
    if (!ctx)
        return;

    if (ctx->proc)
        Block_free(ctx->proc);
    map_destroy(ctx->structs);
    map_destroy(ctx->enums);
    bhex_free(ctx);
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
