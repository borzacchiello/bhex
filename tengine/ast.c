#include <stdio.h>
#include <string.h>

#include "ast.h"
#include "defs.h"
#include "util/byte_to_str.h"

#include <alloc.h>
#include <log.h>
#include <dlist.h>
#include <map.h>

Expr* Expr_SCONST_new(s64_t v, u8_t size)
{
    Expr* e         = bhex_calloc(sizeof(Expr));
    e->t            = EXPR_SCONST;
    e->sconst_value = v;
    e->sconst_size  = size;
    return e;
}

Expr* Expr_UCONST_new(u64_t v, u8_t size)
{
    Expr* e         = bhex_calloc(sizeof(Expr));
    e->t            = EXPR_UCONST;
    e->uconst_value = v;
    e->uconst_size  = size;
    return e;
}

Expr* Expr_ENUM_CONST_new(const char* enum_name, const char* enum_field)
{
    Expr* e       = bhex_calloc(sizeof(Expr));
    e->t          = EXPR_ENUM_CONST;
    e->enum_name  = bhex_strdup(enum_name);
    e->enum_field = bhex_strdup(enum_field);
    return e;
}

Expr* Expr_STRING_new(const u8_t* str, u32_t size)
{
    Expr* e    = bhex_calloc(sizeof(Expr));
    e->t       = EXPR_STRING;
    e->str     = bhex_calloc(size + 1);
    e->str_len = size;
    memcpy(e->str, str, size);
    return e;
}

Expr* Expr_VAR_new(const char* var)
{
    Expr* e = bhex_calloc(sizeof(Expr));
    e->t    = EXPR_VAR;
    e->name = bhex_strdup(var);
    return e;
}

Expr* Expr_SUBSCR_new(Expr* ee, const char* name)
{
    Expr* e        = bhex_calloc(sizeof(Expr));
    e->t           = EXPR_SUBSCR;
    e->subscr_e    = ee;
    e->subscr_name = bhex_strdup(name);
    return e;
}

Expr* Expr_ARRAY_SUB_new(Expr* e, Expr* n)
{
    Expr* r        = bhex_calloc(sizeof(Expr));
    r->t           = EXPR_ARRAY_SUB;
    r->array_sub_e = e;
    r->array_sub_n = n;
    return r;
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

Expr* Expr_AND_new(Expr* lhs, Expr* rhs)
{
    Expr* e = bhex_calloc(sizeof(Expr));
    e->t    = EXPR_AND;
    e->lhs  = lhs;
    e->rhs  = rhs;
    return e;
}

Expr* Expr_OR_new(Expr* lhs, Expr* rhs)
{
    Expr* e = bhex_calloc(sizeof(Expr));
    e->t    = EXPR_OR;
    e->lhs  = lhs;
    e->rhs  = rhs;
    return e;
}

Expr* Expr_XOR_new(Expr* lhs, Expr* rhs)
{
    Expr* e = bhex_calloc(sizeof(Expr));
    e->t    = EXPR_XOR;
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

Expr* Expr_DIV_new(Expr* lhs, Expr* rhs)
{
    Expr* e = bhex_calloc(sizeof(Expr));
    e->t    = EXPR_DIV;
    e->lhs  = lhs;
    e->rhs  = rhs;
    return e;
}

Expr* Expr_MOD_new(Expr* lhs, Expr* rhs)
{
    Expr* e = bhex_calloc(sizeof(Expr));
    e->t    = EXPR_MOD;
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

Expr* Expr_BAND_new(Expr* lhs, Expr* rhs)
{
    Expr* e = bhex_calloc(sizeof(Expr));
    e->t    = EXPR_BAND;
    e->lhs  = lhs;
    e->rhs  = rhs;
    return e;
}

Expr* Expr_BOR_new(Expr* lhs, Expr* rhs)
{
    Expr* e = bhex_calloc(sizeof(Expr));
    e->t    = EXPR_BOR;
    e->lhs  = lhs;
    e->rhs  = rhs;
    return e;
}

Expr* Expr_BNOT_new(Expr* v)
{
    Expr* e  = bhex_calloc(sizeof(Expr));
    e->t     = EXPR_BNOT;
    e->child = v;
    return e;
}

Expr* Expr_dup(Expr* e)
{
    if (!e)
        return NULL;

    Expr* r = bhex_calloc(sizeof(Expr));
    r->t    = e->t;
    switch (e->t) {
        case EXPR_SCONST:
            r->sconst_value = e->sconst_value;
            r->sconst_size  = e->sconst_size;
            break;
        case EXPR_UCONST:
            r->uconst_value = e->uconst_value;
            r->uconst_size  = e->uconst_size;
            break;
        case EXPR_ENUM_CONST:
            r->enum_name  = bhex_strdup(r->enum_name);
            r->enum_field = bhex_strdup(r->enum_field);
            break;
        case EXPR_STRING:
            r->str     = bhex_calloc(e->str_len + 1);
            r->str_len = r->str_len;
            memcpy(r->str, e->str, e->str_len);
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
        case EXPR_SUBSCR:
            r->subscr_e    = Expr_dup(e->subscr_e);
            r->subscr_name = bhex_strdup(e->subscr_name);
            break;
        case EXPR_ARRAY_SUB:
            r->array_sub_e = Expr_dup(e->array_sub_e);
            r->array_sub_n = Expr_dup(e->array_sub_n);
            break;
        case EXPR_ADD:
        case EXPR_SUB:
        case EXPR_MUL:
        case EXPR_AND:
        case EXPR_OR:
        case EXPR_XOR:
        case EXPR_BEQ:
        case EXPR_BLT:
        case EXPR_BLE:
        case EXPR_BGT:
        case EXPR_BGE:
        case EXPR_BAND:
        case EXPR_BOR:
            r->lhs = Expr_dup(e->lhs);
            r->rhs = Expr_dup(e->rhs);
            break;
        case EXPR_BNOT:
            r->child = Expr_dup(e->child);
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
        case EXPR_SCONST:
        case EXPR_UCONST:
            break;
        case EXPR_ENUM_CONST:
            bhex_free(e->enum_name);
            bhex_free(e->enum_field);
            break;
        case EXPR_STRING:
            bhex_free(e->str);
            break;
        case EXPR_VAR:
            bhex_free(e->name);
            break;
        case EXPR_SUBSCR:
            Expr_free(e->subscr_e);
            bhex_free(e->subscr_name);
            break;
        case EXPR_ARRAY_SUB:
            Expr_free(e->array_sub_e);
            Expr_free(e->array_sub_n);
            break;
        case EXPR_FUN_CALL:
            if (e->params)
                DList_destroy(e->params, (void (*)(void*))Expr_free);
            bhex_free(e->fname);
            break;
        case EXPR_ADD:
        case EXPR_SUB:
        case EXPR_MUL:
        case EXPR_DIV:
        case EXPR_MOD:
        case EXPR_AND:
        case EXPR_OR:
        case EXPR_XOR:
        case EXPR_BEQ:
        case EXPR_BLT:
        case EXPR_BLE:
        case EXPR_BGT:
        case EXPR_BGE:
        case EXPR_BAND:
        case EXPR_BOR:
            Expr_free(e->lhs);
            Expr_free(e->rhs);
            break;
        case EXPR_BNOT:
            Expr_free(e->child);
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
        case EXPR_SCONST:
            printf("%lld", e->sconst_value);
            break;
        case EXPR_UCONST:
            printf("%llu", e->uconst_value);
            break;
        case EXPR_STRING:
            printf("'");
            for (u32_t i = 0; i < e->str_len; ++i) {
                if (is_printable_ascii(e->str[i]))
                    printf("%c", e->str[i]);
                else
                    printf("\\x%02x", e->str[i]);
            }
            printf("'");
            break;
        case EXPR_VAR:
            printf("%s", e->name);
            break;
        case EXPR_SUBSCR:
            Expr_pp(e->subscr_e);
            printf(".%s", e->subscr_name);
            break;
        case EXPR_ARRAY_SUB:
            Expr_pp(e->array_sub_e);
            printf("[");
            Expr_pp(e->array_sub_n);
            printf("]");
            break;
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
        case EXPR_DIV:
            printf("( ");
            Expr_pp(e->lhs);
            printf(" / ");
            Expr_pp(e->rhs);
            printf(" )");
            break;
        case EXPR_MOD:
            printf("( ");
            Expr_pp(e->lhs);
            printf(" %% ");
            Expr_pp(e->rhs);
            printf(" )");
            break;
        case EXPR_AND:
            printf("( ");
            Expr_pp(e->lhs);
            printf(" & ");
            Expr_pp(e->rhs);
            printf(" )");
            break;
        case EXPR_OR:
            printf("( ");
            Expr_pp(e->lhs);
            printf(" | ");
            Expr_pp(e->rhs);
            printf(" )");
            break;
        case EXPR_XOR:
            printf("( ");
            Expr_pp(e->lhs);
            printf(" ^ ");
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
        case EXPR_BAND:
            printf("( ");
            Expr_pp(e->lhs);
            printf(" && ");
            Expr_pp(e->rhs);
            printf(" )");
            break;
        case EXPR_BOR:
            printf("( ");
            Expr_pp(e->lhs);
            printf(" || ");
            Expr_pp(e->rhs);
            printf(" )");
            break;
        case EXPR_BNOT:
            printf("!(");
            Expr_pp(e->child);
            printf(")");
            break;
        default:
            panic("unknown expression type %d", e->t);
    }
}

IfCond* IfCond_new(Expr* cond, Block* block)
{
    IfCond* c = bhex_calloc(sizeof(IfCond));
    c->cond   = cond;
    c->block  = block;
    return c;
}

void IfCond_free(IfCond* c)
{
    Expr_free(c->cond);
    Block_free(c->block);
    bhex_free(c);
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

Stmt* Stmt_STMT_IF_new(Expr* cond, Block* block)
{
    Stmt* stmt          = bhex_calloc(sizeof(Stmt));
    stmt->t             = STMT_IF_ELIF_ELSE;
    stmt->if_conditions = DList_new();

    IfCond* c = IfCond_new(cond, block);
    DList_add(stmt->if_conditions, c);
    return stmt;
}

void Stmt_STMT_IF_add_cond(Stmt* stmt, Expr* cond, struct Block* block)
{
    if (stmt->t != STMT_IF_ELIF_ELSE)
        panic("Stmt_STMT_IF_add_cond(): invalid stmt type");

    IfCond* c = IfCond_new(cond, block);
    DList_add(stmt->if_conditions, c);
}

void Stmt_STMT_IF_add_else(Stmt* stmt, struct Block* block)
{
    if (stmt->t != STMT_IF_ELIF_ELSE)
        panic("Stmt_STMT_IF_add_else(): invalid stmt type");

    if (stmt->else_block)
        Block_free(stmt->else_block);
    stmt->else_block = block;
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
    if (stmt->params)
        DList_destroy(stmt->params, (void (*)(void*))Expr_free);
}

static void STMT_IF_WHILE_free(Stmt* stmt)
{
    Expr_free(stmt->cond);
    Block_free(stmt->body);
}

static void STMT_IF_ELIF_ELSE_free(Stmt* stmt)
{
    DList_destroy(stmt->if_conditions, (void (*)(void*))&IfCond_free);
    if (stmt->else_block)
        Block_free(stmt->else_block);
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
        case STMT_WHILE:
            STMT_IF_WHILE_free(stmt);
            break;
        case STMT_IF_ELIF_ELSE:
            STMT_IF_ELIF_ELSE_free(stmt);
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
        case STMT_IF_ELIF_ELSE: {
            if (stmt->if_conditions->size == 0)
                panic("Stmt_pp(): invalid STMT_IF_ELIF_ELSE");
            IfCond* ic = stmt->if_conditions->data[0];
            printf("if (");
            Expr_pp(ic->cond);
            printf(")\n");
            Block_pp(ic->block);
            for (u64_t i = 1; i < stmt->if_conditions->size; ++i) {
                ic = stmt->if_conditions->data[i];
                printf("elif (");
                Expr_pp(ic->cond);
                printf(")\n");
                Block_pp(ic->block);
            }
            if (stmt->else_block) {
                printf("else\n");
                Block_pp(ic->block);
            }
        }
            printf("if (");
            Expr_pp(stmt->cond);
            printf(")\n");
            Block_pp(stmt->body);
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
    DList_destroy(b->stmts, (void (*)(void*))Stmt_free);
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

int Enum_find_value(Enum* e, const char* name, u64_t* o_value)
{
    for (u64_t i = 0; i < e->entries->size; ++i) {
        EnumEntry* ee = e->entries->data[i];
        if (strcmp(ee->name, name) == 0) {
            *o_value = ee->value;
            return 0;
        }
    }
    return 1;
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
    DList_destroy(e->entries, (void (*)(void*))EnumEntry_free);
    bhex_free(e);
}

Function* Function_new(const char* name, DList* params, Block* block)
{
    Function* fn = bhex_calloc(sizeof(Function));
    fn->name     = bhex_strdup(name);
    fn->params   = params;
    fn->block    = block;
    return fn;
}

void Function_free(Function* fn)
{
    if (fn->params)
        DList_destroy(fn->params, (void (*)(void*))bhex_free);
    bhex_free(fn->name);
    Block_free(fn->block);
    bhex_free(fn);
}

ASTCtx* ASTCtx_new(void)
{
    ASTCtx* ctx  = bhex_calloc(sizeof(ASTCtx));
    ctx->proc    = NULL;
    ctx->structs = map_create();
    map_set_dispose(ctx->structs, (void (*)(void*))Block_free);
    ctx->enums = map_create();
    map_set_dispose(ctx->enums, (void (*)(void*))Enum_free);
    ctx->functions = map_create();
    map_set_dispose(ctx->functions, (void (*)(void*))Function_free);
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
    map_destroy(ctx->functions);
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
