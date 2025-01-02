#ifndef AST_H
#define AST_H

#include "../dlist.h"
#include "map.h"

#define MAX_IDENT_SIZE 32

typedef enum ASTNumExprType {
    NUMEXPR_CONST = 200,
    NUMEXPR_VAR,
    NUMEXPR_ADD,
} ASTNumExprType;

typedef struct NumExpr {
    ASTNumExprType t;
    union {
        // NUMEXPR_CONST
        s64_t value;
        // EXPR_VAR
        char* name;
        struct {
            // EXPR_ADD
            struct NumExpr* lhs;
            struct NumExpr* rhs;
        };
    };
} NumExpr;

NumExpr* NumExpr_CONST_new(s64_t v);
NumExpr* NumExpr_VAR_new(const char* var);
NumExpr* NumExpr_ADD_new(NumExpr* lhs, NumExpr* rhs);
NumExpr* NumExpr_dup(NumExpr* e);
void     NumExpr_free(NumExpr* e);

typedef enum ASTStmtType {
    FILE_VAR_DECL =
        100, // File variable declaration (content is taken from FileBuffer)
} ASTStmtType;

typedef struct Stmt {
    ASTStmtType t;
    union {
        struct {
            // FILE_VAR_DECL
            char*    type;
            char*    name;
            NumExpr* arr_size;
        };
    };
} Stmt;

Stmt* Stmt_FILE_VAR_DECL_new(const char* type, const char* name, NumExpr* size);
void  Stmt_free(Stmt* stmt);

typedef struct ASTCtx {
    // proc { ... } => List of Stmt*
    DList* proc;

    // struct XXX { ... } => Map of name to CustomStruct*
    map* structs;
} ASTCtx;

void ASTCtx_init(ASTCtx* ctx);
void ASTCtx_deinit(ASTCtx* ctx);

// Debug print routines
void NumExpr_pp(NumExpr* e);
void Stmt_pp(Stmt* stmt);
void ASTCtx_pp(ASTCtx* ctx);

#endif
