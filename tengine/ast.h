#ifndef AST_H
#define AST_H

#include "dlist.h"
#include "map.h"

#define MAX_IDENT_SIZE 32

typedef enum ASTExprType {
    EXPR_CONST = 200,
    EXPR_VAR,
    EXPR_VARCHAIN,
    EXPR_ADD,
    EXPR_BEQ,
} ASTExprType;

typedef struct Expr {
    ASTExprType t;
    union {
        // EXPR_CONST
        s64_t value;
        // EXPR_VAR
        char* name;
        // EXPR_VARCHAIN
        DList* chain;
        struct {
            // EXPR_ADD, EXPR_BEQ
            struct Expr* lhs;
            struct Expr* rhs;
        };
    };
} Expr;

Expr* Expr_CONST_new(s64_t v);
Expr* Expr_VAR_new(const char* var);
Expr* Expr_VARCHAIN_new(DList* chain);
Expr* Expr_ADD_new(Expr* lhs, Expr* rhs);
Expr* Expr_BEQ_new(Expr* lhs, Expr* rhs);
Expr* Expr_dup(Expr* e);
void  Expr_free(Expr* e);

typedef enum ASTStmtType {
    FILE_VAR_DECL =
        100, // File variable declaration (content is taken from FileBuffer)
    VOID_FUNC_CALL, // Function call
    STMT_IF,
    STMT_IF_ELSE,
} ASTStmtType;

struct Block;
typedef struct Stmt {
    ASTStmtType t;
    union {
        struct {
            // FILE_VAR_DECL
            char* type;
            char* name;
            Expr* arr_size;
        };
        struct {
            // VOID_FUNC_CALL
            char*  fname;
            DList* params;
        };
        struct {
            // STMT_IF
            Expr*         cond;
            struct Block* if_body;
        };
        struct {
            // STMT_IF_ELSE
            Expr*         if_else_cond;
            struct Block* if_else_true_body;
            struct Block* if_else_false_body;
        };
    };
} Stmt;

Stmt* Stmt_FILE_VAR_DECL_new(const char* type, const char* name, Expr* size);
Stmt* Stmt_VOID_FUNC_CALL_new(const char* name, DList* params);
Stmt* Stmt_STMT_IF_new(Expr* cond, struct Block* trueblock);
Stmt* Stmt_STMT_IF_ELSE_new(Expr* cond, struct Block* trueblock,
                            struct Block* falseblock);
void  Stmt_free(Stmt* stmt);

typedef struct Block {
    DList* stmts;
} Block;

Block* Block_new(DList* stmts);
void   Block_free(Block* b);
void   Block_pp(Block* b);

typedef struct EnumEntry {
    char* name;
    u64_t value;
} EnumEntry;

typedef struct Enum {
    char*  type;
    DList* entries;
} Enum;

EnumEntry* EnumEntry_new(const char* name, u64_t value);
void       EnumEntry_free(EnumEntry* ee);
void       EnumEntry_pp(EnumEntry* ee);

Enum*       Enum_new(const char* type, DList* entries);
const char* Enum_find_const(Enum* e, u64_t c);
void        Enum_free(Enum* ee);

typedef struct ASTCtx {
    // proc { ... } => Block*
    Block* proc;

    // struct XXX { ... } => Map of name to Block*
    map* structs;

    // enum XXX { ... } => Map of name to Enum*
    map* enums;
} ASTCtx;

ASTCtx* ASTCtx_new();
void    ASTCtx_delete(ASTCtx* ctx);

// Debug print routines
void Expr_pp(Expr* e);
void Stmt_pp(Stmt* stmt);
void ASTCtx_pp(ASTCtx* ctx);

#endif
