#ifndef AST_H
#define AST_H

#include "../dlist.h"

#define MAX_IDENT_SIZE 32

typedef enum ASTStmtType {
    FILE_VAR_DECL =
        100, // File variable declaration (content is taken from FileBuffer)
} ASTStmtType;

typedef struct Stmt {
    ASTStmtType t;
    union {
        struct {
            // FILE_VAR_DECL
            char* type;
            char* name;
            // TODO: arr_size should be a generic expression
            u32_t arr_size;
        };
    };
} Stmt;

Stmt* Stmt_FILE_VAR_DECL_new(const char* type, const char* name, u32_t size);
void  Stmt_free(Stmt* stmt);

typedef struct ASTCtx {
    // proc { ... } => List of Stmt*
    DList* proc;
} ASTCtx;

void ASTCtx_init(ASTCtx* ctx);
void ASTCtx_deinit(ASTCtx* ctx);

// Debug print routines
void Stmt_pp(Stmt* stmt);
void ASTCtx_pp(ASTCtx* ctx);

#endif
