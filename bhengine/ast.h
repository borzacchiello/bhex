#ifndef AST_H
#define AST_H

#include "defs.h"
#include <dlist.h>
#include <stdio.h>
#include <map.h>

#define MAX_IDENT_SIZE 32

typedef enum ASTExprType {
    EXPR_SCONST = 200,
    EXPR_UCONST,
    EXPR_STRING,
    EXPR_VAR,
    EXPR_SUBSCR,
    EXPR_ENUM_CONST,
    EXPR_ARRAY_SUB,
    EXPR_FUN_CALL,
    EXPR_ADD,
    EXPR_SUB,
    EXPR_MUL,
    EXPR_DIV,
    EXPR_MOD,
    EXPR_AND,
    EXPR_OR,
    EXPR_XOR,
    EXPR_BEQ,
    EXPR_BLT,
    EXPR_BLE,
    EXPR_BGT,
    EXPR_BGE,
    EXPR_BAND,
    EXPR_BOR,
    EXPR_SHL,
    EXPR_SHR,
    EXPR_BNOT
} ASTExprType;

typedef struct Expr {
    ASTExprType t;
    union {
        struct {
            // EXPR_SCONST
            s64_t sconst_value;
            u8_t  sconst_size;
        };
        struct {
            // EXPR_UCONST
            u64_t uconst_value;
            u8_t  uconst_size;
        };
        struct {
            // EXPR_ENUM_CONST
            char* enum_name;
            char* enum_field;
        };
        struct {
            // EXPR_STRING
            u8_t* str;
            u32_t str_len;
        };
        // EXPR_BNOT
        struct Expr* child;
        // EXPR_VAR
        char* name;
        struct {
            // EXPR_SUBSCR
            struct Expr* subscr_e;
            char*        subscr_name;
        };
        struct {
            // EXPR_ARRAY_SUB
            struct Expr* array_sub_e;
            struct Expr* array_sub_n;
        };
        struct {
            // EXPR_ADD, EXPR_SUB, EXPR_BEQ, EXPR_BLT, EXPR_BLE, EXPR_BGT,
            // EXPR_BGE, EXPR_AND, EXPR_OR, EXPR_XOR, EXPR_SHR, EXPR_SHL
            struct Expr* lhs;
            struct Expr* rhs;
        };
        struct {
            // EXPR_FUN_CALL
            char*  fname;
            DList* params;
        };
    };
} Expr;

Expr* Expr_SCONST_new(s64_t v, u8_t size);
Expr* Expr_UCONST_new(u64_t v, u8_t size);
Expr* Expr_ENUM_CONST_new(const char* enum_name, const char* enum_field);
Expr* Expr_STRING_new(const u8_t* str, u32_t size);
Expr* Expr_VAR_new(const char* var);
Expr* Expr_SUBSCR_new(Expr* e, const char* name);
Expr* Expr_ARRAY_SUB_new(Expr* e, Expr* n);
Expr* Expr_FUN_CALL_new(const char* fname, DList* params);
Expr* Expr_ADD_new(Expr* lhs, Expr* rhs);
Expr* Expr_AND_new(Expr* lhs, Expr* rhs);
Expr* Expr_OR_new(Expr* lhs, Expr* rhs);
Expr* Expr_XOR_new(Expr* lhs, Expr* rhs);
Expr* Expr_SHR_new(Expr* lhs, Expr* rhs);
Expr* Expr_SHL_new(Expr* lhs, Expr* rhs);
Expr* Expr_SUB_new(Expr* lhs, Expr* rhs);
Expr* Expr_MUL_new(Expr* lhs, Expr* rhs);
Expr* Expr_DIV_new(Expr* lhs, Expr* rhs);
Expr* Expr_MOD_new(Expr* lhs, Expr* rhs);
Expr* Expr_BEQ_new(Expr* lhs, Expr* rhs);
Expr* Expr_BLT_new(Expr* lhs, Expr* rhs);
Expr* Expr_BLE_new(Expr* lhs, Expr* rhs);
Expr* Expr_BGT_new(Expr* lhs, Expr* rhs);
Expr* Expr_BGE_new(Expr* lhs, Expr* rhs);
Expr* Expr_BAND_new(Expr* lhs, Expr* rhs);
Expr* Expr_BOR_new(Expr* lhs, Expr* rhs);
Expr* Expr_BNOT_new(Expr* e);
Expr* Expr_dup(Expr* e);
void  Expr_free(Expr* e);

typedef struct Type {
    // name of the type
    char* name;
    // if the type is not imported, bhe_name is NULL
    char* bhe_name;
} Type;

Type* Type_new(const char* name, const char* bhe_name);
void  Type_free(Type* t);

typedef enum ASTStmtType {
    FILE_VAR_DECL =
        100, // File variable declaration (content is taken from FileBuffer)
    LOCAL_VAR_DECL,
    LOCAL_VAR_ASS,
    VOID_FUNC_CALL, // Function call
    STMT_IF_ELIF_ELSE,
    STMT_WHILE,
    STMT_BREAK,
    STMT_RETURN,
} ASTStmtType;

struct Block;
typedef struct Stmt {
    ASTStmtType t;
    int         line_of_code;
    int         column;
    union {
        struct {
            // FILE_VAR_DECL
            Type* type;
            char* name;
            Expr* arr_size;
        };
        struct {
            // LOCAL_VAR_DECL, LOCAL_VAR_ASS
            char* local_name;
            Expr* local_value;
        };
        struct {
            // VOID_FUNC_CALL
            char*  fname;
            DList* params;
        };
        struct {
            // STMT_WHILE
            Expr*         cond;
            struct Block* body;
        };
        struct {
            // STMT_IF_ELIF_ELSE
            DList*        if_conditions;
            struct Block* else_block;
        };
    };
} Stmt;

Stmt* Stmt_FILE_VAR_DECL_new(Type* type, const char* name, Expr* size);
Stmt* Stmt_LOCAL_VAR_DECL_new(const char* name, Expr* value);
Stmt* Stmt_LOCAL_VAR_ASS_new(const char* name, Expr* value);
Stmt* Stmt_VOID_FUNC_CALL_new(const char* name, DList* params);
Stmt* Stmt_STMT_IF_new(Expr* cond, struct Block* block);
void  Stmt_STMT_IF_add_cond(Stmt* stmt, Expr* cond, struct Block* block);
void  Stmt_STMT_IF_add_else(Stmt* stmt, struct Block* block);
Stmt* Stmt_WHILE_new(Expr* cond, struct Block* block);
Stmt* Stmt_BREAK_new();
Stmt* Stmt_RETURN_new();
void  Stmt_set_source_info(Stmt* stmt, int loc, int col);
void  Stmt_free(Stmt* stmt);

typedef struct Block {
    DList* stmts;
} Block;

Block* Block_new(DList* stmts);
void   Block_free(Block* b);
void   Block_pp(Block* b);

typedef struct IfCond {
    Expr*  cond;
    Block* block;
} IfCond;

IfCond* IfCond_new(Expr* cond, Block* block);
void    IfCond_free(IfCond* c);

typedef struct EnumEntry {
    char* name;
    u64_t value;
} EnumEntry;

typedef struct Enum {
    char*  type;
    DList* entries;
    int    isor;
} Enum;

EnumEntry* EnumEntry_new(const char* name, u64_t value);
void       EnumEntry_free(EnumEntry* ee);
void       EnumEntry_pp(EnumEntry* ee);

Enum* Enum_new(const char* type, DList* entries, int isor);
int   Enum_find_value(Enum* e, const char* name, u64_t* o_value);
char* Enum_find_const(Enum* e, u64_t c);
void  Enum_free(Enum* ee);

typedef struct Function {
    char*  name;
    DList* params;
    Block* block;
} Function;

Function* Function_new(const char* name, DList* params, Block* block);
void      Function_free(Function* fn);

typedef struct ASTCtx {
    // proc { ... } => Block*
    Block* proc;

    // proc NAME { ... } => Block*
    map* named_procs;

    // struct XXX { ... } => Map of name to Block*
    map* structs;

    // enum XXX { ... } => Map of name to Enum*
    map* enums;

    // fn XXX ( ... ) { ... } => Map of name to Function*
    map* functions;

    // the maximum length of any file var name found while parsing the AST
    u64_t max_fvar_len;

    // source code, can be NULL
    char* source;
} ASTCtx;

ASTCtx* ASTCtx_new();
void    ASTCtx_delete(ASTCtx* ctx);

ASTCtx* bhengine_parse_filename(const char* bhe);
ASTCtx* bhengine_parse_file(FILE* f);
ASTCtx* bhengine_parse_string(const char* str);

// Debug print routines
void Expr_pp(Expr* e);
void Stmt_pp(Stmt* stmt);
void ASTCtx_pp(ASTCtx* ctx);

#endif
