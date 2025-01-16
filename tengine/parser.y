%{

#include <stdio.h>

#include <alloc.h>
#include <log.h>
#include "ast.h"

extern int   yylex();
extern char* yytext;
extern char  yystrval[MAX_IDENT_SIZE];
extern s64_t yysnumval;
extern u64_t yyunumval;
extern int   yynumsize;
extern int   yymax_ident_len;

static ASTCtx* g_ctx;

void yyset_ctx(ASTCtx* ctx)
{
    g_ctx = ctx;
}

void yyerror(const char *s)
{
    error("[tengine parser] %s [near token '%s']", s, yytext);
}

%}

// Represents the many different ways we can access our data
%union {
    Stmt*    stmt;
    DList*   stmts;
    DList*   params;
    DList*   enum_list;
    DList*   varchain;
    Expr*    expr;
    char*    ident;
}

// Terminal tokens
%token TPROC TLOCAL TSTRUCT TENUM TORENUM TIF TELSE TWHILE TBREAK
%token TIDENTIFIER TSNUM64 TUNUM8
%token TCLBRACE TCRBRACE TLBRACE TRBRACE SQLBRACE SQRBRACE 
%token TSEMICOLON TCOLON TCOMMA TDOT
%token TADD TSUB TMUL TBEQ TBGT TBGE TBLT TBLE TEQUAL

// Non terminal tokens types
%type <stmt>      stmt fvar_decl lvar_decl lvar_ass void_fcall if if_else while break
%type <stmts>     stmts
%type <enum_list> enum_list
%type <varchain>  varchain
%type <ident>     ident
%type <expr>      expr num
%type <params>    params

// Operator precedence
%left TMUL TADD TSUB TBEQ TBLT TBLE TBGT TBGE

// The grammar
%%

program     :
            | program TPROC TLBRACE stmts TRBRACE   {
                                                        if (g_ctx->proc != NULL)
                                                            // You can only have one proc
                                                            YYABORT;
                                                        g_ctx->proc = Block_new($4);
                                                    }
            | program TSTRUCT ident TLBRACE stmts TRBRACE 
                                                    {
                                                        map_set(g_ctx->structs, $3, Block_new($5));
                                                        bhex_free($3);
                                                    }
            | program TENUM ident TCOLON ident TLBRACE enum_list TRBRACE 
                                                    {
                                                        map_set(g_ctx->enums, $3, Enum_new($5, $7, 0));
                                                        bhex_free($3);
                                                        bhex_free($5);
                                                    }
            | program TORENUM ident TCOLON ident TLBRACE enum_list TRBRACE
                                                    {
                                                        map_set(g_ctx->enums, $3, Enum_new($5, $7, 1));
                                                        bhex_free($3);
                                                        bhex_free($5);
                                                    }
    ;

enum_list  : ident TEQUAL TSNUM64                   {
                                                        $$ = DList_new();
                                                        DList_add($$, EnumEntry_new($1, yysnumval));
                                                        bhex_free($1);
                                                    }
           | enum_list TCOMMA ident TEQUAL TSNUM64  {
                                                        DList_add($1, EnumEntry_new($3, yysnumval));
                                                        bhex_free($3);
                                                    }
    ;

stmts       : stmt TSEMICOLON                       {
                                                        $$ = DList_new();
                                                        DList_add($$, $1);
                                                    }
            | stmts stmt TSEMICOLON                 {
                                                        DList_add($1, $2);
                                                    }
    ;

stmt        : fvar_decl
            | lvar_decl
            | lvar_ass
            | void_fcall
            | if
            | if_else
            | while
            | break
    ;

fvar_decl   : ident ident                           {
                                                        $$ = Stmt_FILE_VAR_DECL_new($1, $2, NULL);
                                                        bhex_free($1);
                                                        bhex_free($2);
                                                    }
            | ident ident SQLBRACE expr SQRBRACE    {
                                                        $$ = Stmt_FILE_VAR_DECL_new($1, $2, $4);
                                                        bhex_free($1);
                                                        bhex_free($2);
                                                    }
    ;

lvar_decl   : TLOCAL ident TEQUAL expr              {
                                                        $$ = Stmt_LOCAL_VAR_DECL_new($2, $4);
                                                        bhex_free($2);
                                                    }
    ;

lvar_ass   : ident TEQUAL expr                      {
                                                        $$ = Stmt_LOCAL_VAR_ASS_new($1, $3);
                                                        bhex_free($1);
                                                    }
    ;

void_fcall  : ident TCLBRACE TCRBRACE               {
                                                        $$ = Stmt_VOID_FUNC_CALL_new($1, NULL);
                                                        bhex_free($1);
                                                    }
            | ident TCLBRACE params TCRBRACE        {
                                                        $$ = Stmt_VOID_FUNC_CALL_new($1, $3);
                                                        bhex_free($1);
                                                    }
    ;

if          : TIF TCLBRACE expr TCRBRACE TLBRACE stmts TRBRACE
                                                    {
                                                        $$ = Stmt_STMT_IF_new($3, Block_new($6));
                                                    }
    ;

if_else     : TIF TCLBRACE expr TCRBRACE TLBRACE stmts TRBRACE TELSE TLBRACE stmts TRBRACE
                                                    {
                                                        $$ = Stmt_STMT_IF_ELSE_new($3, Block_new($6), Block_new($10));
                                                    }
    ;

while       : TWHILE TCLBRACE expr TCRBRACE TLBRACE stmts TRBRACE
                                                    {
                                                        $$ = Stmt_WHILE_new($3, Block_new($6));
                                                    }
    ;

break       : TBREAK                                {
                                                        $$ = Stmt_BREAK_new();
                                                    }
    ;

expr        : num
            | ident                                 {
                                                        $$ = Expr_VAR_new($1);
                                                        bhex_free($1);
                                                    }
            | varchain                              {
                                                        $$ = Expr_VARCHAIN_new($1);
                                                    }
            | ident TCLBRACE TCRBRACE               {
                                                        $$ = Expr_FUN_CALL_new($1, NULL);
                                                        bhex_free($1);
                                                    }
            | ident TCLBRACE params TCRBRACE        {
                                                        $$ = Expr_FUN_CALL_new($1, $3);
                                                        bhex_free($1);
                                                    }
            | TCLBRACE expr TCRBRACE                {
                                                        $$ = $2;
                                                    }
            | expr TADD expr                        {
                                                        $$ = Expr_ADD_new($1, $3);
                                                    }
            | expr TSUB expr                        {
                                                        $$ = Expr_SUB_new($1, $3);
                                                    }
            | expr TMUL expr                        {
                                                        $$ = Expr_MUL_new($1, $3);
                                                    }
            | expr TBEQ expr                        {
                                                        $$ = Expr_BEQ_new($1, $3);
                                                    }
            | expr TBLT expr                        {
                                                        $$ = Expr_BLT_new($1, $3);
                                                    }
            | expr TBLE expr                        {
                                                        $$ = Expr_BLE_new($1, $3);
                                                    }
            | expr TBGT expr                        {
                                                        $$ = Expr_BGT_new($1, $3);
                                                    }
            | expr TBGE expr                        {
                                                        $$ = Expr_BGE_new($1, $3);
                                                    }
    ;

varchain    : ident TDOT ident                      {
                                                        $$ = DList_new();
                                                        DList_add($$, $1);
                                                        DList_add($$, $3);
                                                    }
            | varchain TDOT ident                   {
                                                        DList_add($1, $3);
                                                    }
    ;

params      : expr                                  {
                                                        $$ = DList_new();
                                                        DList_add($$, $1);
                                                    }
            | params TCOMMA expr                    {
                                                        DList_add($$, $3);
                                                    }
    ;

num         : TSNUM64                               {
                                                        $$ = Expr_SCONST_new(yysnumval, yynumsize);
                                                    }
            | TUNUM8                                {
                                                        $$ = Expr_UCONST_new(yyunumval, yynumsize);
                                                    }
    ;

ident       : TIDENTIFIER                           {
                                                        $$ = bhex_strdup(yystrval);
                                                    }
    ;

%%
