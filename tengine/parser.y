%{

#include "../alloc.h"
#include "../log.h"
#include "ast.h"

extern int   yylex();
extern char* yytext;
extern char  yystrval[MAX_IDENT_SIZE];
extern s64_t yynumval;

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
    NumExpr* expr;
    char*    ident;
}

// Terminal tokens
%token TPROC TSTRUCT
%token TIDENTIFIER TNUM
%token TCLBRACE TCRBRACE TLBRACE TRBRACE SQLBRACE SQRBRACE TSEMICOLON TCOLON
%token TADD

// Non terminal tokens types
%type <stmt>   stmt fvar_decl func_call
%type <stmts>  stmts
%type <ident>  ident
%type <expr>   expr num
%type <params> params

// Operator precedence
%left TADD

// The grammar
%%

program     :
            | program TPROC TLBRACE stmts TRBRACE   {
                                                        if (g_ctx->proc != NULL)
                                                            // You can only have one proc
                                                            YYABORT;
                                                        g_ctx->proc = $4;
                                                    }
            | program TSTRUCT ident TLBRACE stmts TRBRACE 
                                                    {
                                                        map_set(g_ctx->structs, $3, $5);
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
            | func_call
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

func_call   : ident TCLBRACE TCRBRACE               {
                                                        $$ = Stmt_FUNC_CALL_new($1, NULL);
                                                        bhex_free($1);
                                                    }
            | ident TCLBRACE params TCRBRACE        {
                                                        $$ = Stmt_FUNC_CALL_new($1, $3);
                                                        bhex_free($1);
                                                    }
    ;

expr        : num
            | ident                                 {
                                                        $$ = NumExpr_VAR_new($1);
                                                        bhex_free($1);
                                                    }
            | expr TADD expr                        {
                                                        $$ = NumExpr_ADD_new($1, $3);
                                                    }
    ;

params      : expr                                  {
                                                        $$ = DList_new();
                                                        DList_add($$, $1);
                                                    }
            | params TCOLON expr                    {
                                                        DList_add($$, $3);
                                                    }
    ;

num         : TNUM                                  {
                                                        $$ = NumExpr_CONST_new(yynumval);
                                                    }
    ;

ident       : TIDENTIFIER                           {
                                                        $$ = bhex_strdup(yystrval);
                                                    }
    ;

%%
