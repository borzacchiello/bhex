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
    error("[tengine parser] %s [token '%s']\n", s, yytext);
}

%}

// Represents the many different ways we can access our data
%union {
    Stmt*    stmt;
    DList*   stmts;
    NumExpr* expr;
    char*    ident;
}

// Terminal tokens
%token TPROC
%token TIDENTIFIER TNUM
%token TLBRACE TRBRACE SQLBRACE SQRBRACE TSEMICOLON
%token TADD

// Non terminal tokens types
%type <stmt>  stmt fvar_decl
%type <stmts> stmts proc
%type <ident> ident
%type <expr>  expr num

// Operator precedence
%left TADD

// The grammar
%%

program     :
            | program proc                         {
                                                        if (g_ctx->proc != NULL)
                                                            // You can only have one proc
                                                            YYABORT;
                                                        g_ctx->proc = $2;
                                                    }
    ;

proc        : TPROC TLBRACE stmts TRBRACE          {
                                                        $$ = $3;
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

expr        : num
            | ident                                 {
                                                        $$ = NumExpr_VAR_new($1);
                                                        bhex_free($1);
                                                    }
            | expr TADD expr                        {
                                                        $$ = NumExpr_ADD_new($1, $3);
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
