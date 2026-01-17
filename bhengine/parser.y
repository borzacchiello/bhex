%{

#include <stdio.h>

#include <strbuilder.h>
#include <string.h>
#include <alloc.h>
#include <log.h>
#include "ast.h"

#define YYERROR_VERBOSE 1
#define max(x, y) ((x) > (y) ? (x) : (y))

extern int   yylex();
extern char* yytext;
extern char  yystrval[MAX_IDENT_SIZE];
extern u8_t* yyheapbuf;
extern u32_t yyheapbuf_len;
extern s64_t yysnumval;
extern u64_t yyunumval;

extern int     yy_line;
extern int     yy_column;
extern FILE*   yyin;
extern char*   yy_string_to_parse;
extern ASTCtx* g_ctx;

u64_t yymax_fvar_name_len;

static void print_error_from_file(int yylineno, int yy_column)
{
    rewind(yyin);

    char*   line = NULL;
    size_t  len  = 0;
    ssize_t read = 0;

    int linenum          = 1;
    int min_print_lineno = max(yylineno-2, 0);
    int max_print_lineno = yylineno+2;
    while ((read = getline(&line, &len, yyin)) != -1) {
        if (read > 0 && line[read-1] == '\n')
            line[read-1] = 0;

        if (linenum >= min_print_lineno && linenum <= max_print_lineno)
            error("%03d: %s", linenum, line);
        if (linenum == yylineno) {
            StringBuilder* sb = strbuilder_new();
            strbuilder_append(sb, "     ");
            for (int i=0; i<yy_column-1; ++i)
                strbuilder_append_char(sb, '_');
            strbuilder_append_char(sb, '^');
            char* errstr = strbuilder_finalize(sb);
            error("%s", errstr);
            bhex_free(errstr);
        }
        linenum += 1;
    }
    free(line);
}

static void print_error_from_string(int yylineno, int yy_column)
{
    char *line, *curr, *tofree;
    tofree = curr = bhex_strdup(yy_string_to_parse);

    int linenum          = 1;
    int min_print_lineno = max(yylineno-2, 0);
    int max_print_lineno = yylineno+2;
    while ((line = strsep(&curr, "\n")) != NULL) {
        if (linenum >= min_print_lineno && linenum <= max_print_lineno)
            error("%03d: %s", linenum, line);
        if (linenum == yylineno) {
            StringBuilder* sb = strbuilder_new();
            strbuilder_append(sb, "     ");
            for (int i=0; i<yy_column-1; ++i)
                strbuilder_append_char(sb, '_');
            strbuilder_append_char(sb, '^');
            char* errstr = strbuilder_finalize(sb);
            error("%s", errstr);
            bhex_free(errstr);
        }

        linenum += 1;
    }
    bhex_free(tofree);
}

void yyerror(const char *s)
{
    error("%s @ line %d, column %d", s, yy_line, yy_column);
    if (yyin != NULL)
        print_error_from_file(yy_line, yy_column);
    else if (yy_string_to_parse != NULL)
        print_error_from_string(yy_line, yy_column);
}

%}

// Represents the many different ways we can access our data
%union {
    Stmt*    stmt;
    DList*   stmts;
    DList*   params;
    DList*   enum_list;
    Expr*    expr;
    Type*    fvar_type;
    char*    ident;
}

// Terminal tokens
%token TPROC TFN TLOCAL TSTRUCT TENUM TORENUM TIF TELIF TELSE TWHILE TBREAK TRETURN
%token TIDENTIFIER TUNUM8 TUNUM16 TUNUM32 TUNUM64 TSNUM8 TSNUM16 TSNUM32 TSNUM64 TSTR
%token TCLBRACE TCRBRACE TLBRACE TRBRACE SQLBRACE SQRBRACE 
%token TSEMICOLON TCOLON TCOMMA TDOT TCOLCOL THASHTAG
%token TADD TSUB TMUL TDIV TMOD TAND TOR TXOR TBAND TBOR TBEQ TBNEQ TBGT TBGE TBLT TBLE TEQUAL TBNOT

// Non terminal tokens types
%type <fvar_type> fvar_type
%type <stmt>      stmt fvar_decl lvar_decl lvar_ass void_fcall if_elif else while break return
%type <stmts>     stmts
%type <enum_list> enum_list
%type <ident>     ident
%type <expr>      expr num
%type <params>    params name_params

// Operator precedence
%left TBAND TBOR
%left TBEQ TBNEQ TBLT TBLE TBGT TBGE
%left TAND TOR TXOR
%left TADD TSUB
%left TMUL TDIV TMOD TSHL TSHR
%left TBNOT
%left SQLBRACE SQRBRACE
%left TDOT

// Options
%locations
%define parse.error detailed

// The grammar
%%

program     :
            | program TPROC TLBRACE stmts TRBRACE   {
                                                        if (g_ctx->proc != NULL)
                                                            // You can only have one proc
                                                            YYABORT;
                                                        g_ctx->proc = Block_new($4);
                                                    }
            | program TPROC ident TLBRACE stmts TRBRACE 
                                                    {
                                                        map_set(g_ctx->named_procs, $3, Block_new($5));
                                                        bhex_free($3);
                                                    }
            | program TFN ident TCLBRACE TCRBRACE TLBRACE stmts TRBRACE 
                                                    {
                                                        map_set(g_ctx->functions, $3, Function_new($3, NULL, Block_new($7)));
                                                        bhex_free($3);
                                                    }
            | program TFN ident TCLBRACE name_params TCRBRACE TLBRACE stmts TRBRACE 
                                                    {
                                                        map_set(g_ctx->functions, $3, Function_new($3, $5, Block_new($8)));
                                                        bhex_free($3);
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

stmts       : stmt                                 {
                                                        $$ = DList_new();
                                                        DList_add($$, $1);
                                                    }
            | stmts stmt                            {
                                                        DList_add($1, $2);
                                                    }
    ;

stmt        : fvar_decl TSEMICOLON
            | lvar_decl TSEMICOLON
            | lvar_ass TSEMICOLON
            | void_fcall TSEMICOLON
            | break TSEMICOLON
            | return TSEMICOLON
            | if_elif
            | else
            | while
    ;

fvar_type   : ident                                 {
                                                        $$ = Type_new($1, NULL);
                                                        bhex_free($1);
                                                    }
            | ident THASHTAG ident                  {
                                                        $$ = Type_new($3, $1);
                                                        bhex_free($1);
                                                        bhex_free($3);
                                                    }

    ;

fvar_decl   : fvar_type ident                       {
                                                        size_t fvar_name_len = strlen($2);
                                                        if ((u64_t)fvar_name_len > yymax_fvar_name_len)
                                                            yymax_fvar_name_len = (u64_t)fvar_name_len;

                                                        $$ = Stmt_FILE_VAR_DECL_new($1, $2, NULL);
                                                        Stmt_set_source_info($$, yy_line, yy_column);
                                                        bhex_free($2);
                                                    }
            | fvar_type ident SQLBRACE expr SQRBRACE 
                                                    {
                                                        $$ = Stmt_FILE_VAR_DECL_new($1, $2, $4);
                                                        Stmt_set_source_info($$, yy_line, yy_column);
                                                        bhex_free($2);
                                                    }
    ;

lvar_decl   : TLOCAL ident TEQUAL expr              {
                                                        $$ = Stmt_LOCAL_VAR_DECL_new($2, $4);
                                                        Stmt_set_source_info($$, yy_line, yy_column);
                                                        bhex_free($2);
                                                    }
    ;

lvar_ass   : ident TEQUAL expr                      {
                                                        $$ = Stmt_LOCAL_VAR_ASS_new($1, $3);
                                                        Stmt_set_source_info($$, yy_line, yy_column);
                                                        bhex_free($1);
                                                    }
    ;

void_fcall  : ident TCLBRACE TCRBRACE               {
                                                        $$ = Stmt_VOID_FUNC_CALL_new($1, NULL);
                                                        Stmt_set_source_info($$, yy_line, yy_column);
                                                        bhex_free($1);
                                                    }
            | ident TCLBRACE params TCRBRACE        {
                                                        $$ = Stmt_VOID_FUNC_CALL_new($1, $3);
                                                        Stmt_set_source_info($$, yy_line, yy_column);
                                                        bhex_free($1);
                                                    }
    ;

if_elif     : TIF TCLBRACE expr TCRBRACE TLBRACE stmts TRBRACE
                                                    {
                                                        $$ = Stmt_STMT_IF_new($3, Block_new($6));
                                                        Stmt_set_source_info($$, yy_line, yy_column);
                                                    }
            | TIF TCLBRACE expr TCRBRACE TLBRACE TRBRACE
                                                    {
                                                        $$ = Stmt_STMT_IF_new($3, Block_new(DList_new()));
                                                        Stmt_set_source_info($$, yy_line, yy_column);
                                                    }
            | if_elif TELIF TCLBRACE expr TCRBRACE TLBRACE stmts TRBRACE
                                                    {
                                                        Stmt_STMT_IF_add_cond($1, $4, Block_new($7));
                                                        $$ = $1;
                                                    }
            | if_elif TELIF TCLBRACE expr TCRBRACE TLBRACE TRBRACE
                                                    {
                                                        Stmt_STMT_IF_add_cond($1, $4, Block_new(DList_new()));
                                                        $$ = $1;
                                                    }
    ;

else        : if_elif TELSE TLBRACE stmts TRBRACE
                                                    {
                                                        Stmt_STMT_IF_add_else($1, Block_new($4));
                                                        $$ = $1;
                                                    }
            | if_elif TELSE TLBRACE TRBRACE         {
                                                        $$ = $1;
                                                    }
    ;

while       : TWHILE TCLBRACE expr TCRBRACE TLBRACE stmts TRBRACE
                                                    {
                                                        $$ = Stmt_WHILE_new($3, Block_new($6));
                                                        Stmt_set_source_info($$, yy_line, yy_column);
                                                    }
    ;

break       : TBREAK                                {
                                                        $$ = Stmt_BREAK_new();
                                                        Stmt_set_source_info($$, yy_line, yy_column);
                                                    }
    ;

return      : TRETURN                               {
                                                        $$ = Stmt_RETURN_new();
                                                        Stmt_set_source_info($$, yy_line, yy_column);
                                                    }
    ;

expr        : num
            | TSTR                                  {
                                                        $$ = Expr_STRING_new(yyheapbuf, yyheapbuf_len);
                                                    }
            | ident                                 {
                                                        $$ = Expr_VAR_new($1);
                                                        bhex_free($1);
                                                    }
            | ident TCOLCOL ident                   {
                                                        $$ = Expr_ENUM_CONST_new($1, $3);
                                                        bhex_free($1);
                                                        bhex_free($3);
                                                    }
            | expr TDOT ident                       {
                                                        $$ = Expr_SUBSCR_new($1, $3);
                                                        bhex_free($3);
                                                    }
            | expr SQLBRACE expr SQRBRACE           {
                                                        $$ = Expr_ARRAY_SUB_new($1, $3);
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
            | TSUB expr                             {
                                                        $$ = Expr_SUB_new(Expr_SCONST_new(0, 8), $2);
                                                    }
            | expr TAND expr                        {
                                                        $$ = Expr_AND_new($1, $3);
                                                    }
            | expr TOR expr                         {
                                                        $$ = Expr_OR_new($1, $3);
                                                    }
            | expr TXOR expr                        {
                                                        $$ = Expr_XOR_new($1, $3);
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
            | expr TDIV expr                        {
                                                        $$ = Expr_DIV_new($1, $3);
                                                    }
            | expr TMOD expr                        {
                                                        $$ = Expr_MOD_new($1, $3);
                                                    }
            | expr TBEQ expr                        {
                                                        $$ = Expr_BEQ_new($1, $3);
                                                    }
            | expr TBNEQ expr                       {
                                                        $$ = Expr_BNOT_new(Expr_BEQ_new($1, $3));
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
            | expr TBAND expr                       {
                                                        $$ = Expr_BAND_new($1, $3);
                                                    }
            | expr TBOR expr                        {
                                                        $$ = Expr_BOR_new($1, $3);
                                                    }
            | expr TSHR expr                        {
                                                        $$ = Expr_SHR_new($1, $3);
                                                    }
            | expr TSHL expr                        {
                                                        $$ = Expr_SHL_new($1, $3);
                                                    }
            | TBNOT expr                            {
                                                        $$ = Expr_BNOT_new($2);
                                                    }
    ;

name_params : ident                                 {
                                                        $$ = DList_new();
                                                        DList_add($$, $1);
                                                    }
            | name_params TCOMMA ident              {
                                                        DList_add($$, $3);
                                                    }

params      : expr                                  {
                                                        $$ = DList_new();
                                                        DList_add($$, $1);
                                                    }
            | params TCOMMA expr                    {
                                                        DList_add($$, $3);
                                                    }
    ;

num         : TUNUM8                                {
                                                        $$ = Expr_UCONST_new(yyunumval, 1);
                                                    }
            | TUNUM16                               {
                                                        $$ = Expr_UCONST_new(yyunumval, 2);
                                                    }
            | TUNUM32                               {
                                                        $$ = Expr_UCONST_new(yyunumval, 4);
                                                    }
            | TUNUM64                               {
                                                        $$ = Expr_UCONST_new(yyunumval, 8);
                                                    }
            | TSNUM8                                {
                                                        $$ = Expr_SCONST_new(yysnumval, 1);
                                                    }
            | TSNUM16                               {
                                                        $$ = Expr_SCONST_new(yysnumval, 2);
                                                    }
            | TSNUM32                               {
                                                        $$ = Expr_SCONST_new(yysnumval, 4);
                                                    }
            | TSNUM64                               {
                                                        $$ = Expr_SCONST_new(yysnumval, 8);
                                                    }
    ;

ident       : TIDENTIFIER                           {
                                                        $$ = bhex_strdup(yystrval);
                                                    }
    ;

%%
