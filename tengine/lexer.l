%{

#include "ast.h"
#include "parser.h"
#include "../cmd/util/byte_to_num.h"
#include "../log.h"

#define min(x, y) ((x) < (y) ? (x) : (y))

#define YY_FATAL_ERROR(msg) panic(msg)

char  yystrval[MAX_IDENT_SIZE];
s64_t yynumval;
int   yymax_ident_len;

%}

%option noyywrap

%%

[ \t\n]                 { }
"proc"                  { return TPROC; }
"local"                 { return TLOCAL; }
"break"                 { return TBREAK; }
"struct"                { return TSTRUCT; }
"enum"                  { return TENUM; }
"orenum"                { return TORENUM; }
"if"                    { return TIF; }
"else"                  { return TELSE; }
"while"                 { return TWHILE; }
-?[0-9]+                {
                            if (!str_to_int64(yytext, &yynumval)) {
                                error("[tengine lexer] invalid num '%s'", yytext);
                                return 1;
                            }
                            return TNUM;
                        }
-?0x[0-9a-fA-F]+        {
                            if (!str_to_int64(yytext, &yynumval)) {
                                error("[tengine lexer] invalid hex num '%s'", yytext);
                                return 1;
                            }
                            return TNUM;
                        }
[a-zA-Z_][a-zA-Z0-9_]*  {
                            yy_size_t l = min(yyleng, sizeof(yystrval)-1);
                            if (l > (yy_size_t)yymax_ident_len)
                                yymax_ident_len = (int)l;

                            memset(yystrval, 0, sizeof(yystrval));
                            memcpy(yystrval, yytext, l);
                            return TIDENTIFIER;
                        }
"+"                     { return TADD; }
"-"                     { return TSUB; }
"*"                     { return TMUL; }
"=="                    { return TBEQ; }
">"                     { return TBGT; }
"<"                     { return TBLT; }
">="                    { return TBGE; }
"<="                    { return TBLE; }
"="                     { return TEQUAL; }
"("                     { return TCLBRACE; }
")"                     { return TCRBRACE; }
"{"                     { return TLBRACE;}
"}"                     { return TRBRACE; }
"["                     { return SQLBRACE;}
"]"                     { return SQRBRACE; }
","                     { return TCOMMA; }
"."                     { return TDOT; }
":"                     { return TCOLON; }
";"                     { return TSEMICOLON; }
.                       {
                            error("[tengine lexer] unknown token");
                            return 1;
                        }

%%
