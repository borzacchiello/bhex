%{

#include "ast.h"
#include "parser.h"
#include "../cmd/util/byte_to_num.h"
#include "../log.h"

#define min(x, y) ((x) < (y) ? (x) : (y))

char  yystrval[MAX_IDENT_SIZE];
u32_t yyuintval;
int   yymax_ident_len;

%}

%option noyywrap

%%

[ \t\n]                 { }
"proc"                  { return TPROC; }
[0-9]+                  {
                            if (!str_to_uint32(yytext, &yyuintval)) {
                                error("[tengine lexer] invalid uint '%s'", yytext);
                                yyterminate();
                            }
                            return TUINT;
                        }
[a-zA-Z_][a-zA-Z0-9_]*  {
                            yy_size_t l = min(yyleng, sizeof(yystrval)-1);
                            if (l > (yy_size_t)yymax_ident_len)
                                yymax_ident_len = (int)l;

                            memset(yystrval, 0, sizeof(yystrval));
                            memcpy(yystrval, yytext, l);
                            return TIDENTIFIER;
                        }
"{"                     { return TLBRACE;}
"}"                     { return TRBRACE; }
"["                     { return SQLBRACE;}
"]"                     { return SQRBRACE; }
";"                     { return TSEMICOLON; }
.                       {
                            error("[tengine lexer] unknown token");
                            yyterminate();
                        }

%%
