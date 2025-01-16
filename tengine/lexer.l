%{

#include "ast.h"
#include "parser.h"
#include <util/byte_to_num.h>
#include <log.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

#define YY_FATAL_ERROR(msg) panic(msg)

char  yystrval[MAX_IDENT_SIZE];
s64_t yysnumval;
u64_t yyunumval;
int   yynumsize;
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
                            yynumsize = 8;
                            if (!str_to_int64(yytext, &yysnumval)) {
                                error("[tengine lexer] invalid s64 num '%s'", yytext);
                                return 1;
                            }
                            return TSNUM64;
                        }
-?0x[0-9a-fA-F]+        {
                            yynumsize = 8;
                            if (!str_to_int64(yytext, &yysnumval)) {
                                error("[tengine lexer] invalid s64 hex num '%s'", yytext);
                                return 1;
                            }
                            return TSNUM64;
                        }
[0-9]+u8                {
                            u8_t n;
                            yynumsize = 1;
                            yytext[yyleng-2] = '\0';
                            if (!str_to_uint8(yytext, &n)) {
                                error("[tengine lexer] invalid u8 num '%s'", yytext);
                                return 1;
                            }
                            yyunumval = (u64_t)n;
                            return TUNUM8;
                        }
0x[0-9a-fA-F]+u8        {
                            u8_t n;
                            yynumsize = 1;
                            yytext[yyleng-2] = '\0';
                            if (!str_to_uint8(yytext, &n)) {
                                error("[tengine lexer] invalid u8 hex num '%s'", yytext);
                                return 1;
                            }
                            yyunumval = (u64_t)n;
                            return TUNUM8;
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
