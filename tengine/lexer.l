%{

#include "ast.h"
#include "parser.h"

#include <util/byte_to_num.h>
#include <util/str.h>
#include <alloc.h>
#include <log.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

#define YY_FATAL_ERROR(msg) panic(msg)

char  yystrval[MAX_IDENT_SIZE];
u8_t* yyheapbuf = NULL;
u32_t yyheapbuf_len;
s64_t yysnumval;
u64_t yyunumval;
int   yymax_ident_len;

__attribute__((destructor)) static void delete_yyheapbuf(void) { if (yyheapbuf) bhex_free(yyheapbuf); }

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
"elif"                  { return TELIF; }
"else"                  { return TELSE; }
"fn"                    { return TFN; }
"while"                 { return TWHILE; }
-?[0-9]+                {
                            if (!str_to_int64(yytext, &yysnumval)) {
                                error("[tengine lexer] invalid s64 num '%s'", yytext);
                                return 1;
                            }
                            return TSNUM64;
                        }
-?0x[0-9a-fA-F]+        {
                            if (!str_to_int64(yytext, &yysnumval)) {
                                error("[tengine lexer] invalid s64 hex num '%s'", yytext);
                                return 1;
                            }
                            return TSNUM64;
                        }
[0-9]+u8                {
                            u8_t n;
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
                            yytext[yyleng-2] = '\0';
                            if (!str_to_uint8(yytext, &n)) {
                                error("[tengine lexer] invalid u8 hex num '%s'", yytext);
                                return 1;
                            }
                            yyunumval = (u64_t)n;
                            return TUNUM8;
                        }
[0-9]+u16               {
                            u16_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_uint16(yytext, &n)) {
                                error("[tengine lexer] invalid u16 num '%s'", yytext);
                                return 1;
                            }
                            yyunumval = (u64_t)n;
                            return TUNUM16;
                        }
0x[0-9a-fA-F]+u16       {
                            u16_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_uint16(yytext, &n)) {
                                error("[tengine lexer] invalid u16 hex num '%s'", yytext);
                                return 1;
                            }
                            yyunumval = (u64_t)n;
                            return TUNUM16;
                        }
[0-9]+u32               {
                            u32_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_uint32(yytext, &n)) {
                                error("[tengine lexer] invalid u32 num '%s'", yytext);
                                return 1;
                            }
                            yyunumval = (u64_t)n;
                            return TUNUM32;
                        }
0x[0-9a-fA-F]+u32       {
                            u32_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_uint32(yytext, &n)) {
                                error("[tengine lexer] invalid u32 hex num '%s'", yytext);
                                return 1;
                            }
                            yyunumval = (u64_t)n;
                            return TUNUM32;
                        }
[0-9]+u64               {
                            u64_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_uint64(yytext, &n)) {
                                error("[tengine lexer] invalid u64 num '%s'", yytext);
                                return 1;
                            }
                            yyunumval = (u64_t)n;
                            return TUNUM64;
                        }
0x[0-9a-fA-F]+u64       {
                            u64_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_uint64(yytext, &n)) {
                                error("[tengine lexer] invalid u64 hex num '%s'", yytext);
                                return 1;
                            }
                            yyunumval = (u64_t)n;
                            return TUNUM64;
                        }
-?[0-9]+s8              {
                            s8_t n;
                            yytext[yyleng-2] = '\0';
                            if (!str_to_int8(yytext, &n)) {
                                error("[tengine lexer] invalid s8 num '%s'", yytext);
                                return 1;
                            }
                            yysnumval = (s64_t)n;
                            return TSNUM8;
                        }
-?0x[0-9a-fA-F]+s8      {
                            s8_t n;
                            yytext[yyleng-2] = '\0';
                            if (!str_to_int8(yytext, &n)) {
                                error("[tengine lexer] invalid s8 hex num '%s'", yytext);
                                return 1;
                            }
                            yysnumval = (s64_t)n;
                            return TSNUM8;
                        }
-?[0-9]+s16             {
                            s16_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_int16(yytext, &n)) {
                                error("[tengine lexer] invalid s16 num '%s'", yytext);
                                return 1;
                            }
                            yysnumval = (s64_t)n;
                            return TSNUM16;
                        }
-?0x[0-9a-fA-F]+s16     {
                            s16_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_int16(yytext, &n)) {
                                error("[tengine lexer] invalid s16 hex num '%s'", yytext);
                                return 1;
                            }
                            yysnumval = (s64_t)n;
                            return TSNUM16;
                        }
-?[0-9]+s32             {
                            s32_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_int32(yytext, &n)) {
                                error("[tengine lexer] invalid s32 num '%s'", yytext);
                                return 1;
                            }
                            yysnumval = (s64_t)n;
                            return TSNUM32;
                        }
-?0x[0-9a-fA-F]+s32     {
                            s32_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_int32(yytext, &n)) {
                                error("[tengine lexer] invalid s32 hex num '%s'", yytext);
                                return 1;
                            }
                            yysnumval = (s64_t)n;
                            return TSNUM32;
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
"/"                     { return TDIV; }
"%"                     { return TMOD; }
"&"                     { return TAND; }
"|"                     { return TOR; }
"^"                     { return TXOR; }
"!="                    { return TBNEQ; }
"=="                    { return TBEQ; }
">"                     { return TBGT; }
"<"                     { return TBLT; }
">="                    { return TBGE; }
"<="                    { return TBLE; }
"&&"                    { return TBAND; }
"||"                    { return TBOR; }
"!"                     { return TBNOT; }
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
\"[^"]*\"               {
                            if (yyheapbuf) bhex_free(yyheapbuf);

                            char* tmp = bhex_calloc(yyleng-1);
                            memcpy(tmp, yytext+1, yyleng-2);

                            size_t len;
                            if (!unescape_ascii_string(tmp, &yyheapbuf, &len)) {
                                error("[tengine lexer] invalid string '%s'", tmp);
                                yyheapbuf = NULL;
                                bhex_free(tmp);
                                return 1;
                            }
                            yyheapbuf_len = (u32_t)len;
                            bhex_free(tmp);
                            return TSTR;
                        }
.                       {
                            error("[tengine lexer] unknown token");
                            return 1;
                        }

%%
