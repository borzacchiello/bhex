%{

#include "ast.h"
#include "parser.h"

#include <util/byte_to_num.h>
#include <util/str.h>
#include <alloc.h>
#include <log.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

#define YY_FATAL_ERROR(msg) panic(msg)

ASTCtx* g_ctx;

char  yystrval[MAX_IDENT_SIZE];
u8_t* yyheapbuf = NULL;
u32_t yyheapbuf_len;
s64_t yysnumval;
u64_t yyunumval;

int            yy_line            = 1;
int            yy_column          = 1;
static int     yy_next_column     = 1;
char*          yy_string_to_parse = NULL;

#define handle_token do {             \
    yy_column       = yy_next_column; \
    yy_next_column += strlen(yytext); \
} while (0)

void yy_custom_init(ASTCtx* ctx, const char* str)
{
    yy_line = yy_column = yy_next_column = 1;
    g_ctx     = ctx;
    if (str) {
        if (yy_string_to_parse != NULL) {
            free(yy_string_to_parse);
        }
        yy_string_to_parse = strdup(str);
    }
}

void yyset_string_to_parse(const char* str)
{
    if (yy_string_to_parse != NULL) {
        free(yy_string_to_parse);
    }
    yy_string_to_parse = strdup(str);
}

__attribute__((destructor)) static void delete_yy_bufs(void)
{
    if (yyheapbuf) yyfree(yyheapbuf);
    free(yy_string_to_parse);
}

%}

%option noyywrap

%%

[ \t]+                  { handle_token; }
\n                      { handle_token; yy_next_column = 1; yy_line += 1; }
"proc"                  { handle_token; return TPROC; }
"local"                 { handle_token; return TLOCAL; }
"break"                 { handle_token; return TBREAK; }
"return"                { handle_token; return TRETURN; }
"struct"                { handle_token; return TSTRUCT; }
"enum"                  { handle_token; return TENUM; }
"orenum"                { handle_token; return TORENUM; }
"if"                    { handle_token; return TIF; }
"elif"                  { handle_token; return TELIF; }
"else"                  { handle_token; return TELSE; }
"fn"                    { handle_token; return TFN; }
"while"                 { handle_token; return TWHILE; }
[0-9]+                  {
                            handle_token;
                            if (!str_to_int64(yytext, &yysnumval)) {
                                // error("[tengine lexer] invalid s64 num '%s'", yytext);
                                return 1;
                            }
                            return TSNUM64;
                        }
0x[0-9a-fA-F]+          {
                            handle_token;
                            if (!str_to_int64(yytext, &yysnumval)) {
                                // error("[tengine lexer] invalid s64 hex num '%s'", yytext);
                                return 1;
                            }
                            return TSNUM64;
                        }
[0-9]+u8                {
                            handle_token;
                            u8_t n;
                            yytext[yyleng-2] = '\0';
                            if (!str_to_uint8(yytext, &n)) {
                                // error("[tengine lexer] invalid u8 num '%s'", yytext);
                                return 1;
                            }
                            yyunumval = (u64_t)n;
                            return TUNUM8;
                        }
0x[0-9a-fA-F]+u8        {
                            handle_token;
                            u8_t n;
                            yytext[yyleng-2] = '\0';
                            if (!str_to_uint8(yytext, &n)) {
                                // error("[tengine lexer] invalid u8 hex num '%s'", yytext);
                                return 1;
                            }
                            yyunumval = (u64_t)n;
                            return TUNUM8;
                        }
[0-9]+u16               {
                            handle_token;
                            u16_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_uint16(yytext, &n)) {
                                // error("[tengine lexer] invalid u16 num '%s'", yytext);
                                return 1;
                            }
                            yyunumval = (u64_t)n;
                            return TUNUM16;
                        }
0x[0-9a-fA-F]+u16       {
                            handle_token;
                            u16_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_uint16(yytext, &n)) {
                                // error("[tengine lexer] invalid u16 hex num '%s'", yytext);
                                return 1;
                            }
                            yyunumval = (u64_t)n;
                            return TUNUM16;
                        }
[0-9]+u32               {
                            handle_token;
                            u32_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_uint32(yytext, &n)) {
                                // error("[tengine lexer] invalid u32 num '%s'", yytext);
                                return 1;
                            }
                            yyunumval = (u64_t)n;
                            return TUNUM32;
                        }
0x[0-9a-fA-F]+u32       {
                            handle_token;
                            u32_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_uint32(yytext, &n)) {
                                // error("[tengine lexer] invalid u32 hex num '%s'", yytext);
                                return 1;
                            }
                            yyunumval = (u64_t)n;
                            return TUNUM32;
                        }
[0-9]+u64               {
                            handle_token;
                            u64_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_uint64(yytext, &n)) {
                                // error("[tengine lexer] invalid u64 num '%s'", yytext);
                                return 1;
                            }
                            yyunumval = (u64_t)n;
                            return TUNUM64;
                        }
0x[0-9a-fA-F]+u64       {
                            handle_token;
                            u64_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_uint64(yytext, &n)) {
                                // error("[tengine lexer] invalid u64 hex num '%s'", yytext);
                                return 1;
                            }
                            yyunumval = (u64_t)n;
                            return TUNUM64;
                        }
[0-9]+s8                {
                            handle_token;
                            s8_t n;
                            yytext[yyleng-2] = '\0';
                            if (!str_to_int8(yytext, &n)) {
                                // error("[tengine lexer] invalid s8 num '%s'", yytext);
                                return 1;
                            }
                            yysnumval = (s64_t)n;
                            return TSNUM8;
                        }
0x[0-9a-fA-F]+s8        {
                            handle_token;
                            s8_t n;
                            yytext[yyleng-2] = '\0';
                            if (!str_to_int8(yytext, &n)) {
                                // error("[tengine lexer] invalid s8 hex num '%s'", yytext);
                                return 1;
                            }
                            yysnumval = (s64_t)n;
                            return TSNUM8;
                        }
[0-9]+s16               {
                            handle_token;
                            s16_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_int16(yytext, &n)) {
                                // error("[tengine lexer] invalid s16 num '%s'", yytext);
                                return 1;
                            }
                            yysnumval = (s64_t)n;
                            return TSNUM16;
                        }
0x[0-9a-fA-F]+s16       {
                            handle_token;
                            s16_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_int16(yytext, &n)) {
                                // error("[tengine lexer] invalid s16 hex num '%s'", yytext);
                                return 1;
                            }
                            yysnumval = (s64_t)n;
                            return TSNUM16;
                        }
[0-9]+s32               {
                            handle_token;
                            s32_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_int32(yytext, &n)) {
                                // error("[tengine lexer] invalid s32 num '%s'", yytext);
                                return 1;
                            }
                            yysnumval = (s64_t)n;
                            return TSNUM32;
                        }
0x[0-9a-fA-F]+s32       {
                            handle_token;
                            s32_t n;
                            yytext[yyleng-3] = '\0';
                            if (!str_to_int32(yytext, &n)) {
                                // error("[tengine lexer] invalid s32 hex num '%s'", yytext);
                                return 1;
                            }
                            yysnumval = (s64_t)n;
                            return TSNUM32;
                        }
[a-zA-Z_][a-zA-Z0-9_]*  {
                            handle_token;
                            yy_size_t l = min(yyleng, sizeof(yystrval)-1);
                            memset(yystrval, 0, sizeof(yystrval));
                            memcpy(yystrval, yytext, l);
                            return TIDENTIFIER;
                        }
"::"                    { handle_token; return TCOLCOL; }
"+"                     { handle_token; return TADD; }
"-"                     { handle_token; return TSUB; }
"*"                     { handle_token; return TMUL; }
"/"                     { handle_token; return TDIV; }
"%"                     { handle_token; return TMOD; }
"&"                     { handle_token; return TAND; }
"|"                     { handle_token; return TOR; }
"^"                     { handle_token; return TXOR; }
"!="                    { handle_token; return TBNEQ; }
"=="                    { handle_token; return TBEQ; }
">>"                    { handle_token; return TSHR; }
"<<"                    { handle_token; return TSHL; }
">"                     { handle_token; return TBGT; }
"<"                     { handle_token; return TBLT; }
">="                    { handle_token; return TBGE; }
"<="                    { handle_token; return TBLE; }
"&&"                    { handle_token; return TBAND; }
"||"                    { handle_token; return TBOR; }
"!"                     { handle_token; return TBNOT; }
"="                     { handle_token; return TEQUAL; }
"("                     { handle_token; return TCLBRACE; }
")"                     { handle_token; return TCRBRACE; }
"{"                     { handle_token; return TLBRACE;}
"}"                     { handle_token; return TRBRACE; }
"["                     { handle_token; return SQLBRACE;}
"]"                     { handle_token; return SQRBRACE; }
","                     { handle_token; return TCOMMA; }
"."                     { handle_token; return TDOT; }
":"                     { handle_token; return TCOLON; }
";"                     { handle_token; return TSEMICOLON; }
"#"                     { handle_token; return THASHTAG; }
\"[^"]*\"               {
                            handle_token;
                            if (yyheapbuf) yyfree(yyheapbuf);
                            yyheapbuf = NULL;

                            char* tmp = bhex_calloc(yyleng-1);
                            memcpy(tmp, yytext+1, yyleng-2);

                            size_t len;
                            u8_t*  unescaped;
                            if (!unescape_ascii_string(tmp, &unescaped, &len)) {
                                // error("[tengine lexer] invalid string '%s'", tmp);
                                bhex_free(tmp);
                                return 1;
                            }
                            yyheapbuf_len = (u32_t)len;
                            yyheapbuf = yyalloc(len);
                            memcpy(yyheapbuf, unescaped, len);
                            bhex_free(unescaped);
                            bhex_free(tmp);
                            return TSTR;
                        }
"//".*                       { handle_token; /* single line comment */ }
"/*"([^*]|"*"+[^*/])*"*"+"/" { handle_token; /* multi-line comment */  }
.                       {
                            handle_token;
                            // error("[tengine lexer] unknown token");
                            return 1;
                        }

%%
