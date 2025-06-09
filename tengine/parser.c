/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton implementation for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.3"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Using locations.  */
#define YYLSP_NEEDED 1



/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     TPROC = 258,
     TFN = 259,
     TLOCAL = 260,
     TSTRUCT = 261,
     TENUM = 262,
     TORENUM = 263,
     TIF = 264,
     TELIF = 265,
     TELSE = 266,
     TWHILE = 267,
     TBREAK = 268,
     TIDENTIFIER = 269,
     TUNUM8 = 270,
     TUNUM16 = 271,
     TUNUM32 = 272,
     TUNUM64 = 273,
     TSNUM8 = 274,
     TSNUM16 = 275,
     TSNUM32 = 276,
     TSNUM64 = 277,
     TSTR = 278,
     TCLBRACE = 279,
     TCRBRACE = 280,
     TLBRACE = 281,
     TRBRACE = 282,
     SQLBRACE = 283,
     SQRBRACE = 284,
     TSEMICOLON = 285,
     TCOLON = 286,
     TCOMMA = 287,
     TDOT = 288,
     TCOLCOL = 289,
     THASHTAG = 290,
     TADD = 291,
     TSUB = 292,
     TMUL = 293,
     TDIV = 294,
     TMOD = 295,
     TAND = 296,
     TOR = 297,
     TXOR = 298,
     TBAND = 299,
     TBOR = 300,
     TBEQ = 301,
     TBNEQ = 302,
     TBGT = 303,
     TBGE = 304,
     TBLT = 305,
     TBLE = 306,
     TEQUAL = 307,
     TBNOT = 308
   };
#endif
/* Tokens.  */
#define TPROC 258
#define TFN 259
#define TLOCAL 260
#define TSTRUCT 261
#define TENUM 262
#define TORENUM 263
#define TIF 264
#define TELIF 265
#define TELSE 266
#define TWHILE 267
#define TBREAK 268
#define TIDENTIFIER 269
#define TUNUM8 270
#define TUNUM16 271
#define TUNUM32 272
#define TUNUM64 273
#define TSNUM8 274
#define TSNUM16 275
#define TSNUM32 276
#define TSNUM64 277
#define TSTR 278
#define TCLBRACE 279
#define TCRBRACE 280
#define TLBRACE 281
#define TRBRACE 282
#define SQLBRACE 283
#define SQRBRACE 284
#define TSEMICOLON 285
#define TCOLON 286
#define TCOMMA 287
#define TDOT 288
#define TCOLCOL 289
#define THASHTAG 290
#define TADD 291
#define TSUB 292
#define TMUL 293
#define TDIV 294
#define TMOD 295
#define TAND 296
#define TOR 297
#define TXOR 298
#define TBAND 299
#define TBOR 300
#define TBEQ 301
#define TBNEQ 302
#define TBGT 303
#define TBGE 304
#define TBLT 305
#define TBLE 306
#define TEQUAL 307
#define TBNOT 308




/* Copy the first part of user declarations.  */
#line 1 "parser.y"


#include <stdio.h>

#include <alloc.h>
#include <log.h>
#include "ast.h"

extern int   yylex();
extern char* yytext;
extern int   yylineno;
extern char  yystrval[MAX_IDENT_SIZE];
extern u8_t* yyheapbuf;
extern u32_t yyheapbuf_len;
extern s64_t yysnumval;
extern u64_t yyunumval;
extern int   yymax_ident_len;

static ASTCtx* g_ctx;

void yyset_ctx(ASTCtx* ctx)
{
    g_ctx = ctx;
}

void yyerror(const char *s)
{
    error("[tengine parser] %s @ line %d [near token '%s']", s, yylineno, yytext);
}



/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif

#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 34 "parser.y"
{
    Stmt*    stmt;
    DList*   stmts;
    DList*   params;
    DList*   enum_list;
    Expr*    expr;
    Type*    fvar_type;
    char*    ident;
}
/* Line 193 of yacc.c.  */
#line 244 "parser.c"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

#if ! defined YYLTYPE && ! defined YYLTYPE_IS_DECLARED
typedef struct YYLTYPE
{
  int first_line;
  int first_column;
  int last_line;
  int last_column;
} YYLTYPE;
# define yyltype YYLTYPE /* obsolescent; will be withdrawn */
# define YYLTYPE_IS_DECLARED 1
# define YYLTYPE_IS_TRIVIAL 1
#endif


/* Copy the second part of user declarations.  */


/* Line 216 of yacc.c.  */
#line 269 "parser.c"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(e) ((void) (e))
#else
# define YYUSE(e) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(n) (n)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int i)
#else
static int
YYID (i)
    int i;
#endif
{
  return i;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef _STDLIB_H
#      define _STDLIB_H 1
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined _STDLIB_H \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef _STDLIB_H
#    define _STDLIB_H 1
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL \
	     && defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss;
  YYSTYPE yyvs;
    YYLTYPE yyls;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE) + sizeof (YYLTYPE)) \
      + 2 * YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  YYSIZE_T yyi;				\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (YYID (0))
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   499

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  54
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  19
/* YYNRULES -- Number of rules.  */
#define YYNRULES  73
/* YYNRULES -- Number of states.  */
#define YYNSTATES  172

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   308

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     4,    10,    19,    29,    36,    45,    54,
      58,    64,    66,    69,    72,    75,    78,    81,    84,    86,
      88,    90,    92,    96,    99,   105,   110,   114,   118,   123,
     131,   140,   146,   154,   156,   158,   160,   162,   166,   170,
     175,   179,   184,   188,   191,   195,   199,   203,   207,   211,
     215,   219,   223,   227,   231,   235,   239,   243,   247,   251,
     255,   258,   260,   264,   266,   270,   272,   274,   276,   278,
     280,   282,   284,   286
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      55,     0,    -1,    -1,    55,     3,    26,    57,    27,    -1,
      55,     4,    72,    24,    25,    26,    57,    27,    -1,    55,
       4,    72,    24,    69,    25,    26,    57,    27,    -1,    55,
       6,    72,    26,    57,    27,    -1,    55,     7,    72,    31,
      72,    26,    56,    27,    -1,    55,     8,    72,    31,    72,
      26,    56,    27,    -1,    72,    52,    22,    -1,    56,    32,
      72,    52,    22,    -1,    58,    -1,    57,    58,    -1,    60,
      30,    -1,    61,    30,    -1,    62,    30,    -1,    63,    30,
      -1,    67,    30,    -1,    64,    -1,    65,    -1,    66,    -1,
      72,    -1,    72,    35,    72,    -1,    59,    72,    -1,    59,
      72,    28,    68,    29,    -1,     5,    72,    52,    68,    -1,
      72,    52,    68,    -1,    72,    24,    25,    -1,    72,    24,
      70,    25,    -1,     9,    24,    68,    25,    26,    57,    27,
      -1,    64,    10,    24,    68,    25,    26,    57,    27,    -1,
      64,    11,    26,    57,    27,    -1,    12,    24,    68,    25,
      26,    57,    27,    -1,    13,    -1,    71,    -1,    23,    -1,
      72,    -1,    72,    34,    72,    -1,    68,    33,    72,    -1,
      68,    28,    68,    29,    -1,    72,    24,    25,    -1,    72,
      24,    70,    25,    -1,    24,    68,    25,    -1,    37,    68,
      -1,    68,    41,    68,    -1,    68,    42,    68,    -1,    68,
      43,    68,    -1,    68,    36,    68,    -1,    68,    37,    68,
      -1,    68,    38,    68,    -1,    68,    39,    68,    -1,    68,
      40,    68,    -1,    68,    46,    68,    -1,    68,    47,    68,
      -1,    68,    50,    68,    -1,    68,    51,    68,    -1,    68,
      48,    68,    -1,    68,    49,    68,    -1,    68,    44,    68,
      -1,    68,    45,    68,    -1,    53,    68,    -1,    72,    -1,
      69,    32,    72,    -1,    68,    -1,    70,    32,    68,    -1,
      15,    -1,    16,    -1,    17,    -1,    18,    -1,    19,    -1,
      20,    -1,    21,    -1,    22,    -1,    14,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,    76,    76,    77,    83,    88,    93,    98,   104,   112,
     117,   123,   127,   132,   133,   134,   135,   136,   137,   138,
     139,   142,   146,   154,   158,   165,   171,   177,   181,   187,
     191,   198,   205,   211,   216,   217,   220,   224,   229,   233,
     236,   240,   244,   247,   250,   253,   256,   259,   262,   265,
     268,   271,   274,   277,   280,   283,   286,   289,   292,   295,
     298,   303,   307,   311,   315,   320,   323,   326,   329,   332,
     335,   338,   341,   346
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "TPROC", "TFN", "TLOCAL", "TSTRUCT",
  "TENUM", "TORENUM", "TIF", "TELIF", "TELSE", "TWHILE", "TBREAK",
  "TIDENTIFIER", "TUNUM8", "TUNUM16", "TUNUM32", "TUNUM64", "TSNUM8",
  "TSNUM16", "TSNUM32", "TSNUM64", "TSTR", "TCLBRACE", "TCRBRACE",
  "TLBRACE", "TRBRACE", "SQLBRACE", "SQRBRACE", "TSEMICOLON", "TCOLON",
  "TCOMMA", "TDOT", "TCOLCOL", "THASHTAG", "TADD", "TSUB", "TMUL", "TDIV",
  "TMOD", "TAND", "TOR", "TXOR", "TBAND", "TBOR", "TBEQ", "TBNEQ", "TBGT",
  "TBGE", "TBLT", "TBLE", "TEQUAL", "TBNOT", "$accept", "program",
  "enum_list", "stmts", "stmt", "fvar_type", "fvar_decl", "lvar_decl",
  "lvar_ass", "void_fcall", "if_elif", "else", "while", "break", "expr",
  "name_params", "params", "num", "ident", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    54,    55,    55,    55,    55,    55,    55,    55,    56,
      56,    57,    57,    58,    58,    58,    58,    58,    58,    58,
      58,    59,    59,    60,    60,    61,    62,    63,    63,    64,
      64,    65,    66,    67,    68,    68,    68,    68,    68,    68,
      68,    68,    68,    68,    68,    68,    68,    68,    68,    68,
      68,    68,    68,    68,    68,    68,    68,    68,    68,    68,
      68,    69,    69,    70,    70,    71,    71,    71,    71,    71,
      71,    71,    71,    72
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     5,     8,     9,     6,     8,     8,     3,
       5,     1,     2,     2,     2,     2,     2,     2,     1,     1,
       1,     1,     3,     2,     5,     4,     3,     3,     4,     7,
       8,     5,     7,     1,     1,     1,     1,     3,     3,     4,
       3,     4,     3,     2,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       2,     1,     3,     1,     3,     1,     1,     1,     1,     1,
       1,     1,     1,     1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       2,     0,     1,     0,     0,     0,     0,     0,     0,    73,
       0,     0,     0,     0,     0,     0,     0,    33,     0,    11,
       0,     0,     0,     0,     0,    18,    19,    20,     0,    21,
       0,     0,     0,     0,     0,     0,     0,     3,    12,    23,
      13,    14,    15,    16,     0,     0,    17,     0,     0,     0,
       0,     0,    61,     0,     0,     0,     0,    65,    66,    67,
      68,    69,    70,    71,    72,    35,     0,     0,     0,     0,
      34,    36,     0,     0,     0,     0,    27,    63,     0,    22,
      26,     0,     0,     0,     6,     0,     0,    25,     0,    43,
      60,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    28,     0,     0,     0,
      62,     0,     0,     0,    42,     0,     0,    38,    47,    48,
      49,    50,    51,    44,    45,    46,    58,    59,    52,    53,
      56,    57,    54,    55,    40,     0,    37,     0,    24,     0,
      31,    64,     4,     0,     7,     0,     0,     8,     0,    39,
      41,     0,     0,     5,     0,     9,    29,    32,     0,     0,
      30,    10
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
      -1,     1,   121,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    77,    51,    78,    70,    71
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -26
static const yytype_int16 yypact[] =
{
     -26,   487,   -26,    -5,    -3,    -3,    -3,    -3,   104,   -26,
      23,    13,   -22,    39,    -3,    48,    49,   -26,    10,   -26,
      -3,    45,    56,    57,    65,    31,   -26,   -26,    67,   -17,
      20,   104,    -3,    -3,    22,   207,   207,   -26,   -26,    70,
     -26,   -26,   -26,   -26,    75,    77,   -26,    43,    -3,   207,
      78,    44,   -26,    79,    82,    84,   207,   -26,   -26,   -26,
     -26,   -26,   -26,   -26,   -26,   -26,   207,   207,   207,   225,
     -26,    12,   252,   207,   207,   104,   -26,   378,    53,   -26,
     378,   104,    86,    -3,   -26,    -3,    -3,   378,   279,    -8,
     -20,    93,   207,    -3,   207,   207,   207,   207,   207,   207,
     207,   207,   207,   207,   207,   207,   207,   207,   207,   207,
     109,    -3,    94,   330,   306,   169,   -26,   207,   227,   104,
     -26,   -15,    83,     6,   -26,   104,   354,   -26,    -8,    -8,
     -20,   -20,   -20,    15,    15,    15,   402,   402,   151,   151,
     151,   151,   151,   151,   -26,    58,   -26,   104,   -26,   110,
     -26,   378,   -26,   449,   -26,    -3,   119,   -26,   455,   -26,
     -26,   461,   104,   -26,    90,   -26,   -26,   -26,   472,   122,
     -26,   -26
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -26,   -26,    61,   -25,   -13,   -26,   -26,   -26,   -26,   -26,
     -26,   -26,   -26,   -26,   103,   -26,    -9,   -26,    -4
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const yytype_uint8 yytable[] =
{
      10,    11,    12,    13,    29,    38,    53,    47,    92,    32,
      34,     9,   154,    93,    29,    14,    39,   155,    48,    15,
      92,     8,    16,    17,     9,    93,    52,    29,    54,    55,
      96,    97,    98,   157,     9,    49,   110,    37,   155,    31,
      38,    44,    45,    92,    79,    50,   111,    30,    93,    29,
     115,    94,    95,    96,    97,    98,   118,     9,    57,    58,
      59,    60,    61,    62,    63,    64,    65,    66,    76,    82,
      33,    29,    35,    36,    56,    40,    83,    29,   116,   120,
      67,   122,   122,   160,    14,   117,    41,    42,    15,   127,
     117,    16,    17,     9,   153,    43,    68,    46,    73,    74,
     158,   145,    38,    75,    81,    38,    84,   146,    85,    14,
      86,    29,   119,    15,    29,    29,    16,    17,     9,   125,
     147,    29,   161,     9,    57,    58,    59,    60,    61,    62,
      63,    64,    65,    66,   144,   156,   162,   168,    69,    72,
      38,   165,   169,    29,   171,    38,    67,   123,    38,    29,
       0,   164,    80,     0,    29,    38,     0,    29,    29,    87,
       0,     0,    68,     0,    29,     0,     0,     0,     0,    88,
      89,    90,     0,     0,    14,     0,   113,   114,    15,    92,
       0,    16,    17,     9,    93,     0,     0,    94,    95,    96,
      97,    98,    99,   100,   101,   126,   150,   128,   129,   130,
     131,   132,   133,   134,   135,   136,   137,   138,   139,   140,
     141,   142,   143,     0,     0,     0,     0,     0,     0,     0,
     151,     9,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    14,     0,     0,     0,    15,     0,     0,    16,
      17,     9,     0,     0,    67,     0,     0,     0,     0,     0,
      91,     0,     0,    92,   152,     0,     0,     0,    93,     0,
      68,    94,    95,    96,    97,    98,    99,   100,   101,   102,
     103,   104,   105,   106,   107,   108,   109,   112,     0,     0,
      92,     0,     0,     0,     0,    93,     0,     0,    94,    95,
      96,    97,    98,    99,   100,   101,   102,   103,   104,   105,
     106,   107,   108,   109,   124,     0,     0,    92,     0,     0,
       0,     0,    93,     0,     0,    94,    95,    96,    97,    98,
      99,   100,   101,   102,   103,   104,   105,   106,   107,   108,
     109,   149,     0,     0,    92,     0,     0,     0,     0,    93,
       0,     0,    94,    95,    96,    97,    98,    99,   100,   101,
     102,   103,   104,   105,   106,   107,   108,   109,    92,   148,
       0,     0,     0,    93,     0,     0,    94,    95,    96,    97,
      98,    99,   100,   101,   102,   103,   104,   105,   106,   107,
     108,   109,    92,   159,     0,     0,     0,    93,     0,     0,
      94,    95,    96,    97,    98,    99,   100,   101,   102,   103,
     104,   105,   106,   107,   108,   109,    92,     0,     0,     0,
       0,    93,     0,     0,    94,    95,    96,    97,    98,    99,
     100,   101,   102,   103,   104,   105,   106,   107,   108,   109,
      92,     0,     0,     0,     0,    93,     0,     0,    94,    95,
      96,    97,    98,    99,   100,   101,     0,     0,   104,   105,
     106,   107,   108,   109,    14,     0,     0,     0,    15,     0,
      14,    16,    17,     9,    15,     0,    14,    16,    17,     9,
      15,     0,     0,    16,    17,     9,   163,    14,     0,     0,
       0,    15,   166,     0,    16,    17,     9,     2,   167,     0,
       3,     4,     0,     5,     6,     7,     0,     0,     0,   170
};

static const yytype_int16 yycheck[] =
{
       4,     5,     6,     7,     8,    18,    31,    24,    28,    31,
      14,    14,    27,    33,    18,     5,    20,    32,    35,     9,
      28,    26,    12,    13,    14,    33,    30,    31,    32,    33,
      38,    39,    40,    27,    14,    52,    24,    27,    32,    26,
      53,    10,    11,    28,    48,    25,    34,    24,    33,    53,
      75,    36,    37,    38,    39,    40,    81,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    25,
      31,    75,    24,    24,    52,    30,    32,    81,    25,    83,
      37,    85,    86,    25,     5,    32,    30,    30,     9,    93,
      32,    12,    13,    14,   119,    30,    53,    30,    28,    24,
     125,   110,   115,    26,    26,   118,    27,   111,    26,     5,
      26,   115,    26,     9,   118,   119,    12,    13,    14,    26,
      26,   125,   147,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    52,    26,   162,    35,    36,
     153,    22,    52,   147,    22,   158,    37,    86,   161,   153,
      -1,   155,    49,    -1,   158,   168,    -1,   161,   162,    56,
      -1,    -1,    53,    -1,   168,    -1,    -1,    -1,    -1,    66,
      67,    68,    -1,    -1,     5,    -1,    73,    74,     9,    28,
      -1,    12,    13,    14,    33,    -1,    -1,    36,    37,    38,
      39,    40,    41,    42,    43,    92,    27,    94,    95,    96,
      97,    98,    99,   100,   101,   102,   103,   104,   105,   106,
     107,   108,   109,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     117,    14,    15,    16,    17,    18,    19,    20,    21,    22,
      23,    24,     5,    -1,    -1,    -1,     9,    -1,    -1,    12,
      13,    14,    -1,    -1,    37,    -1,    -1,    -1,    -1,    -1,
      25,    -1,    -1,    28,    27,    -1,    -1,    -1,    33,    -1,
      53,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    25,    -1,    -1,
      28,    -1,    -1,    -1,    -1,    33,    -1,    -1,    36,    37,
      38,    39,    40,    41,    42,    43,    44,    45,    46,    47,
      48,    49,    50,    51,    25,    -1,    -1,    28,    -1,    -1,
      -1,    -1,    33,    -1,    -1,    36,    37,    38,    39,    40,
      41,    42,    43,    44,    45,    46,    47,    48,    49,    50,
      51,    25,    -1,    -1,    28,    -1,    -1,    -1,    -1,    33,
      -1,    -1,    36,    37,    38,    39,    40,    41,    42,    43,
      44,    45,    46,    47,    48,    49,    50,    51,    28,    29,
      -1,    -1,    -1,    33,    -1,    -1,    36,    37,    38,    39,
      40,    41,    42,    43,    44,    45,    46,    47,    48,    49,
      50,    51,    28,    29,    -1,    -1,    -1,    33,    -1,    -1,
      36,    37,    38,    39,    40,    41,    42,    43,    44,    45,
      46,    47,    48,    49,    50,    51,    28,    -1,    -1,    -1,
      -1,    33,    -1,    -1,    36,    37,    38,    39,    40,    41,
      42,    43,    44,    45,    46,    47,    48,    49,    50,    51,
      28,    -1,    -1,    -1,    -1,    33,    -1,    -1,    36,    37,
      38,    39,    40,    41,    42,    43,    -1,    -1,    46,    47,
      48,    49,    50,    51,     5,    -1,    -1,    -1,     9,    -1,
       5,    12,    13,    14,     9,    -1,     5,    12,    13,    14,
       9,    -1,    -1,    12,    13,    14,    27,     5,    -1,    -1,
      -1,     9,    27,    -1,    12,    13,    14,     0,    27,    -1,
       3,     4,    -1,     6,     7,     8,    -1,    -1,    -1,    27
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    55,     0,     3,     4,     6,     7,     8,    26,    14,
      72,    72,    72,    72,     5,     9,    12,    13,    57,    58,
      59,    60,    61,    62,    63,    64,    65,    66,    67,    72,
      24,    26,    31,    31,    72,    24,    24,    27,    58,    72,
      30,    30,    30,    30,    10,    11,    30,    24,    35,    52,
      25,    69,    72,    57,    72,    72,    52,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    37,    53,    68,
      71,    72,    68,    28,    24,    26,    25,    68,    70,    72,
      68,    26,    25,    32,    27,    26,    26,    68,    68,    68,
      68,    25,    28,    33,    36,    37,    38,    39,    40,    41,
      42,    43,    44,    45,    46,    47,    48,    49,    50,    51,
      24,    34,    25,    68,    68,    57,    25,    32,    57,    26,
      72,    56,    72,    56,    25,    26,    68,    72,    68,    68,
      68,    68,    68,    68,    68,    68,    68,    68,    68,    68,
      68,    68,    68,    68,    25,    70,    72,    26,    29,    25,
      27,    68,    27,    57,    27,    32,    52,    27,    57,    29,
      25,    57,    26,    27,    72,    22,    27,    27,    57,    52,
      27,    22
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK (1);						\
      goto yybackup;						\
    }								\
  else								\
    {								\
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (YYID (N))                                                    \
	{								\
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;	\
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;	\
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;		\
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;	\
	}								\
      else								\
	{								\
	  (Current).first_line   = (Current).last_line   =		\
	    YYRHSLOC (Rhs, 0).last_line;				\
	  (Current).first_column = (Current).last_column =		\
	    YYRHSLOC (Rhs, 0).last_column;				\
	}								\
    while (YYID (0))
#endif


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL
#  define YY_LOCATION_PRINT(File, Loc)			\
     fprintf (File, "%d.%d-%d.%d",			\
	      (Loc).first_line, (Loc).first_column,	\
	      (Loc).last_line,  (Loc).last_column)
# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value, Location); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep, yylocationp)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    YYLTYPE const * const yylocationp;
#endif
{
  if (!yyvaluep)
    return;
  YYUSE (yylocationp);
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
	break;
    }
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep, yylocationp)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    YYLTYPE const * const yylocationp;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  YY_LOCATION_PRINT (yyoutput, *yylocationp);
  YYFPRINTF (yyoutput, ": ");
  yy_symbol_value_print (yyoutput, yytype, yyvaluep, yylocationp);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *bottom, yytype_int16 *top)
#else
static void
yy_stack_print (bottom, top)
    yytype_int16 *bottom;
    yytype_int16 *top;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; bottom <= top; ++bottom)
    YYFPRINTF (stderr, " %d", *bottom);
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, YYLTYPE *yylsp, int yyrule)
#else
static void
yy_reduce_print (yyvsp, yylsp, yyrule)
    YYSTYPE *yyvsp;
    YYLTYPE *yylsp;
    int yyrule;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      fprintf (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       , &(yylsp[(yyi + 1) - (yynrhs)])		       );
      fprintf (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, yylsp, Rule); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
	switch (*++yyp)
	  {
	  case '\'':
	  case ',':
	    goto do_not_strip_quotes;

	  case '\\':
	    if (*++yyp != '\\')
	      goto do_not_strip_quotes;
	    /* Fall through.  */
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into YYRESULT an error message about the unexpected token
   YYCHAR while in state YYSTATE.  Return the number of bytes copied,
   including the terminating null byte.  If YYRESULT is null, do not
   copy anything; just return the number of bytes that would be
   copied.  As a special case, return 0 if an ordinary "syntax error"
   message will do.  Return YYSIZE_MAXIMUM if overflow occurs during
   size calculation.  */
static YYSIZE_T
yysyntax_error (char *yyresult, int yystate, int yychar)
{
  int yyn = yypact[yystate];

  if (! (YYPACT_NINF < yyn && yyn <= YYLAST))
    return 0;
  else
    {
      int yytype = YYTRANSLATE (yychar);
      YYSIZE_T yysize0 = yytnamerr (0, yytname[yytype]);
      YYSIZE_T yysize = yysize0;
      YYSIZE_T yysize1;
      int yysize_overflow = 0;
      enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
      char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
      int yyx;

# if 0
      /* This is so xgettext sees the translatable formats that are
	 constructed on the fly.  */
      YY_("syntax error, unexpected %s");
      YY_("syntax error, unexpected %s, expecting %s");
      YY_("syntax error, unexpected %s, expecting %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s");
# endif
      char *yyfmt;
      char const *yyf;
      static char const yyunexpected[] = "syntax error, unexpected %s";
      static char const yyexpecting[] = ", expecting %s";
      static char const yyor[] = " or %s";
      char yyformat[sizeof yyunexpected
		    + sizeof yyexpecting - 1
		    + ((YYERROR_VERBOSE_ARGS_MAXIMUM - 2)
		       * (sizeof yyor - 1))];
      char const *yyprefix = yyexpecting;

      /* Start YYX at -YYN if negative to avoid negative indexes in
	 YYCHECK.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;

      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yycount = 1;

      yyarg[0] = yytname[yytype];
      yyfmt = yystpcpy (yyformat, yyunexpected);

      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	  {
	    if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
	      {
		yycount = 1;
		yysize = yysize0;
		yyformat[sizeof yyunexpected - 1] = '\0';
		break;
	      }
	    yyarg[yycount++] = yytname[yyx];
	    yysize1 = yysize + yytnamerr (0, yytname[yyx]);
	    yysize_overflow |= (yysize1 < yysize);
	    yysize = yysize1;
	    yyfmt = yystpcpy (yyfmt, yyprefix);
	    yyprefix = yyor;
	  }

      yyf = YY_(yyformat);
      yysize1 = yysize + yystrlen (yyf);
      yysize_overflow |= (yysize1 < yysize);
      yysize = yysize1;

      if (yysize_overflow)
	return YYSIZE_MAXIMUM;

      if (yyresult)
	{
	  /* Avoid sprintf, as that infringes on the user's name space.
	     Don't have undefined behavior even if the translation
	     produced a string with the wrong number of "%s"s.  */
	  char *yyp = yyresult;
	  int yyi = 0;
	  while ((*yyp = *yyf) != '\0')
	    {
	      if (*yyp == '%' && yyf[1] == 's' && yyi < yycount)
		{
		  yyp += yytnamerr (yyp, yyarg[yyi++]);
		  yyf += 2;
		}
	      else
		{
		  yyp++;
		  yyf++;
		}
	    }
	}
      return yysize;
    }
}
#endif /* YYERROR_VERBOSE */


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, YYLTYPE *yylocationp)
#else
static void
yydestruct (yymsg, yytype, yyvaluep, yylocationp)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
    YYLTYPE *yylocationp;
#endif
{
  YYUSE (yyvaluep);
  YYUSE (yylocationp);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {

      default:
	break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */

#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (void);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */



/* The look-ahead symbol.  */
int yychar;

/* The semantic value of the look-ahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;
/* Location data for the look-ahead symbol.  */
YYLTYPE yylloc;



/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{
  
  int yystate;
  int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Look-ahead token as an internal (translated) token number.  */
  int yytoken = 0;
#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  yytype_int16 yyssa[YYINITDEPTH];
  yytype_int16 *yyss = yyssa;
  yytype_int16 *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  YYSTYPE *yyvsp;

  /* The location stack.  */
  YYLTYPE yylsa[YYINITDEPTH];
  YYLTYPE *yyls = yylsa;
  YYLTYPE *yylsp;
  /* The locations where the error started and ended.  */
  YYLTYPE yyerror_range[2];

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N), yylsp -= (N))

  YYSIZE_T yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;
  YYLTYPE yyloc;

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;
  yylsp = yyls;
#if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL
  /* Initialize the default location before parsing starts.  */
  yylloc.first_line   = yylloc.last_line   = 1;
  yylloc.first_column = yylloc.last_column = 0;
#endif

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack.  Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;
	YYLTYPE *yyls1 = yyls;

	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yyls1, yysize * sizeof (*yylsp),
		    &yystacksize);
	yyls = yyls1;
	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);
	YYSTACK_RELOCATE (yyls);
#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;
      yylsp = yyls + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     look-ahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to look-ahead token.  */
  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a look-ahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid look-ahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the look-ahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  yystate = yyn;
  *++yyvsp = yylval;
  *++yylsp = yylloc;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];

  /* Default location.  */
  YYLLOC_DEFAULT (yyloc, (yylsp - yylen), yylen);
  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 3:
#line 77 "parser.y"
    {
                                                        if (g_ctx->proc != NULL)
                                                            // You can only have one proc
                                                            YYABORT;
                                                        g_ctx->proc = Block_new((yyvsp[(4) - (5)].stmts));
                                                    ;}
    break;

  case 4:
#line 84 "parser.y"
    {
                                                        map_set(g_ctx->functions, (yyvsp[(3) - (8)].ident), Function_new((yyvsp[(3) - (8)].ident), NULL, Block_new((yyvsp[(7) - (8)].stmts))));
                                                        bhex_free((yyvsp[(3) - (8)].ident));
                                                    ;}
    break;

  case 5:
#line 89 "parser.y"
    {
                                                        map_set(g_ctx->functions, (yyvsp[(3) - (9)].ident), Function_new((yyvsp[(3) - (9)].ident), (yyvsp[(5) - (9)].params), Block_new((yyvsp[(8) - (9)].stmts))));
                                                        bhex_free((yyvsp[(3) - (9)].ident));
                                                    ;}
    break;

  case 6:
#line 94 "parser.y"
    {
                                                        map_set(g_ctx->structs, (yyvsp[(3) - (6)].ident), Block_new((yyvsp[(5) - (6)].stmts)));
                                                        bhex_free((yyvsp[(3) - (6)].ident));
                                                    ;}
    break;

  case 7:
#line 99 "parser.y"
    {
                                                        map_set(g_ctx->enums, (yyvsp[(3) - (8)].ident), Enum_new((yyvsp[(5) - (8)].ident), (yyvsp[(7) - (8)].enum_list), 0));
                                                        bhex_free((yyvsp[(3) - (8)].ident));
                                                        bhex_free((yyvsp[(5) - (8)].ident));
                                                    ;}
    break;

  case 8:
#line 105 "parser.y"
    {
                                                        map_set(g_ctx->enums, (yyvsp[(3) - (8)].ident), Enum_new((yyvsp[(5) - (8)].ident), (yyvsp[(7) - (8)].enum_list), 1));
                                                        bhex_free((yyvsp[(3) - (8)].ident));
                                                        bhex_free((yyvsp[(5) - (8)].ident));
                                                    ;}
    break;

  case 9:
#line 112 "parser.y"
    {
                                                        (yyval.enum_list) = DList_new();
                                                        DList_add((yyval.enum_list), EnumEntry_new((yyvsp[(1) - (3)].ident), yysnumval));
                                                        bhex_free((yyvsp[(1) - (3)].ident));
                                                    ;}
    break;

  case 10:
#line 117 "parser.y"
    {
                                                        DList_add((yyvsp[(1) - (5)].enum_list), EnumEntry_new((yyvsp[(3) - (5)].ident), yysnumval));
                                                        bhex_free((yyvsp[(3) - (5)].ident));
                                                    ;}
    break;

  case 11:
#line 123 "parser.y"
    {
                                                        (yyval.stmts) = DList_new();
                                                        DList_add((yyval.stmts), (yyvsp[(1) - (1)].stmt));
                                                    ;}
    break;

  case 12:
#line 127 "parser.y"
    {
                                                        DList_add((yyvsp[(1) - (2)].stmts), (yyvsp[(2) - (2)].stmt));
                                                    ;}
    break;

  case 21:
#line 142 "parser.y"
    {
                                                        (yyval.fvar_type) = Type_new((yyvsp[(1) - (1)].ident), NULL);
                                                        bhex_free((yyvsp[(1) - (1)].ident));
                                                    ;}
    break;

  case 22:
#line 146 "parser.y"
    {
                                                        (yyval.fvar_type) = Type_new((yyvsp[(3) - (3)].ident), (yyvsp[(1) - (3)].ident));
                                                        bhex_free((yyvsp[(1) - (3)].ident));
                                                        bhex_free((yyvsp[(3) - (3)].ident));
                                                    ;}
    break;

  case 23:
#line 154 "parser.y"
    {
                                                        (yyval.stmt) = Stmt_FILE_VAR_DECL_new((yyvsp[(1) - (2)].fvar_type), (yyvsp[(2) - (2)].ident), NULL);
                                                        bhex_free((yyvsp[(2) - (2)].ident));
                                                    ;}
    break;

  case 24:
#line 159 "parser.y"
    {
                                                        (yyval.stmt) = Stmt_FILE_VAR_DECL_new((yyvsp[(1) - (5)].fvar_type), (yyvsp[(2) - (5)].ident), (yyvsp[(4) - (5)].expr));
                                                        bhex_free((yyvsp[(2) - (5)].ident));
                                                    ;}
    break;

  case 25:
#line 165 "parser.y"
    {
                                                        (yyval.stmt) = Stmt_LOCAL_VAR_DECL_new((yyvsp[(2) - (4)].ident), (yyvsp[(4) - (4)].expr));
                                                        bhex_free((yyvsp[(2) - (4)].ident));
                                                    ;}
    break;

  case 26:
#line 171 "parser.y"
    {
                                                        (yyval.stmt) = Stmt_LOCAL_VAR_ASS_new((yyvsp[(1) - (3)].ident), (yyvsp[(3) - (3)].expr));
                                                        bhex_free((yyvsp[(1) - (3)].ident));
                                                    ;}
    break;

  case 27:
#line 177 "parser.y"
    {
                                                        (yyval.stmt) = Stmt_VOID_FUNC_CALL_new((yyvsp[(1) - (3)].ident), NULL);
                                                        bhex_free((yyvsp[(1) - (3)].ident));
                                                    ;}
    break;

  case 28:
#line 181 "parser.y"
    {
                                                        (yyval.stmt) = Stmt_VOID_FUNC_CALL_new((yyvsp[(1) - (4)].ident), (yyvsp[(3) - (4)].params));
                                                        bhex_free((yyvsp[(1) - (4)].ident));
                                                    ;}
    break;

  case 29:
#line 188 "parser.y"
    {
                                                        (yyval.stmt) = Stmt_STMT_IF_new((yyvsp[(3) - (7)].expr), Block_new((yyvsp[(6) - (7)].stmts)));
                                                    ;}
    break;

  case 30:
#line 192 "parser.y"
    {
                                                        Stmt_STMT_IF_add_cond((yyvsp[(1) - (8)].stmt), (yyvsp[(4) - (8)].expr), Block_new((yyvsp[(7) - (8)].stmts)));
                                                        (yyval.stmt) = (yyvsp[(1) - (8)].stmt);
                                                    ;}
    break;

  case 31:
#line 199 "parser.y"
    {
                                                        Stmt_STMT_IF_add_else((yyvsp[(1) - (5)].stmt), Block_new((yyvsp[(4) - (5)].stmts)));
                                                        (yyval.stmt) = (yyvsp[(1) - (5)].stmt);
                                                    ;}
    break;

  case 32:
#line 206 "parser.y"
    {
                                                        (yyval.stmt) = Stmt_WHILE_new((yyvsp[(3) - (7)].expr), Block_new((yyvsp[(6) - (7)].stmts)));
                                                    ;}
    break;

  case 33:
#line 211 "parser.y"
    {
                                                        (yyval.stmt) = Stmt_BREAK_new();
                                                    ;}
    break;

  case 35:
#line 217 "parser.y"
    {
                                                        (yyval.expr) = Expr_STRING_new(yyheapbuf, yyheapbuf_len);
                                                    ;}
    break;

  case 36:
#line 220 "parser.y"
    {
                                                        (yyval.expr) = Expr_VAR_new((yyvsp[(1) - (1)].ident));
                                                        bhex_free((yyvsp[(1) - (1)].ident));
                                                    ;}
    break;

  case 37:
#line 224 "parser.y"
    {
                                                        (yyval.expr) = Expr_ENUM_CONST_new((yyvsp[(1) - (3)].ident), (yyvsp[(3) - (3)].ident));
                                                        bhex_free((yyvsp[(1) - (3)].ident));
                                                        bhex_free((yyvsp[(3) - (3)].ident));
                                                    ;}
    break;

  case 38:
#line 229 "parser.y"
    {
                                                        (yyval.expr) = Expr_SUBSCR_new((yyvsp[(1) - (3)].expr), (yyvsp[(3) - (3)].ident));
                                                        bhex_free((yyvsp[(3) - (3)].ident));
                                                    ;}
    break;

  case 39:
#line 233 "parser.y"
    {
                                                        (yyval.expr) = Expr_ARRAY_SUB_new((yyvsp[(1) - (4)].expr), (yyvsp[(3) - (4)].expr));
                                                    ;}
    break;

  case 40:
#line 236 "parser.y"
    {
                                                        (yyval.expr) = Expr_FUN_CALL_new((yyvsp[(1) - (3)].ident), NULL);
                                                        bhex_free((yyvsp[(1) - (3)].ident));
                                                    ;}
    break;

  case 41:
#line 240 "parser.y"
    {
                                                        (yyval.expr) = Expr_FUN_CALL_new((yyvsp[(1) - (4)].ident), (yyvsp[(3) - (4)].params));
                                                        bhex_free((yyvsp[(1) - (4)].ident));
                                                    ;}
    break;

  case 42:
#line 244 "parser.y"
    {
                                                        (yyval.expr) = (yyvsp[(2) - (3)].expr);
                                                    ;}
    break;

  case 43:
#line 247 "parser.y"
    {
                                                        (yyval.expr) = Expr_SUB_new(Expr_SCONST_new(0, 1), (yyvsp[(2) - (2)].expr));
                                                    ;}
    break;

  case 44:
#line 250 "parser.y"
    {
                                                        (yyval.expr) = Expr_AND_new((yyvsp[(1) - (3)].expr), (yyvsp[(3) - (3)].expr));
                                                    ;}
    break;

  case 45:
#line 253 "parser.y"
    {
                                                        (yyval.expr) = Expr_OR_new((yyvsp[(1) - (3)].expr), (yyvsp[(3) - (3)].expr));
                                                    ;}
    break;

  case 46:
#line 256 "parser.y"
    {
                                                        (yyval.expr) = Expr_XOR_new((yyvsp[(1) - (3)].expr), (yyvsp[(3) - (3)].expr));
                                                    ;}
    break;

  case 47:
#line 259 "parser.y"
    {
                                                        (yyval.expr) = Expr_ADD_new((yyvsp[(1) - (3)].expr), (yyvsp[(3) - (3)].expr));
                                                    ;}
    break;

  case 48:
#line 262 "parser.y"
    {
                                                        (yyval.expr) = Expr_SUB_new((yyvsp[(1) - (3)].expr), (yyvsp[(3) - (3)].expr));
                                                    ;}
    break;

  case 49:
#line 265 "parser.y"
    {
                                                        (yyval.expr) = Expr_MUL_new((yyvsp[(1) - (3)].expr), (yyvsp[(3) - (3)].expr));
                                                    ;}
    break;

  case 50:
#line 268 "parser.y"
    {
                                                        (yyval.expr) = Expr_DIV_new((yyvsp[(1) - (3)].expr), (yyvsp[(3) - (3)].expr));
                                                    ;}
    break;

  case 51:
#line 271 "parser.y"
    {
                                                        (yyval.expr) = Expr_MOD_new((yyvsp[(1) - (3)].expr), (yyvsp[(3) - (3)].expr));
                                                    ;}
    break;

  case 52:
#line 274 "parser.y"
    {
                                                        (yyval.expr) = Expr_BEQ_new((yyvsp[(1) - (3)].expr), (yyvsp[(3) - (3)].expr));
                                                    ;}
    break;

  case 53:
#line 277 "parser.y"
    {
                                                        (yyval.expr) = Expr_BNOT_new(Expr_BEQ_new((yyvsp[(1) - (3)].expr), (yyvsp[(3) - (3)].expr)));
                                                    ;}
    break;

  case 54:
#line 280 "parser.y"
    {
                                                        (yyval.expr) = Expr_BLT_new((yyvsp[(1) - (3)].expr), (yyvsp[(3) - (3)].expr));
                                                    ;}
    break;

  case 55:
#line 283 "parser.y"
    {
                                                        (yyval.expr) = Expr_BLE_new((yyvsp[(1) - (3)].expr), (yyvsp[(3) - (3)].expr));
                                                    ;}
    break;

  case 56:
#line 286 "parser.y"
    {
                                                        (yyval.expr) = Expr_BGT_new((yyvsp[(1) - (3)].expr), (yyvsp[(3) - (3)].expr));
                                                    ;}
    break;

  case 57:
#line 289 "parser.y"
    {
                                                        (yyval.expr) = Expr_BGE_new((yyvsp[(1) - (3)].expr), (yyvsp[(3) - (3)].expr));
                                                    ;}
    break;

  case 58:
#line 292 "parser.y"
    {
                                                        (yyval.expr) = Expr_BAND_new((yyvsp[(1) - (3)].expr), (yyvsp[(3) - (3)].expr));
                                                    ;}
    break;

  case 59:
#line 295 "parser.y"
    {
                                                        (yyval.expr) = Expr_BOR_new((yyvsp[(1) - (3)].expr), (yyvsp[(3) - (3)].expr));
                                                    ;}
    break;

  case 60:
#line 298 "parser.y"
    {
                                                        (yyval.expr) = Expr_BNOT_new((yyvsp[(2) - (2)].expr));
                                                    ;}
    break;

  case 61:
#line 303 "parser.y"
    {
                                                        (yyval.params) = DList_new();
                                                        DList_add((yyval.params), (yyvsp[(1) - (1)].ident));
                                                    ;}
    break;

  case 62:
#line 307 "parser.y"
    {
                                                        DList_add((yyval.params), (yyvsp[(3) - (3)].ident));
                                                    ;}
    break;

  case 63:
#line 311 "parser.y"
    {
                                                        (yyval.params) = DList_new();
                                                        DList_add((yyval.params), (yyvsp[(1) - (1)].expr));
                                                    ;}
    break;

  case 64:
#line 315 "parser.y"
    {
                                                        DList_add((yyval.params), (yyvsp[(3) - (3)].expr));
                                                    ;}
    break;

  case 65:
#line 320 "parser.y"
    {
                                                        (yyval.expr) = Expr_UCONST_new(yyunumval, 1);
                                                    ;}
    break;

  case 66:
#line 323 "parser.y"
    {
                                                        (yyval.expr) = Expr_UCONST_new(yyunumval, 2);
                                                    ;}
    break;

  case 67:
#line 326 "parser.y"
    {
                                                        (yyval.expr) = Expr_UCONST_new(yyunumval, 4);
                                                    ;}
    break;

  case 68:
#line 329 "parser.y"
    {
                                                        (yyval.expr) = Expr_UCONST_new(yyunumval, 8);
                                                    ;}
    break;

  case 69:
#line 332 "parser.y"
    {
                                                        (yyval.expr) = Expr_SCONST_new(yysnumval, 1);
                                                    ;}
    break;

  case 70:
#line 335 "parser.y"
    {
                                                        (yyval.expr) = Expr_SCONST_new(yysnumval, 2);
                                                    ;}
    break;

  case 71:
#line 338 "parser.y"
    {
                                                        (yyval.expr) = Expr_SCONST_new(yysnumval, 4);
                                                    ;}
    break;

  case 72:
#line 341 "parser.y"
    {
                                                        (yyval.expr) = Expr_SCONST_new(yysnumval, 8);
                                                    ;}
    break;

  case 73:
#line 346 "parser.y"
    {
                                                        (yyval.ident) = bhex_strdup(yystrval);
                                                    ;}
    break;


/* Line 1267 of yacc.c.  */
#line 2165 "parser.c"
      default: break;
    }
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;
  *++yylsp = yyloc;

  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
      {
	YYSIZE_T yysize = yysyntax_error (0, yystate, yychar);
	if (yymsg_alloc < yysize && yymsg_alloc < YYSTACK_ALLOC_MAXIMUM)
	  {
	    YYSIZE_T yyalloc = 2 * yysize;
	    if (! (yysize <= yyalloc && yyalloc <= YYSTACK_ALLOC_MAXIMUM))
	      yyalloc = YYSTACK_ALLOC_MAXIMUM;
	    if (yymsg != yymsgbuf)
	      YYSTACK_FREE (yymsg);
	    yymsg = (char *) YYSTACK_ALLOC (yyalloc);
	    if (yymsg)
	      yymsg_alloc = yyalloc;
	    else
	      {
		yymsg = yymsgbuf;
		yymsg_alloc = sizeof yymsgbuf;
	      }
	  }

	if (0 < yysize && yysize <= yymsg_alloc)
	  {
	    (void) yysyntax_error (yymsg, yystate, yychar);
	    yyerror (yymsg);
	  }
	else
	  {
	    yyerror (YY_("syntax error"));
	    if (yysize != 0)
	      goto yyexhaustedlab;
	  }
      }
#endif
    }

  yyerror_range[0] = yylloc;

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse look-ahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
	{
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval, &yylloc);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse look-ahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  yyerror_range[0] = yylsp[1-yylen];
  /* Do not reclaim the symbols of the rule which action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;

      yyerror_range[0] = *yylsp;
      yydestruct ("Error: popping",
		  yystos[yystate], yyvsp, yylsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  *++yyvsp = yylval;

  yyerror_range[1] = yylloc;
  /* Using YYLLOC is tempting, but would change the location of
     the look-ahead.  YYLOC is available though.  */
  YYLLOC_DEFAULT (yyloc, (yyerror_range - 1), 2);
  *++yylsp = yyloc;

  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#ifndef yyoverflow
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEOF && yychar != YYEMPTY)
     yydestruct ("Cleanup: discarding lookahead",
		 yytoken, &yylval, &yylloc);
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp, yylsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}


#line 351 "parser.y"


