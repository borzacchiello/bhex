/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

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

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1




/* First part of user prologue.  */
#line 1 "parser.y"


#include <stdio.h>

#include <alloc.h>
#include <log.h>
#include "ast.h"

extern int   yylex();
extern char* yytext;
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
    error("[tengine parser] %s [near token '%s']", s, yytext);
}


#line 102 "parser.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

#include "parser.h"
/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_TPROC = 3,                      /* TPROC  */
  YYSYMBOL_TLOCAL = 4,                     /* TLOCAL  */
  YYSYMBOL_TSTRUCT = 5,                    /* TSTRUCT  */
  YYSYMBOL_TENUM = 6,                      /* TENUM  */
  YYSYMBOL_TORENUM = 7,                    /* TORENUM  */
  YYSYMBOL_TIF = 8,                        /* TIF  */
  YYSYMBOL_TELIF = 9,                      /* TELIF  */
  YYSYMBOL_TELSE = 10,                     /* TELSE  */
  YYSYMBOL_TWHILE = 11,                    /* TWHILE  */
  YYSYMBOL_TBREAK = 12,                    /* TBREAK  */
  YYSYMBOL_TIDENTIFIER = 13,               /* TIDENTIFIER  */
  YYSYMBOL_TUNUM8 = 14,                    /* TUNUM8  */
  YYSYMBOL_TUNUM16 = 15,                   /* TUNUM16  */
  YYSYMBOL_TUNUM32 = 16,                   /* TUNUM32  */
  YYSYMBOL_TUNUM64 = 17,                   /* TUNUM64  */
  YYSYMBOL_TSNUM8 = 18,                    /* TSNUM8  */
  YYSYMBOL_TSNUM16 = 19,                   /* TSNUM16  */
  YYSYMBOL_TSNUM32 = 20,                   /* TSNUM32  */
  YYSYMBOL_TSNUM64 = 21,                   /* TSNUM64  */
  YYSYMBOL_TSTR = 22,                      /* TSTR  */
  YYSYMBOL_TCLBRACE = 23,                  /* TCLBRACE  */
  YYSYMBOL_TCRBRACE = 24,                  /* TCRBRACE  */
  YYSYMBOL_TLBRACE = 25,                   /* TLBRACE  */
  YYSYMBOL_TRBRACE = 26,                   /* TRBRACE  */
  YYSYMBOL_SQLBRACE = 27,                  /* SQLBRACE  */
  YYSYMBOL_SQRBRACE = 28,                  /* SQRBRACE  */
  YYSYMBOL_TSEMICOLON = 29,                /* TSEMICOLON  */
  YYSYMBOL_TCOLON = 30,                    /* TCOLON  */
  YYSYMBOL_TCOMMA = 31,                    /* TCOMMA  */
  YYSYMBOL_TDOT = 32,                      /* TDOT  */
  YYSYMBOL_TADD = 33,                      /* TADD  */
  YYSYMBOL_TSUB = 34,                      /* TSUB  */
  YYSYMBOL_TMUL = 35,                      /* TMUL  */
  YYSYMBOL_TAND = 36,                      /* TAND  */
  YYSYMBOL_TOR = 37,                       /* TOR  */
  YYSYMBOL_TXOR = 38,                      /* TXOR  */
  YYSYMBOL_TBAND = 39,                     /* TBAND  */
  YYSYMBOL_TBOR = 40,                      /* TBOR  */
  YYSYMBOL_TBEQ = 41,                      /* TBEQ  */
  YYSYMBOL_TBGT = 42,                      /* TBGT  */
  YYSYMBOL_TBGE = 43,                      /* TBGE  */
  YYSYMBOL_TBLT = 44,                      /* TBLT  */
  YYSYMBOL_TBLE = 45,                      /* TBLE  */
  YYSYMBOL_TEQUAL = 46,                    /* TEQUAL  */
  YYSYMBOL_YYACCEPT = 47,                  /* $accept  */
  YYSYMBOL_program = 48,                   /* program  */
  YYSYMBOL_enum_list = 49,                 /* enum_list  */
  YYSYMBOL_stmts = 50,                     /* stmts  */
  YYSYMBOL_stmt = 51,                      /* stmt  */
  YYSYMBOL_fvar_decl = 52,                 /* fvar_decl  */
  YYSYMBOL_lvar_decl = 53,                 /* lvar_decl  */
  YYSYMBOL_lvar_ass = 54,                  /* lvar_ass  */
  YYSYMBOL_void_fcall = 55,                /* void_fcall  */
  YYSYMBOL_if_elif = 56,                   /* if_elif  */
  YYSYMBOL_else = 57,                      /* else  */
  YYSYMBOL_while = 58,                     /* while  */
  YYSYMBOL_break = 59,                     /* break  */
  YYSYMBOL_expr = 60,                      /* expr  */
  YYSYMBOL_varchain = 61,                  /* varchain  */
  YYSYMBOL_params = 62,                    /* params  */
  YYSYMBOL_num = 63,                       /* num  */
  YYSYMBOL_ident = 64                      /* ident  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;




#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_uint8 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
#if defined __GNUC__ && ! defined __ICC && 406 <= __GNUC__ * 100 + __GNUC_MINOR__
# if __GNUC__ * 100 + __GNUC_MINOR__ < 407
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")
# else
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# endif
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if !defined yyoverflow

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
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
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
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* !defined yyoverflow */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   373

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  47
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  18
/* YYNRULES -- Number of rules.  */
#define YYNRULES  63
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  144

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   301


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
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
      45,    46
};

#if YYDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,    69,    69,    70,    76,    81,    87,    95,   100,   106,
     110,   115,   116,   117,   118,   119,   120,   121,   122,   125,
     130,   137,   143,   149,   153,   159,   163,   170,   177,   183,
     188,   189,   192,   196,   199,   203,   207,   210,   213,   216,
     219,   222,   225,   228,   231,   234,   237,   240,   243,   246,
     249,   254,   259,   264,   268,   273,   276,   279,   282,   285,
     288,   291,   294,   299
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if YYDEBUG || 0
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "TPROC", "TLOCAL",
  "TSTRUCT", "TENUM", "TORENUM", "TIF", "TELIF", "TELSE", "TWHILE",
  "TBREAK", "TIDENTIFIER", "TUNUM8", "TUNUM16", "TUNUM32", "TUNUM64",
  "TSNUM8", "TSNUM16", "TSNUM32", "TSNUM64", "TSTR", "TCLBRACE",
  "TCRBRACE", "TLBRACE", "TRBRACE", "SQLBRACE", "SQRBRACE", "TSEMICOLON",
  "TCOLON", "TCOMMA", "TDOT", "TADD", "TSUB", "TMUL", "TAND", "TOR",
  "TXOR", "TBAND", "TBOR", "TBEQ", "TBGT", "TBGE", "TBLT", "TBLE",
  "TEQUAL", "$accept", "program", "enum_list", "stmts", "stmt",
  "fvar_decl", "lvar_decl", "lvar_ass", "void_fcall", "if_elif", "else",
  "while", "break", "expr", "varchain", "params", "num", "ident", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-24)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-1)

#define yytable_value_is_error(Yyn) \
  0

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -24,   108,   -24,   -18,     2,     2,     2,    91,   -24,   -16,
     -17,    10,     2,     4,     7,   -24,     6,   -24,    15,    30,
      32,    37,    48,   -24,   -24,    39,    -7,    91,     2,     2,
      27,   300,   300,   -24,   -24,   -24,   -24,   -24,   -24,    51,
      46,   -24,   256,   300,    50,    25,    58,    59,   300,   -24,
     -24,   -24,   -24,   -24,   -24,   -24,   -24,   -24,   300,   300,
     157,    43,   -24,   -12,   179,   300,    91,   -24,   315,    -3,
     315,   300,   -24,     2,     2,   315,   201,    54,    60,   300,
     300,   300,   300,   300,   300,   300,   300,   300,   300,   300,
     300,   300,     2,   278,     2,    62,   223,    41,   -24,   300,
     302,     0,    45,    24,   -24,    91,    54,    54,   -24,    13,
      13,    13,   328,   328,   113,   113,   113,   113,   113,   -24,
     -24,    11,   -24,    91,    67,   -24,   315,   -24,   -24,     2,
      75,   -24,    52,   -24,    68,    91,    61,   -24,   -24,   -24,
     163,    76,   -24,   -24
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_int8 yydefact[] =
{
       2,     0,     1,     0,     0,     0,     0,     0,    63,     0,
       0,     0,     0,     0,     0,    29,     0,     9,     0,     0,
       0,     0,    16,    17,    18,     0,     0,     0,     0,     0,
       0,     0,     0,     3,    10,    11,    12,    13,    14,     0,
       0,    15,     0,     0,    19,     0,     0,     0,     0,    55,
      56,    57,    58,    59,    60,    61,    62,    31,     0,     0,
       0,    33,    30,    32,     0,     0,     0,    23,    53,     0,
      22,     0,     4,     0,     0,    21,     0,    37,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,    24,     0,
       0,     0,     0,     0,    36,     0,    41,    42,    43,    38,
      39,    40,    49,    50,    44,    47,    48,    45,    46,    52,
      34,     0,    51,     0,     0,    27,    54,    20,     5,     0,
       0,     6,     0,    35,     0,     0,     0,     7,    25,    28,
       0,     0,    26,     8
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -24,   -24,    35,   -23,   -11,   -24,   -24,   -24,   -24,   -24,
     -24,   -24,   -24,    74,   -24,     5,   -24,    -4
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
       0,     1,   101,    16,    17,    18,    19,    20,    21,    22,
      23,    24,    25,    68,    61,    69,    62,    63
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_uint8 yytable[] =
{
       9,    10,    11,    26,    45,    34,     8,     7,    30,    27,
      12,    93,    26,    28,    13,     8,    42,    14,    15,     8,
      94,    98,    44,    26,    46,    47,   128,    31,    99,    12,
      32,   129,    33,    13,    34,   133,    14,    15,     8,    43,
      29,    26,    99,    97,    35,    12,    79,    80,    81,    13,
     131,    72,    14,    15,     8,   129,    12,    39,    40,    36,
      13,    37,    26,    14,    15,     8,    38,   125,    41,   102,
     102,    66,    12,    48,    65,    92,    13,    71,   138,    14,
      15,     8,   132,    73,    74,   105,    34,   123,   119,    81,
     122,   130,   135,    26,   139,    12,   137,   143,   121,    13,
     134,    26,    14,    15,     8,    60,    64,   141,     2,   103,
       0,     3,   140,     4,     5,     6,     0,    70,     0,    26,
       0,    34,    75,    34,     0,   136,     0,     0,    26,    34,
      26,    26,    76,    77,     0,     0,    26,     0,     0,    96,
       0,     0,     0,     0,     0,   100,    79,    80,    81,    82,
      83,    84,     0,   106,   107,   108,   109,   110,   111,   112,
     113,   114,   115,   116,   117,   118,     0,    12,     0,     0,
       0,    13,     0,   126,    14,    15,     8,     0,     0,     0,
       0,    78,     0,     0,     0,     0,     0,     0,     0,   142,
      79,    80,    81,    82,    83,    84,    85,    86,    87,    88,
      89,    90,    91,    95,     0,     0,     0,     0,     0,     0,
       0,     0,    79,    80,    81,    82,    83,    84,    85,    86,
      87,    88,    89,    90,    91,   104,     0,     0,     0,     0,
       0,     0,     0,     0,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    90,    91,   124,     0,     0,
       0,     0,     0,     0,     0,     0,    79,    80,    81,    82,
      83,    84,    85,    86,    87,    88,    89,    90,    91,     8,
      49,    50,    51,    52,    53,    54,    55,    56,    57,    58,
      67,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      59,     8,    49,    50,    51,    52,    53,    54,    55,    56,
      57,    58,   120,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    59,     8,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,     0,     0,     0,     0,     0,     0,
     127,     0,     0,     0,    59,    79,    80,    81,    82,    83,
      84,    85,    86,    87,    88,    89,    90,    91,    79,    80,
      81,    82,    83,    84,    85,    86,    87,    88,    89,    90,
      91,    79,    80,    81,    82,    83,    84,     0,     0,    87,
      88,    89,    90,    91
};

static const yytype_int16 yycheck[] =
{
       4,     5,     6,     7,    27,    16,    13,    25,    12,    25,
       4,    23,    16,    30,     8,    13,    23,    11,    12,    13,
      32,    24,    26,    27,    28,    29,    26,    23,    31,     4,
      23,    31,    26,     8,    45,    24,    11,    12,    13,    46,
      30,    45,    31,    66,    29,     4,    33,    34,    35,     8,
      26,    26,    11,    12,    13,    31,     4,     9,    10,    29,
       8,    29,    66,    11,    12,    13,    29,    26,    29,    73,
      74,    25,     4,    46,    23,    32,     8,    27,    26,    11,
      12,    13,   105,    25,    25,    25,    97,    25,    92,    35,
      94,    46,    25,    97,    26,     4,    21,    21,    93,     8,
     123,   105,    11,    12,    13,    31,    32,    46,     0,    74,
      -1,     3,   135,     5,     6,     7,    -1,    43,    -1,   123,
      -1,   132,    48,   134,    -1,   129,    -1,    -1,   132,   140,
     134,   135,    58,    59,    -1,    -1,   140,    -1,    -1,    65,
      -1,    -1,    -1,    -1,    -1,    71,    33,    34,    35,    36,
      37,    38,    -1,    79,    80,    81,    82,    83,    84,    85,
      86,    87,    88,    89,    90,    91,    -1,     4,    -1,    -1,
      -1,     8,    -1,    99,    11,    12,    13,    -1,    -1,    -1,
      -1,    24,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    26,
      33,    34,    35,    36,    37,    38,    39,    40,    41,    42,
      43,    44,    45,    24,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    33,    34,    35,    36,    37,    38,    39,    40,
      41,    42,    43,    44,    45,    24,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    33,    34,    35,    36,    37,    38,
      39,    40,    41,    42,    43,    44,    45,    24,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    33,    34,    35,    36,
      37,    38,    39,    40,    41,    42,    43,    44,    45,    13,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      34,    13,    14,    15,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    34,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    -1,    -1,    -1,    -1,    -1,    -1,
      28,    -1,    -1,    -1,    34,    33,    34,    35,    36,    37,
      38,    39,    40,    41,    42,    43,    44,    45,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    33,    34,    35,    36,    37,    38,    -1,    -1,    41,
      42,    43,    44,    45
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,    48,     0,     3,     5,     6,     7,    25,    13,    64,
      64,    64,     4,     8,    11,    12,    50,    51,    52,    53,
      54,    55,    56,    57,    58,    59,    64,    25,    30,    30,
      64,    23,    23,    26,    51,    29,    29,    29,    29,     9,
      10,    29,    23,    46,    64,    50,    64,    64,    46,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    34,
      60,    61,    63,    64,    60,    23,    25,    24,    60,    62,
      60,    27,    26,    25,    25,    60,    60,    60,    24,    33,
      34,    35,    36,    37,    38,    39,    40,    41,    42,    43,
      44,    45,    32,    23,    32,    24,    60,    50,    24,    31,
      60,    49,    64,    49,    24,    25,    60,    60,    60,    60,
      60,    60,    60,    60,    60,    60,    60,    60,    60,    64,
      24,    62,    64,    25,    24,    26,    60,    28,    26,    31,
      46,    26,    50,    24,    50,    25,    64,    21,    26,    26,
      50,    46,    26,    21
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr1[] =
{
       0,    47,    48,    48,    48,    48,    48,    49,    49,    50,
      50,    51,    51,    51,    51,    51,    51,    51,    51,    52,
      52,    53,    54,    55,    55,    56,    56,    57,    58,    59,
      60,    60,    60,    60,    60,    60,    60,    60,    60,    60,
      60,    60,    60,    60,    60,    60,    60,    60,    60,    60,
      60,    61,    61,    62,    62,    63,    63,    63,    63,    63,
      63,    63,    63,    64
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     0,     5,     6,     8,     8,     3,     5,     1,
       2,     2,     2,     2,     2,     2,     1,     1,     1,     2,
       5,     4,     3,     3,     4,     7,     8,     5,     7,     1,
       1,     1,     1,     1,     3,     4,     3,     2,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     1,     3,     1,     1,     1,     1,     1,
       1,     1,     1,     1
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYNOMEM         goto yyexhaustedlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Backward compatibility with an undocumented macro.
   Use YYerror or YYUNDEF. */
#define YYERRCODE YYUNDEF


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)




# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  if (!yyvaluep)
    return;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  yy_symbol_value_print (yyo, yykind, yyvaluep);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp,
                 int yyrule)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)]);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
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






/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep)
{
  YY_USE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/* Lookahead token kind.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;




/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = YYEMPTY; /* Cause a token to be read.  */

  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    YYNOMEM;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        YYNOMEM;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          YYNOMEM;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */


  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = YYEOF;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == YYerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = YYUNDEF;
      yytoken = YYSYMBOL_YYerror;
      goto yyerrlab1;
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
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
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
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 3: /* program: program TPROC TLBRACE stmts TRBRACE  */
#line 70 "parser.y"
                                                    {
                                                        if (g_ctx->proc != NULL)
                                                            // You can only have one proc
                                                            YYABORT;
                                                        g_ctx->proc = Block_new((yyvsp[-1].stmts));
                                                    }
#line 1293 "parser.c"
    break;

  case 4: /* program: program TSTRUCT ident TLBRACE stmts TRBRACE  */
#line 77 "parser.y"
                                                    {
                                                        map_set(g_ctx->structs, (yyvsp[-3].ident), Block_new((yyvsp[-1].stmts)));
                                                        bhex_free((yyvsp[-3].ident));
                                                    }
#line 1302 "parser.c"
    break;

  case 5: /* program: program TENUM ident TCOLON ident TLBRACE enum_list TRBRACE  */
#line 82 "parser.y"
                                                    {
                                                        map_set(g_ctx->enums, (yyvsp[-5].ident), Enum_new((yyvsp[-3].ident), (yyvsp[-1].enum_list), 0));
                                                        bhex_free((yyvsp[-5].ident));
                                                        bhex_free((yyvsp[-3].ident));
                                                    }
#line 1312 "parser.c"
    break;

  case 6: /* program: program TORENUM ident TCOLON ident TLBRACE enum_list TRBRACE  */
#line 88 "parser.y"
                                                    {
                                                        map_set(g_ctx->enums, (yyvsp[-5].ident), Enum_new((yyvsp[-3].ident), (yyvsp[-1].enum_list), 1));
                                                        bhex_free((yyvsp[-5].ident));
                                                        bhex_free((yyvsp[-3].ident));
                                                    }
#line 1322 "parser.c"
    break;

  case 7: /* enum_list: ident TEQUAL TSNUM64  */
#line 95 "parser.y"
                                                    {
                                                        (yyval.enum_list) = DList_new();
                                                        DList_add((yyval.enum_list), EnumEntry_new((yyvsp[-2].ident), yysnumval));
                                                        bhex_free((yyvsp[-2].ident));
                                                    }
#line 1332 "parser.c"
    break;

  case 8: /* enum_list: enum_list TCOMMA ident TEQUAL TSNUM64  */
#line 100 "parser.y"
                                                    {
                                                        DList_add((yyvsp[-4].enum_list), EnumEntry_new((yyvsp[-2].ident), yysnumval));
                                                        bhex_free((yyvsp[-2].ident));
                                                    }
#line 1341 "parser.c"
    break;

  case 9: /* stmts: stmt  */
#line 106 "parser.y"
                                                   {
                                                        (yyval.stmts) = DList_new();
                                                        DList_add((yyval.stmts), (yyvsp[0].stmt));
                                                    }
#line 1350 "parser.c"
    break;

  case 10: /* stmts: stmts stmt  */
#line 110 "parser.y"
                                                    {
                                                        DList_add((yyvsp[-1].stmts), (yyvsp[0].stmt));
                                                    }
#line 1358 "parser.c"
    break;

  case 19: /* fvar_decl: ident ident  */
#line 125 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_FILE_VAR_DECL_new((yyvsp[-1].ident), (yyvsp[0].ident), NULL);
                                                        bhex_free((yyvsp[-1].ident));
                                                        bhex_free((yyvsp[0].ident));
                                                    }
#line 1368 "parser.c"
    break;

  case 20: /* fvar_decl: ident ident SQLBRACE expr SQRBRACE  */
#line 130 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_FILE_VAR_DECL_new((yyvsp[-4].ident), (yyvsp[-3].ident), (yyvsp[-1].expr));
                                                        bhex_free((yyvsp[-4].ident));
                                                        bhex_free((yyvsp[-3].ident));
                                                    }
#line 1378 "parser.c"
    break;

  case 21: /* lvar_decl: TLOCAL ident TEQUAL expr  */
#line 137 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_LOCAL_VAR_DECL_new((yyvsp[-2].ident), (yyvsp[0].expr));
                                                        bhex_free((yyvsp[-2].ident));
                                                    }
#line 1387 "parser.c"
    break;

  case 22: /* lvar_ass: ident TEQUAL expr  */
#line 143 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_LOCAL_VAR_ASS_new((yyvsp[-2].ident), (yyvsp[0].expr));
                                                        bhex_free((yyvsp[-2].ident));
                                                    }
#line 1396 "parser.c"
    break;

  case 23: /* void_fcall: ident TCLBRACE TCRBRACE  */
#line 149 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_VOID_FUNC_CALL_new((yyvsp[-2].ident), NULL);
                                                        bhex_free((yyvsp[-2].ident));
                                                    }
#line 1405 "parser.c"
    break;

  case 24: /* void_fcall: ident TCLBRACE params TCRBRACE  */
#line 153 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_VOID_FUNC_CALL_new((yyvsp[-3].ident), (yyvsp[-1].params));
                                                        bhex_free((yyvsp[-3].ident));
                                                    }
#line 1414 "parser.c"
    break;

  case 25: /* if_elif: TIF TCLBRACE expr TCRBRACE TLBRACE stmts TRBRACE  */
#line 160 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_STMT_IF_new((yyvsp[-4].expr), Block_new((yyvsp[-1].stmts)));
                                                    }
#line 1422 "parser.c"
    break;

  case 26: /* if_elif: if_elif TELIF TCLBRACE expr TCRBRACE TLBRACE stmts TRBRACE  */
#line 164 "parser.y"
                                                    {
                                                        Stmt_STMT_IF_add_cond((yyvsp[-7].stmt), (yyvsp[-4].expr), Block_new((yyvsp[-1].stmts)));
                                                        (yyval.stmt) = (yyvsp[-7].stmt);
                                                    }
#line 1431 "parser.c"
    break;

  case 27: /* else: if_elif TELSE TLBRACE stmts TRBRACE  */
#line 171 "parser.y"
                                                    {
                                                        Stmt_STMT_IF_add_else((yyvsp[-4].stmt), Block_new((yyvsp[-1].stmts)));
                                                        (yyval.stmt) = (yyvsp[-4].stmt);
                                                    }
#line 1440 "parser.c"
    break;

  case 28: /* while: TWHILE TCLBRACE expr TCRBRACE TLBRACE stmts TRBRACE  */
#line 178 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_WHILE_new((yyvsp[-4].expr), Block_new((yyvsp[-1].stmts)));
                                                    }
#line 1448 "parser.c"
    break;

  case 29: /* break: TBREAK  */
#line 183 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_BREAK_new();
                                                    }
#line 1456 "parser.c"
    break;

  case 31: /* expr: TSTR  */
#line 189 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_STRING_new(yyheapbuf, yyheapbuf_len);
                                                    }
#line 1464 "parser.c"
    break;

  case 32: /* expr: ident  */
#line 192 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_VAR_new((yyvsp[0].ident));
                                                        bhex_free((yyvsp[0].ident));
                                                    }
#line 1473 "parser.c"
    break;

  case 33: /* expr: varchain  */
#line 196 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_VARCHAIN_new((yyvsp[0].varchain));
                                                    }
#line 1481 "parser.c"
    break;

  case 34: /* expr: ident TCLBRACE TCRBRACE  */
#line 199 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_FUN_CALL_new((yyvsp[-2].ident), NULL);
                                                        bhex_free((yyvsp[-2].ident));
                                                    }
#line 1490 "parser.c"
    break;

  case 35: /* expr: ident TCLBRACE params TCRBRACE  */
#line 203 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_FUN_CALL_new((yyvsp[-3].ident), (yyvsp[-1].params));
                                                        bhex_free((yyvsp[-3].ident));
                                                    }
#line 1499 "parser.c"
    break;

  case 36: /* expr: TCLBRACE expr TCRBRACE  */
#line 207 "parser.y"
                                                    {
                                                        (yyval.expr) = (yyvsp[-1].expr);
                                                    }
#line 1507 "parser.c"
    break;

  case 37: /* expr: TSUB expr  */
#line 210 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SUB_new(Expr_SCONST_new(0, 1), (yyvsp[0].expr));
                                                    }
#line 1515 "parser.c"
    break;

  case 38: /* expr: expr TAND expr  */
#line 213 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_AND_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1523 "parser.c"
    break;

  case 39: /* expr: expr TOR expr  */
#line 216 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_OR_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1531 "parser.c"
    break;

  case 40: /* expr: expr TXOR expr  */
#line 219 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_XOR_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1539 "parser.c"
    break;

  case 41: /* expr: expr TADD expr  */
#line 222 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_ADD_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1547 "parser.c"
    break;

  case 42: /* expr: expr TSUB expr  */
#line 225 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SUB_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1555 "parser.c"
    break;

  case 43: /* expr: expr TMUL expr  */
#line 228 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_MUL_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1563 "parser.c"
    break;

  case 44: /* expr: expr TBEQ expr  */
#line 231 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BEQ_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1571 "parser.c"
    break;

  case 45: /* expr: expr TBLT expr  */
#line 234 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BLT_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1579 "parser.c"
    break;

  case 46: /* expr: expr TBLE expr  */
#line 237 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BLE_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1587 "parser.c"
    break;

  case 47: /* expr: expr TBGT expr  */
#line 240 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BGT_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1595 "parser.c"
    break;

  case 48: /* expr: expr TBGE expr  */
#line 243 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BGE_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1603 "parser.c"
    break;

  case 49: /* expr: expr TBAND expr  */
#line 246 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BAND_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1611 "parser.c"
    break;

  case 50: /* expr: expr TBOR expr  */
#line 249 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BOR_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1619 "parser.c"
    break;

  case 51: /* varchain: ident TDOT ident  */
#line 254 "parser.y"
                                                    {
                                                        (yyval.varchain) = DList_new();
                                                        DList_add((yyval.varchain), (yyvsp[-2].ident));
                                                        DList_add((yyval.varchain), (yyvsp[0].ident));
                                                    }
#line 1629 "parser.c"
    break;

  case 52: /* varchain: varchain TDOT ident  */
#line 259 "parser.y"
                                                    {
                                                        DList_add((yyvsp[-2].varchain), (yyvsp[0].ident));
                                                    }
#line 1637 "parser.c"
    break;

  case 53: /* params: expr  */
#line 264 "parser.y"
                                                    {
                                                        (yyval.params) = DList_new();
                                                        DList_add((yyval.params), (yyvsp[0].expr));
                                                    }
#line 1646 "parser.c"
    break;

  case 54: /* params: params TCOMMA expr  */
#line 268 "parser.y"
                                                    {
                                                        DList_add((yyval.params), (yyvsp[0].expr));
                                                    }
#line 1654 "parser.c"
    break;

  case 55: /* num: TUNUM8  */
#line 273 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_UCONST_new(yyunumval, 1);
                                                    }
#line 1662 "parser.c"
    break;

  case 56: /* num: TUNUM16  */
#line 276 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_UCONST_new(yyunumval, 2);
                                                    }
#line 1670 "parser.c"
    break;

  case 57: /* num: TUNUM32  */
#line 279 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_UCONST_new(yyunumval, 4);
                                                    }
#line 1678 "parser.c"
    break;

  case 58: /* num: TUNUM64  */
#line 282 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_UCONST_new(yyunumval, 8);
                                                    }
#line 1686 "parser.c"
    break;

  case 59: /* num: TSNUM8  */
#line 285 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SCONST_new(yysnumval, 1);
                                                    }
#line 1694 "parser.c"
    break;

  case 60: /* num: TSNUM16  */
#line 288 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SCONST_new(yysnumval, 2);
                                                    }
#line 1702 "parser.c"
    break;

  case 61: /* num: TSNUM32  */
#line 291 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SCONST_new(yysnumval, 4);
                                                    }
#line 1710 "parser.c"
    break;

  case 62: /* num: TSNUM64  */
#line 294 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SCONST_new(yysnumval, 8);
                                                    }
#line 1718 "parser.c"
    break;

  case 63: /* ident: TIDENTIFIER  */
#line 299 "parser.y"
                                                    {
                                                        (yyval.ident) = bhex_strdup(yystrval);
                                                    }
#line 1726 "parser.c"
    break;


#line 1730 "parser.c"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      yyerror (YY_("syntax error"));
    }

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
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
                      yytoken, &yylval);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;
  ++yynerrs;

  /* Do not reclaim the symbols of the rule whose action triggered
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
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturnlab;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturnlab;


/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturnlab;


/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif

  return yyresult;
}

#line 304 "parser.y"

