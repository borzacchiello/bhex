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


#line 103 "parser.c"

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
  YYSYMBOL_TFN = 4,                        /* TFN  */
  YYSYMBOL_TLOCAL = 5,                     /* TLOCAL  */
  YYSYMBOL_TSTRUCT = 6,                    /* TSTRUCT  */
  YYSYMBOL_TENUM = 7,                      /* TENUM  */
  YYSYMBOL_TORENUM = 8,                    /* TORENUM  */
  YYSYMBOL_TIF = 9,                        /* TIF  */
  YYSYMBOL_TELIF = 10,                     /* TELIF  */
  YYSYMBOL_TELSE = 11,                     /* TELSE  */
  YYSYMBOL_TWHILE = 12,                    /* TWHILE  */
  YYSYMBOL_TBREAK = 13,                    /* TBREAK  */
  YYSYMBOL_TIDENTIFIER = 14,               /* TIDENTIFIER  */
  YYSYMBOL_TUNUM8 = 15,                    /* TUNUM8  */
  YYSYMBOL_TUNUM16 = 16,                   /* TUNUM16  */
  YYSYMBOL_TUNUM32 = 17,                   /* TUNUM32  */
  YYSYMBOL_TUNUM64 = 18,                   /* TUNUM64  */
  YYSYMBOL_TSNUM8 = 19,                    /* TSNUM8  */
  YYSYMBOL_TSNUM16 = 20,                   /* TSNUM16  */
  YYSYMBOL_TSNUM32 = 21,                   /* TSNUM32  */
  YYSYMBOL_TSNUM64 = 22,                   /* TSNUM64  */
  YYSYMBOL_TSTR = 23,                      /* TSTR  */
  YYSYMBOL_TCLBRACE = 24,                  /* TCLBRACE  */
  YYSYMBOL_TCRBRACE = 25,                  /* TCRBRACE  */
  YYSYMBOL_TLBRACE = 26,                   /* TLBRACE  */
  YYSYMBOL_TRBRACE = 27,                   /* TRBRACE  */
  YYSYMBOL_SQLBRACE = 28,                  /* SQLBRACE  */
  YYSYMBOL_SQRBRACE = 29,                  /* SQRBRACE  */
  YYSYMBOL_TSEMICOLON = 30,                /* TSEMICOLON  */
  YYSYMBOL_TCOLON = 31,                    /* TCOLON  */
  YYSYMBOL_TCOMMA = 32,                    /* TCOMMA  */
  YYSYMBOL_TDOT = 33,                      /* TDOT  */
  YYSYMBOL_TCOLCOL = 34,                   /* TCOLCOL  */
  YYSYMBOL_TADD = 35,                      /* TADD  */
  YYSYMBOL_TSUB = 36,                      /* TSUB  */
  YYSYMBOL_TMUL = 37,                      /* TMUL  */
  YYSYMBOL_TDIV = 38,                      /* TDIV  */
  YYSYMBOL_TMOD = 39,                      /* TMOD  */
  YYSYMBOL_TAND = 40,                      /* TAND  */
  YYSYMBOL_TOR = 41,                       /* TOR  */
  YYSYMBOL_TXOR = 42,                      /* TXOR  */
  YYSYMBOL_TBAND = 43,                     /* TBAND  */
  YYSYMBOL_TBOR = 44,                      /* TBOR  */
  YYSYMBOL_TBEQ = 45,                      /* TBEQ  */
  YYSYMBOL_TBNEQ = 46,                     /* TBNEQ  */
  YYSYMBOL_TBGT = 47,                      /* TBGT  */
  YYSYMBOL_TBGE = 48,                      /* TBGE  */
  YYSYMBOL_TBLT = 49,                      /* TBLT  */
  YYSYMBOL_TBLE = 50,                      /* TBLE  */
  YYSYMBOL_TEQUAL = 51,                    /* TEQUAL  */
  YYSYMBOL_TBNOT = 52,                     /* TBNOT  */
  YYSYMBOL_YYACCEPT = 53,                  /* $accept  */
  YYSYMBOL_program = 54,                   /* program  */
  YYSYMBOL_enum_list = 55,                 /* enum_list  */
  YYSYMBOL_stmts = 56,                     /* stmts  */
  YYSYMBOL_stmt = 57,                      /* stmt  */
  YYSYMBOL_fvar_decl = 58,                 /* fvar_decl  */
  YYSYMBOL_lvar_decl = 59,                 /* lvar_decl  */
  YYSYMBOL_lvar_ass = 60,                  /* lvar_ass  */
  YYSYMBOL_void_fcall = 61,                /* void_fcall  */
  YYSYMBOL_if_elif = 62,                   /* if_elif  */
  YYSYMBOL_else = 63,                      /* else  */
  YYSYMBOL_while = 64,                     /* while  */
  YYSYMBOL_break = 65,                     /* break  */
  YYSYMBOL_expr = 66,                      /* expr  */
  YYSYMBOL_name_params = 67,               /* name_params  */
  YYSYMBOL_params = 68,                    /* params  */
  YYSYMBOL_num = 69,                       /* num  */
  YYSYMBOL_ident = 70                      /* ident  */
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
         || (defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL \
             && defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
  YYLTYPE yyls_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE) \
             + YYSIZEOF (YYLTYPE)) \
      + 2 * YYSTACK_GAP_MAXIMUM)

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
#define YYLAST   477

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  53
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  18
/* YYNRULES -- Number of rules.  */
#define YYNRULES  71
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  169

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   307


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
      45,    46,    47,    48,    49,    50,    51,    52
};

#if YYDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,    74,    74,    75,    81,    86,    91,    96,   102,   110,
     115,   121,   125,   130,   131,   132,   133,   134,   135,   136,
     137,   140,   145,   152,   158,   164,   168,   174,   178,   185,
     192,   198,   203,   204,   207,   211,   216,   220,   223,   227,
     231,   234,   237,   240,   243,   246,   249,   252,   255,   258,
     261,   264,   267,   270,   273,   276,   279,   282,   285,   290,
     294,   298,   302,   307,   310,   313,   316,   319,   322,   325,
     328,   333
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
  "\"end of file\"", "error", "\"invalid token\"", "TPROC", "TFN",
  "TLOCAL", "TSTRUCT", "TENUM", "TORENUM", "TIF", "TELIF", "TELSE",
  "TWHILE", "TBREAK", "TIDENTIFIER", "TUNUM8", "TUNUM16", "TUNUM32",
  "TUNUM64", "TSNUM8", "TSNUM16", "TSNUM32", "TSNUM64", "TSTR", "TCLBRACE",
  "TCRBRACE", "TLBRACE", "TRBRACE", "SQLBRACE", "SQRBRACE", "TSEMICOLON",
  "TCOLON", "TCOMMA", "TDOT", "TCOLCOL", "TADD", "TSUB", "TMUL", "TDIV",
  "TMOD", "TAND", "TOR", "TXOR", "TBAND", "TBOR", "TBEQ", "TBNEQ", "TBGT",
  "TBGE", "TBLT", "TBLE", "TEQUAL", "TBNOT", "$accept", "program",
  "enum_list", "stmts", "stmt", "fvar_decl", "lvar_decl", "lvar_ass",
  "void_fcall", "if_elif", "else", "while", "break", "expr", "name_params",
  "params", "num", "ident", YY_NULLPTR
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
     -24,   219,   -24,   -17,    32,    32,    32,    32,   101,   -24,
      38,    43,    44,    53,    32,    40,    64,   -24,     6,   -24,
      59,    66,    67,    70,    49,   -24,   -24,    71,    -8,    17,
     101,    32,    32,    52,   239,   239,   -24,   -24,   -24,   -24,
     -24,   -24,    84,    83,   -24,   193,   239,    89,   106,     5,
     -24,    27,   107,   108,   239,   -24,   -24,   -24,   -24,   -24,
     -24,   -24,   -24,   -24,   239,   239,   239,   257,   -24,    11,
     283,   239,   101,   -24,   404,    25,   404,   239,   101,   109,
      32,   -24,    32,    32,   404,   309,   -16,   -20,   115,   239,
      32,   239,   239,   239,   239,   239,   239,   239,   239,   239,
     239,   239,   239,   239,   239,   239,   239,   216,    32,   123,
     335,    39,   -24,   239,   358,    58,   101,   -24,     2,    92,
      29,   -24,   101,   381,   -24,   -16,   -16,   -20,   -20,   -20,
     241,   241,   241,   427,   427,   138,   138,   138,   138,   138,
     138,   -24,    33,   -24,   101,   124,   -24,   404,   -24,   -24,
      68,   -24,    32,    72,   -24,    78,   -24,   -24,   111,   101,
     -24,   102,   -24,   -24,   -24,   117,    97,   -24,   -24
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_int8 yydefact[] =
{
       2,     0,     1,     0,     0,     0,     0,     0,     0,    71,
       0,     0,     0,     0,     0,     0,     0,    31,     0,    11,
       0,     0,     0,     0,    18,    19,    20,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     3,    12,    13,    14,
      15,    16,     0,     0,    17,     0,     0,    21,     0,     0,
      59,     0,     0,     0,     0,    63,    64,    65,    66,    67,
      68,    69,    70,    33,     0,     0,     0,     0,    32,    34,
       0,     0,     0,    25,    61,     0,    24,     0,     0,     0,
       0,     6,     0,     0,    23,     0,    41,    58,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    26,     0,     0,     0,     0,    60,     0,     0,
       0,    40,     0,     0,    36,    45,    46,    47,    48,    49,
      42,    43,    44,    56,    57,    50,    51,    54,    55,    52,
      53,    38,     0,    35,     0,     0,    29,    62,    22,     4,
       0,     7,     0,     0,     8,     0,    37,    39,     0,     0,
       5,     0,     9,    27,    30,     0,     0,    28,    10
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -24,   -24,    73,   -23,   -13,   -24,   -24,   -24,   -24,   -24,
     -24,   -24,   -24,    93,   -24,    55,   -24,    -4
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
       0,     1,   118,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    74,    49,    75,    68,    69
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_uint8 yytable[] =
{
      10,    11,    12,    13,    28,    37,     9,    51,    89,     8,
      33,    14,    89,    90,    28,    15,    45,    90,    16,    17,
       9,    93,    94,    95,    47,    50,    28,    52,    53,   151,
      79,     9,    14,    36,   152,   107,    15,    80,    37,    16,
      17,     9,    48,    46,    14,   108,     9,    28,    15,   111,
     112,    16,    17,     9,    81,   115,   154,   113,   157,    42,
      43,   152,    29,    14,    34,   113,   146,    15,    28,    30,
      16,    17,     9,    14,    28,    31,   117,    15,   119,   119,
      16,    17,     9,    14,    32,   149,   124,    15,    35,    38,
      16,    17,     9,   150,   162,   160,    39,    40,    37,   155,
      41,    44,    37,    54,   143,   163,    14,    28,    71,    72,
      15,    28,    28,    16,    17,     9,    14,    77,    28,   168,
      15,   158,    14,    16,    17,     9,    15,    67,    70,    16,
      17,     9,    78,    82,    83,   116,   165,    37,   164,    76,
      28,   122,    37,   153,   167,    37,    28,    84,   161,   144,
     159,    28,    37,   166,    28,    28,   120,    85,    86,    87,
       0,    28,   142,     0,   110,     0,    89,     0,     0,     0,
     114,    90,     0,    91,    92,    93,    94,    95,    96,    97,
      98,     0,   123,     0,   125,   126,   127,   128,   129,   130,
     131,   132,   133,   134,   135,   136,   137,   138,   139,   140,
       0,     0,     0,     0,     0,     0,   147,     9,    55,    56,
      57,    58,    59,    60,    61,    62,    63,    64,    73,     2,
       0,     0,     3,     4,     0,     5,     6,     7,     0,    65,
       9,    55,    56,    57,    58,    59,    60,    61,    62,    63,
      64,   141,     0,     0,     0,    66,     0,     0,     0,     0,
       0,     0,    65,     9,    55,    56,    57,    58,    59,    60,
      61,    62,    63,    64,     0,     0,     0,     0,    66,    89,
       0,     0,     0,     0,    90,    65,    91,    92,    93,    94,
      95,     0,    88,     0,     0,    89,     0,     0,     0,     0,
      90,    66,    91,    92,    93,    94,    95,    96,    97,    98,
      99,   100,   101,   102,   103,   104,   105,   106,   109,     0,
       0,    89,     0,     0,     0,     0,    90,     0,    91,    92,
      93,    94,    95,    96,    97,    98,    99,   100,   101,   102,
     103,   104,   105,   106,   121,     0,     0,    89,     0,     0,
       0,     0,    90,     0,    91,    92,    93,    94,    95,    96,
      97,    98,    99,   100,   101,   102,   103,   104,   105,   106,
     145,     0,     0,    89,     0,     0,     0,     0,    90,     0,
      91,    92,    93,    94,    95,    96,    97,    98,    99,   100,
     101,   102,   103,   104,   105,   106,    89,   148,     0,     0,
       0,    90,     0,    91,    92,    93,    94,    95,    96,    97,
      98,    99,   100,   101,   102,   103,   104,   105,   106,    89,
     156,     0,     0,     0,    90,     0,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,   103,   104,
     105,   106,    89,     0,     0,     0,     0,    90,     0,    91,
      92,    93,    94,    95,    96,    97,    98,    99,   100,   101,
     102,   103,   104,   105,   106,    89,     0,     0,     0,     0,
      90,     0,    91,    92,    93,    94,    95,    96,    97,    98,
       0,     0,   101,   102,   103,   104,   105,   106
};

static const yytype_int16 yycheck[] =
{
       4,     5,     6,     7,     8,    18,    14,    30,    28,    26,
      14,     5,    28,    33,    18,     9,    24,    33,    12,    13,
      14,    37,    38,    39,    28,    29,    30,    31,    32,    27,
      25,    14,     5,    27,    32,    24,     9,    32,    51,    12,
      13,    14,    25,    51,     5,    34,    14,    51,     9,    72,
      25,    12,    13,    14,    27,    78,    27,    32,    25,    10,
      11,    32,    24,     5,    24,    32,    27,     9,    72,    26,
      12,    13,    14,     5,    78,    31,    80,     9,    82,    83,
      12,    13,    14,     5,    31,    27,    90,     9,    24,    30,
      12,    13,    14,   116,    22,    27,    30,    30,   111,   122,
      30,    30,   115,    51,   108,    27,     5,   111,    24,    26,
       9,   115,   116,    12,    13,    14,     5,    28,   122,    22,
       9,   144,     5,    12,    13,    14,     9,    34,    35,    12,
      13,    14,    26,    26,    26,    26,   159,   150,    27,    46,
     144,    26,   155,    51,    27,   158,   150,    54,   152,    26,
      26,   155,   165,    51,   158,   159,    83,    64,    65,    66,
      -1,   165,   107,    -1,    71,    -1,    28,    -1,    -1,    -1,
      77,    33,    -1,    35,    36,    37,    38,    39,    40,    41,
      42,    -1,    89,    -1,    91,    92,    93,    94,    95,    96,
      97,    98,    99,   100,   101,   102,   103,   104,   105,   106,
      -1,    -1,    -1,    -1,    -1,    -1,   113,    14,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,     0,
      -1,    -1,     3,     4,    -1,     6,     7,     8,    -1,    36,
      14,    15,    16,    17,    18,    19,    20,    21,    22,    23,
      24,    25,    -1,    -1,    -1,    52,    -1,    -1,    -1,    -1,
      -1,    -1,    36,    14,    15,    16,    17,    18,    19,    20,
      21,    22,    23,    24,    -1,    -1,    -1,    -1,    52,    28,
      -1,    -1,    -1,    -1,    33,    36,    35,    36,    37,    38,
      39,    -1,    25,    -1,    -1,    28,    -1,    -1,    -1,    -1,
      33,    52,    35,    36,    37,    38,    39,    40,    41,    42,
      43,    44,    45,    46,    47,    48,    49,    50,    25,    -1,
      -1,    28,    -1,    -1,    -1,    -1,    33,    -1,    35,    36,
      37,    38,    39,    40,    41,    42,    43,    44,    45,    46,
      47,    48,    49,    50,    25,    -1,    -1,    28,    -1,    -1,
      -1,    -1,    33,    -1,    35,    36,    37,    38,    39,    40,
      41,    42,    43,    44,    45,    46,    47,    48,    49,    50,
      25,    -1,    -1,    28,    -1,    -1,    -1,    -1,    33,    -1,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    28,    29,    -1,    -1,
      -1,    33,    -1,    35,    36,    37,    38,    39,    40,    41,
      42,    43,    44,    45,    46,    47,    48,    49,    50,    28,
      29,    -1,    -1,    -1,    33,    -1,    35,    36,    37,    38,
      39,    40,    41,    42,    43,    44,    45,    46,    47,    48,
      49,    50,    28,    -1,    -1,    -1,    -1,    33,    -1,    35,
      36,    37,    38,    39,    40,    41,    42,    43,    44,    45,
      46,    47,    48,    49,    50,    28,    -1,    -1,    -1,    -1,
      33,    -1,    35,    36,    37,    38,    39,    40,    41,    42,
      -1,    -1,    45,    46,    47,    48,    49,    50
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,    54,     0,     3,     4,     6,     7,     8,    26,    14,
      70,    70,    70,    70,     5,     9,    12,    13,    56,    57,
      58,    59,    60,    61,    62,    63,    64,    65,    70,    24,
      26,    31,    31,    70,    24,    24,    27,    57,    30,    30,
      30,    30,    10,    11,    30,    24,    51,    70,    25,    67,
      70,    56,    70,    70,    51,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    36,    52,    66,    69,    70,
      66,    24,    26,    25,    66,    68,    66,    28,    26,    25,
      32,    27,    26,    26,    66,    66,    66,    66,    25,    28,
      33,    35,    36,    37,    38,    39,    40,    41,    42,    43,
      44,    45,    46,    47,    48,    49,    50,    24,    34,    25,
      66,    56,    25,    32,    66,    56,    26,    70,    55,    70,
      55,    25,    26,    66,    70,    66,    66,    66,    66,    66,
      66,    66,    66,    66,    66,    66,    66,    66,    66,    66,
      66,    25,    68,    70,    26,    25,    27,    66,    29,    27,
      56,    27,    32,    51,    27,    56,    29,    25,    56,    26,
      27,    70,    22,    27,    27,    56,    51,    27,    22
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr1[] =
{
       0,    53,    54,    54,    54,    54,    54,    54,    54,    55,
      55,    56,    56,    57,    57,    57,    57,    57,    57,    57,
      57,    58,    58,    59,    60,    61,    61,    62,    62,    63,
      64,    65,    66,    66,    66,    66,    66,    66,    66,    66,
      66,    66,    66,    66,    66,    66,    66,    66,    66,    66,
      66,    66,    66,    66,    66,    66,    66,    66,    66,    67,
      67,    68,    68,    69,    69,    69,    69,    69,    69,    69,
      69,    70
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     0,     5,     8,     9,     6,     8,     8,     3,
       5,     1,     2,     2,     2,     2,     2,     2,     1,     1,
       1,     2,     5,     4,     3,     3,     4,     7,     8,     5,
       7,     1,     1,     1,     1,     3,     3,     4,     3,     4,
       3,     2,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     2,     1,
       3,     1,     3,     1,     1,     1,     1,     1,     1,     1,
       1,     1
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

/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)                                \
    do                                                                  \
      if (N)                                                            \
        {                                                               \
          (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;        \
          (Current).first_column = YYRHSLOC (Rhs, 1).first_column;      \
          (Current).last_line    = YYRHSLOC (Rhs, N).last_line;         \
          (Current).last_column  = YYRHSLOC (Rhs, N).last_column;       \
        }                                                               \
      else                                                              \
        {                                                               \
          (Current).first_line   = (Current).last_line   =              \
            YYRHSLOC (Rhs, 0).last_line;                                \
          (Current).first_column = (Current).last_column =              \
            YYRHSLOC (Rhs, 0).last_column;                              \
        }                                                               \
    while (0)
#endif

#define YYRHSLOC(Rhs, K) ((Rhs)[K])


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


/* YYLOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

# ifndef YYLOCATION_PRINT

#  if defined YY_LOCATION_PRINT

   /* Temporary convenience wrapper in case some people defined the
      undocumented and private YY_LOCATION_PRINT macros.  */
#   define YYLOCATION_PRINT(File, Loc)  YY_LOCATION_PRINT(File, *(Loc))

#  elif defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL

/* Print *YYLOCP on YYO.  Private, do not rely on its existence. */

YY_ATTRIBUTE_UNUSED
static int
yy_location_print_ (FILE *yyo, YYLTYPE const * const yylocp)
{
  int res = 0;
  int end_col = 0 != yylocp->last_column ? yylocp->last_column - 1 : 0;
  if (0 <= yylocp->first_line)
    {
      res += YYFPRINTF (yyo, "%d", yylocp->first_line);
      if (0 <= yylocp->first_column)
        res += YYFPRINTF (yyo, ".%d", yylocp->first_column);
    }
  if (0 <= yylocp->last_line)
    {
      if (yylocp->first_line < yylocp->last_line)
        {
          res += YYFPRINTF (yyo, "-%d", yylocp->last_line);
          if (0 <= end_col)
            res += YYFPRINTF (yyo, ".%d", end_col);
        }
      else if (0 <= end_col && yylocp->first_column < end_col)
        res += YYFPRINTF (yyo, "-%d", end_col);
    }
  return res;
}

#   define YYLOCATION_PRINT  yy_location_print_

    /* Temporary convenience wrapper in case some people defined the
       undocumented and private YY_LOCATION_PRINT macros.  */
#   define YY_LOCATION_PRINT(File, Loc)  YYLOCATION_PRINT(File, &(Loc))

#  else

#   define YYLOCATION_PRINT(File, Loc) ((void) 0)
    /* Temporary convenience wrapper in case some people defined the
       undocumented and private YY_LOCATION_PRINT macros.  */
#   define YY_LOCATION_PRINT  YYLOCATION_PRINT

#  endif
# endif /* !defined YYLOCATION_PRINT */


# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value, Location); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  YY_USE (yylocationp);
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
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  YYLOCATION_PRINT (yyo, yylocationp);
  YYFPRINTF (yyo, ": ");
  yy_symbol_value_print (yyo, yykind, yyvaluep, yylocationp);
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
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp, YYLTYPE *yylsp,
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
                       &yyvsp[(yyi + 1) - (yynrhs)],
                       &(yylsp[(yyi + 1) - (yynrhs)]));
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, yylsp, Rule); \
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
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep, YYLTYPE *yylocationp)
{
  YY_USE (yyvaluep);
  YY_USE (yylocationp);
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
/* Location data for the lookahead symbol.  */
YYLTYPE yylloc
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL
  = { 1, 1, 1, 1 }
# endif
;
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

    /* The location stack: array, bottom, top.  */
    YYLTYPE yylsa[YYINITDEPTH];
    YYLTYPE *yyls = yylsa;
    YYLTYPE *yylsp = yyls;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;
  YYLTYPE yyloc;

  /* The locations where the error started and ended.  */
  YYLTYPE yyerror_range[3];



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N), yylsp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = YYEMPTY; /* Cause a token to be read.  */

  yylsp[0] = yylloc;
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
        YYLTYPE *yyls1 = yyls;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yyls1, yysize * YYSIZEOF (*yylsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
        yyls = yyls1;
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
        YYSTACK_RELOCATE (yyls_alloc, yyls);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;
      yylsp = yyls + yysize - 1;

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
      yyerror_range[1] = yylloc;
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
  *++yylsp = yylloc;

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

  /* Default location. */
  YYLLOC_DEFAULT (yyloc, (yylsp - yylen), yylen);
  yyerror_range[1] = yyloc;
  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 3: /* program: program TPROC TLBRACE stmts TRBRACE  */
#line 75 "parser.y"
                                                    {
                                                        if (g_ctx->proc != NULL)
                                                            // You can only have one proc
                                                            YYABORT;
                                                        g_ctx->proc = Block_new((yyvsp[-1].stmts));
                                                    }
#line 1446 "parser.c"
    break;

  case 4: /* program: program TFN ident TCLBRACE TCRBRACE TLBRACE stmts TRBRACE  */
#line 82 "parser.y"
                                                    {
                                                        map_set(g_ctx->functions, (yyvsp[-5].ident), Function_new((yyvsp[-5].ident), NULL, Block_new((yyvsp[-1].stmts))));
                                                        bhex_free((yyvsp[-5].ident));
                                                    }
#line 1455 "parser.c"
    break;

  case 5: /* program: program TFN ident TCLBRACE name_params TCRBRACE TLBRACE stmts TRBRACE  */
#line 87 "parser.y"
                                                    {
                                                        map_set(g_ctx->functions, (yyvsp[-6].ident), Function_new((yyvsp[-6].ident), (yyvsp[-4].params), Block_new((yyvsp[-1].stmts))));
                                                        bhex_free((yyvsp[-6].ident));
                                                    }
#line 1464 "parser.c"
    break;

  case 6: /* program: program TSTRUCT ident TLBRACE stmts TRBRACE  */
#line 92 "parser.y"
                                                    {
                                                        map_set(g_ctx->structs, (yyvsp[-3].ident), Block_new((yyvsp[-1].stmts)));
                                                        bhex_free((yyvsp[-3].ident));
                                                    }
#line 1473 "parser.c"
    break;

  case 7: /* program: program TENUM ident TCOLON ident TLBRACE enum_list TRBRACE  */
#line 97 "parser.y"
                                                    {
                                                        map_set(g_ctx->enums, (yyvsp[-5].ident), Enum_new((yyvsp[-3].ident), (yyvsp[-1].enum_list), 0));
                                                        bhex_free((yyvsp[-5].ident));
                                                        bhex_free((yyvsp[-3].ident));
                                                    }
#line 1483 "parser.c"
    break;

  case 8: /* program: program TORENUM ident TCOLON ident TLBRACE enum_list TRBRACE  */
#line 103 "parser.y"
                                                    {
                                                        map_set(g_ctx->enums, (yyvsp[-5].ident), Enum_new((yyvsp[-3].ident), (yyvsp[-1].enum_list), 1));
                                                        bhex_free((yyvsp[-5].ident));
                                                        bhex_free((yyvsp[-3].ident));
                                                    }
#line 1493 "parser.c"
    break;

  case 9: /* enum_list: ident TEQUAL TSNUM64  */
#line 110 "parser.y"
                                                    {
                                                        (yyval.enum_list) = DList_new();
                                                        DList_add((yyval.enum_list), EnumEntry_new((yyvsp[-2].ident), yysnumval));
                                                        bhex_free((yyvsp[-2].ident));
                                                    }
#line 1503 "parser.c"
    break;

  case 10: /* enum_list: enum_list TCOMMA ident TEQUAL TSNUM64  */
#line 115 "parser.y"
                                                    {
                                                        DList_add((yyvsp[-4].enum_list), EnumEntry_new((yyvsp[-2].ident), yysnumval));
                                                        bhex_free((yyvsp[-2].ident));
                                                    }
#line 1512 "parser.c"
    break;

  case 11: /* stmts: stmt  */
#line 121 "parser.y"
                                                   {
                                                        (yyval.stmts) = DList_new();
                                                        DList_add((yyval.stmts), (yyvsp[0].stmt));
                                                    }
#line 1521 "parser.c"
    break;

  case 12: /* stmts: stmts stmt  */
#line 125 "parser.y"
                                                    {
                                                        DList_add((yyvsp[-1].stmts), (yyvsp[0].stmt));
                                                    }
#line 1529 "parser.c"
    break;

  case 21: /* fvar_decl: ident ident  */
#line 140 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_FILE_VAR_DECL_new((yyvsp[-1].ident), (yyvsp[0].ident), NULL);
                                                        bhex_free((yyvsp[-1].ident));
                                                        bhex_free((yyvsp[0].ident));
                                                    }
#line 1539 "parser.c"
    break;

  case 22: /* fvar_decl: ident ident SQLBRACE expr SQRBRACE  */
#line 145 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_FILE_VAR_DECL_new((yyvsp[-4].ident), (yyvsp[-3].ident), (yyvsp[-1].expr));
                                                        bhex_free((yyvsp[-4].ident));
                                                        bhex_free((yyvsp[-3].ident));
                                                    }
#line 1549 "parser.c"
    break;

  case 23: /* lvar_decl: TLOCAL ident TEQUAL expr  */
#line 152 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_LOCAL_VAR_DECL_new((yyvsp[-2].ident), (yyvsp[0].expr));
                                                        bhex_free((yyvsp[-2].ident));
                                                    }
#line 1558 "parser.c"
    break;

  case 24: /* lvar_ass: ident TEQUAL expr  */
#line 158 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_LOCAL_VAR_ASS_new((yyvsp[-2].ident), (yyvsp[0].expr));
                                                        bhex_free((yyvsp[-2].ident));
                                                    }
#line 1567 "parser.c"
    break;

  case 25: /* void_fcall: ident TCLBRACE TCRBRACE  */
#line 164 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_VOID_FUNC_CALL_new((yyvsp[-2].ident), NULL);
                                                        bhex_free((yyvsp[-2].ident));
                                                    }
#line 1576 "parser.c"
    break;

  case 26: /* void_fcall: ident TCLBRACE params TCRBRACE  */
#line 168 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_VOID_FUNC_CALL_new((yyvsp[-3].ident), (yyvsp[-1].params));
                                                        bhex_free((yyvsp[-3].ident));
                                                    }
#line 1585 "parser.c"
    break;

  case 27: /* if_elif: TIF TCLBRACE expr TCRBRACE TLBRACE stmts TRBRACE  */
#line 175 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_STMT_IF_new((yyvsp[-4].expr), Block_new((yyvsp[-1].stmts)));
                                                    }
#line 1593 "parser.c"
    break;

  case 28: /* if_elif: if_elif TELIF TCLBRACE expr TCRBRACE TLBRACE stmts TRBRACE  */
#line 179 "parser.y"
                                                    {
                                                        Stmt_STMT_IF_add_cond((yyvsp[-7].stmt), (yyvsp[-4].expr), Block_new((yyvsp[-1].stmts)));
                                                        (yyval.stmt) = (yyvsp[-7].stmt);
                                                    }
#line 1602 "parser.c"
    break;

  case 29: /* else: if_elif TELSE TLBRACE stmts TRBRACE  */
#line 186 "parser.y"
                                                    {
                                                        Stmt_STMT_IF_add_else((yyvsp[-4].stmt), Block_new((yyvsp[-1].stmts)));
                                                        (yyval.stmt) = (yyvsp[-4].stmt);
                                                    }
#line 1611 "parser.c"
    break;

  case 30: /* while: TWHILE TCLBRACE expr TCRBRACE TLBRACE stmts TRBRACE  */
#line 193 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_WHILE_new((yyvsp[-4].expr), Block_new((yyvsp[-1].stmts)));
                                                    }
#line 1619 "parser.c"
    break;

  case 31: /* break: TBREAK  */
#line 198 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_BREAK_new();
                                                    }
#line 1627 "parser.c"
    break;

  case 33: /* expr: TSTR  */
#line 204 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_STRING_new(yyheapbuf, yyheapbuf_len);
                                                    }
#line 1635 "parser.c"
    break;

  case 34: /* expr: ident  */
#line 207 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_VAR_new((yyvsp[0].ident));
                                                        bhex_free((yyvsp[0].ident));
                                                    }
#line 1644 "parser.c"
    break;

  case 35: /* expr: ident TCOLCOL ident  */
#line 211 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_ENUM_CONST_new((yyvsp[-2].ident), (yyvsp[0].ident));
                                                        bhex_free((yyvsp[-2].ident));
                                                        bhex_free((yyvsp[0].ident));
                                                    }
#line 1654 "parser.c"
    break;

  case 36: /* expr: expr TDOT ident  */
#line 216 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SUBSCR_new((yyvsp[-2].expr), (yyvsp[0].ident));
                                                        bhex_free((yyvsp[0].ident));
                                                    }
#line 1663 "parser.c"
    break;

  case 37: /* expr: expr SQLBRACE expr SQRBRACE  */
#line 220 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_ARRAY_SUB_new((yyvsp[-3].expr), (yyvsp[-1].expr));
                                                    }
#line 1671 "parser.c"
    break;

  case 38: /* expr: ident TCLBRACE TCRBRACE  */
#line 223 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_FUN_CALL_new((yyvsp[-2].ident), NULL);
                                                        bhex_free((yyvsp[-2].ident));
                                                    }
#line 1680 "parser.c"
    break;

  case 39: /* expr: ident TCLBRACE params TCRBRACE  */
#line 227 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_FUN_CALL_new((yyvsp[-3].ident), (yyvsp[-1].params));
                                                        bhex_free((yyvsp[-3].ident));
                                                    }
#line 1689 "parser.c"
    break;

  case 40: /* expr: TCLBRACE expr TCRBRACE  */
#line 231 "parser.y"
                                                    {
                                                        (yyval.expr) = (yyvsp[-1].expr);
                                                    }
#line 1697 "parser.c"
    break;

  case 41: /* expr: TSUB expr  */
#line 234 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SUB_new(Expr_SCONST_new(0, 1), (yyvsp[0].expr));
                                                    }
#line 1705 "parser.c"
    break;

  case 42: /* expr: expr TAND expr  */
#line 237 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_AND_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1713 "parser.c"
    break;

  case 43: /* expr: expr TOR expr  */
#line 240 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_OR_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1721 "parser.c"
    break;

  case 44: /* expr: expr TXOR expr  */
#line 243 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_XOR_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1729 "parser.c"
    break;

  case 45: /* expr: expr TADD expr  */
#line 246 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_ADD_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1737 "parser.c"
    break;

  case 46: /* expr: expr TSUB expr  */
#line 249 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SUB_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1745 "parser.c"
    break;

  case 47: /* expr: expr TMUL expr  */
#line 252 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_MUL_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1753 "parser.c"
    break;

  case 48: /* expr: expr TDIV expr  */
#line 255 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_DIV_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1761 "parser.c"
    break;

  case 49: /* expr: expr TMOD expr  */
#line 258 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_MOD_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1769 "parser.c"
    break;

  case 50: /* expr: expr TBEQ expr  */
#line 261 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BEQ_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1777 "parser.c"
    break;

  case 51: /* expr: expr TBNEQ expr  */
#line 264 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BNOT_new(Expr_BEQ_new((yyvsp[-2].expr), (yyvsp[0].expr)));
                                                    }
#line 1785 "parser.c"
    break;

  case 52: /* expr: expr TBLT expr  */
#line 267 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BLT_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1793 "parser.c"
    break;

  case 53: /* expr: expr TBLE expr  */
#line 270 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BLE_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1801 "parser.c"
    break;

  case 54: /* expr: expr TBGT expr  */
#line 273 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BGT_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1809 "parser.c"
    break;

  case 55: /* expr: expr TBGE expr  */
#line 276 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BGE_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1817 "parser.c"
    break;

  case 56: /* expr: expr TBAND expr  */
#line 279 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BAND_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1825 "parser.c"
    break;

  case 57: /* expr: expr TBOR expr  */
#line 282 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BOR_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 1833 "parser.c"
    break;

  case 58: /* expr: TBNOT expr  */
#line 285 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BNOT_new((yyvsp[0].expr));
                                                    }
#line 1841 "parser.c"
    break;

  case 59: /* name_params: ident  */
#line 290 "parser.y"
                                                    {
                                                        (yyval.params) = DList_new();
                                                        DList_add((yyval.params), (yyvsp[0].ident));
                                                    }
#line 1850 "parser.c"
    break;

  case 60: /* name_params: name_params TCOMMA ident  */
#line 294 "parser.y"
                                                    {
                                                        DList_add((yyval.params), (yyvsp[0].ident));
                                                    }
#line 1858 "parser.c"
    break;

  case 61: /* params: expr  */
#line 298 "parser.y"
                                                    {
                                                        (yyval.params) = DList_new();
                                                        DList_add((yyval.params), (yyvsp[0].expr));
                                                    }
#line 1867 "parser.c"
    break;

  case 62: /* params: params TCOMMA expr  */
#line 302 "parser.y"
                                                    {
                                                        DList_add((yyval.params), (yyvsp[0].expr));
                                                    }
#line 1875 "parser.c"
    break;

  case 63: /* num: TUNUM8  */
#line 307 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_UCONST_new(yyunumval, 1);
                                                    }
#line 1883 "parser.c"
    break;

  case 64: /* num: TUNUM16  */
#line 310 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_UCONST_new(yyunumval, 2);
                                                    }
#line 1891 "parser.c"
    break;

  case 65: /* num: TUNUM32  */
#line 313 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_UCONST_new(yyunumval, 4);
                                                    }
#line 1899 "parser.c"
    break;

  case 66: /* num: TUNUM64  */
#line 316 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_UCONST_new(yyunumval, 8);
                                                    }
#line 1907 "parser.c"
    break;

  case 67: /* num: TSNUM8  */
#line 319 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SCONST_new(yysnumval, 1);
                                                    }
#line 1915 "parser.c"
    break;

  case 68: /* num: TSNUM16  */
#line 322 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SCONST_new(yysnumval, 2);
                                                    }
#line 1923 "parser.c"
    break;

  case 69: /* num: TSNUM32  */
#line 325 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SCONST_new(yysnumval, 4);
                                                    }
#line 1931 "parser.c"
    break;

  case 70: /* num: TSNUM64  */
#line 328 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SCONST_new(yysnumval, 8);
                                                    }
#line 1939 "parser.c"
    break;

  case 71: /* ident: TIDENTIFIER  */
#line 333 "parser.y"
                                                    {
                                                        (yyval.ident) = bhex_strdup(yystrval);
                                                    }
#line 1947 "parser.c"
    break;


#line 1951 "parser.c"

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
  *++yylsp = yyloc;

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

  yyerror_range[1] = yylloc;
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
                      yytoken, &yylval, &yylloc);
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

      yyerror_range[1] = *yylsp;
      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp, yylsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  yyerror_range[2] = yylloc;
  ++yylsp;
  YYLLOC_DEFAULT (*yylsp, yyerror_range, 2);

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
                  yytoken, &yylval, &yylloc);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp, yylsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif

  return yyresult;
}

#line 338 "parser.y"

