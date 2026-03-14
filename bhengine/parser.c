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

// Copyright (c) 2022-2026, bageyelet

#include <stdio.h>

#include <strbuilder.h>
#include <util/str.h>
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
    while ((line = _strsep(&curr, "\n")) != NULL) {
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


#line 171 "parser.c"

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
  YYSYMBOL_TCONTINUE = 14,                 /* TCONTINUE  */
  YYSYMBOL_TRETURN = 15,                   /* TRETURN  */
  YYSYMBOL_TIDENTIFIER = 16,               /* TIDENTIFIER  */
  YYSYMBOL_TUNUM8 = 17,                    /* TUNUM8  */
  YYSYMBOL_TUNUM16 = 18,                   /* TUNUM16  */
  YYSYMBOL_TUNUM32 = 19,                   /* TUNUM32  */
  YYSYMBOL_TUNUM64 = 20,                   /* TUNUM64  */
  YYSYMBOL_TSNUM8 = 21,                    /* TSNUM8  */
  YYSYMBOL_TSNUM16 = 22,                   /* TSNUM16  */
  YYSYMBOL_TSNUM32 = 23,                   /* TSNUM32  */
  YYSYMBOL_TSNUM64 = 24,                   /* TSNUM64  */
  YYSYMBOL_TSTR = 25,                      /* TSTR  */
  YYSYMBOL_TCLBRACE = 26,                  /* TCLBRACE  */
  YYSYMBOL_TCRBRACE = 27,                  /* TCRBRACE  */
  YYSYMBOL_TLBRACE = 28,                   /* TLBRACE  */
  YYSYMBOL_TRBRACE = 29,                   /* TRBRACE  */
  YYSYMBOL_SQLBRACE = 30,                  /* SQLBRACE  */
  YYSYMBOL_SQRBRACE = 31,                  /* SQRBRACE  */
  YYSYMBOL_TSEMICOLON = 32,                /* TSEMICOLON  */
  YYSYMBOL_TCOLON = 33,                    /* TCOLON  */
  YYSYMBOL_TCOMMA = 34,                    /* TCOMMA  */
  YYSYMBOL_TDOT = 35,                      /* TDOT  */
  YYSYMBOL_TCOLCOL = 36,                   /* TCOLCOL  */
  YYSYMBOL_THASHTAG = 37,                  /* THASHTAG  */
  YYSYMBOL_TADD = 38,                      /* TADD  */
  YYSYMBOL_TSUB = 39,                      /* TSUB  */
  YYSYMBOL_TMUL = 40,                      /* TMUL  */
  YYSYMBOL_TDIV = 41,                      /* TDIV  */
  YYSYMBOL_TMOD = 42,                      /* TMOD  */
  YYSYMBOL_TAND = 43,                      /* TAND  */
  YYSYMBOL_TOR = 44,                       /* TOR  */
  YYSYMBOL_TXOR = 45,                      /* TXOR  */
  YYSYMBOL_TBAND = 46,                     /* TBAND  */
  YYSYMBOL_TBOR = 47,                      /* TBOR  */
  YYSYMBOL_TBEQ = 48,                      /* TBEQ  */
  YYSYMBOL_TBNEQ = 49,                     /* TBNEQ  */
  YYSYMBOL_TBGT = 50,                      /* TBGT  */
  YYSYMBOL_TBGE = 51,                      /* TBGE  */
  YYSYMBOL_TBLT = 52,                      /* TBLT  */
  YYSYMBOL_TBLE = 53,                      /* TBLE  */
  YYSYMBOL_TEQUAL = 54,                    /* TEQUAL  */
  YYSYMBOL_TBNOT = 55,                     /* TBNOT  */
  YYSYMBOL_TSHL = 56,                      /* TSHL  */
  YYSYMBOL_TSHR = 57,                      /* TSHR  */
  YYSYMBOL_YYACCEPT = 58,                  /* $accept  */
  YYSYMBOL_program = 59,                   /* program  */
  YYSYMBOL_enum_list = 60,                 /* enum_list  */
  YYSYMBOL_stmts = 61,                     /* stmts  */
  YYSYMBOL_stmt = 62,                      /* stmt  */
  YYSYMBOL_fvar_type = 63,                 /* fvar_type  */
  YYSYMBOL_fvar_decl = 64,                 /* fvar_decl  */
  YYSYMBOL_lvar_decl = 65,                 /* lvar_decl  */
  YYSYMBOL_lvar_ass = 66,                  /* lvar_ass  */
  YYSYMBOL_void_fcall = 67,                /* void_fcall  */
  YYSYMBOL_if_elif = 68,                   /* if_elif  */
  YYSYMBOL_else = 69,                      /* else  */
  YYSYMBOL_while = 70,                     /* while  */
  YYSYMBOL_break = 71,                     /* break  */
  YYSYMBOL_continue = 72,                  /* continue  */
  YYSYMBOL_return = 73,                    /* return  */
  YYSYMBOL_expr = 74,                      /* expr  */
  YYSYMBOL_name_params = 75,               /* name_params  */
  YYSYMBOL_params = 76,                    /* params  */
  YYSYMBOL_num = 77,                       /* num  */
  YYSYMBOL_ident = 78                      /* ident  */
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

#if 1

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
#endif /* 1 */

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
#define YYLAST   677

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  58
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  21
/* YYNRULES -- Number of rules.  */
#define YYNRULES  83
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  189

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   312


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
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57
};

#if YYDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   145,   145,   146,   152,   157,   162,   167,   172,   178,
     186,   191,   197,   201,   206,   207,   208,   209,   210,   211,
     212,   213,   214,   215,   218,   222,   230,   239,   247,   254,
     261,   266,   273,   278,   283,   288,   295,   300,   305,   312,
     318,   324,   330,   331,   334,   338,   343,   347,   350,   354,
     358,   361,   364,   367,   370,   373,   376,   379,   382,   385,
     388,   391,   394,   397,   400,   403,   406,   409,   412,   415,
     418,   423,   427,   431,   435,   440,   443,   446,   449,   452,
     455,   458,   461,   466
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if 1
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  static const char *const yy_sname[] =
  {
  "end of file", "error", "invalid token", "TPROC", "TFN", "TLOCAL",
  "TSTRUCT", "TENUM", "TORENUM", "TIF", "TELIF", "TELSE", "TWHILE",
  "TBREAK", "TCONTINUE", "TRETURN", "TIDENTIFIER", "TUNUM8", "TUNUM16",
  "TUNUM32", "TUNUM64", "TSNUM8", "TSNUM16", "TSNUM32", "TSNUM64", "TSTR",
  "TCLBRACE", "TCRBRACE", "TLBRACE", "TRBRACE", "SQLBRACE", "SQRBRACE",
  "TSEMICOLON", "TCOLON", "TCOMMA", "TDOT", "TCOLCOL", "THASHTAG", "TADD",
  "TSUB", "TMUL", "TDIV", "TMOD", "TAND", "TOR", "TXOR", "TBAND", "TBOR",
  "TBEQ", "TBNEQ", "TBGT", "TBGE", "TBLT", "TBLE", "TEQUAL", "TBNOT",
  "TSHL", "TSHR", "$accept", "program", "enum_list", "stmts", "stmt",
  "fvar_type", "fvar_decl", "lvar_decl", "lvar_ass", "void_fcall",
  "if_elif", "else", "while", "break", "continue", "return", "expr",
  "name_params", "params", "num", "ident", YY_NULLPTR
  };
  return yy_sname[yysymbol];
}
#endif

#define YYPACT_NINF (-29)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-1)

#define yytable_value_is_error(Yyn) \
  0

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     -29,    76,   -29,    21,    -1,    -1,    -1,    -1,   -29,   178,
      11,    15,    23,    10,    25,    -1,    51,    59,   -29,   -29,
     -29,   486,   -29,    -1,    22,    62,    63,    64,     3,   -29,
     -29,    66,    69,    79,    24,   178,    -8,   178,    -1,    -1,
      35,     5,     5,   -29,   -29,    83,   -29,   -29,   -29,   -29,
      73,    86,   -29,   -29,   -29,    48,    -1,     5,   498,    88,
     -17,   -29,   516,    89,    90,     5,   -29,   -29,   -29,   -29,
     -29,   -29,   -29,   -29,   -29,     5,     5,     5,   236,   -29,
      12,   264,     5,     5,   528,   -29,   392,    13,   -29,   392,
     -29,   178,    94,    -1,   -29,    -1,    -1,   392,   292,    91,
     -19,    99,     5,    -1,     5,     5,     5,     5,     5,     5,
       5,     5,     5,     5,     5,     5,     5,     5,     5,     5,
       5,     5,   218,    -1,   102,   344,   320,   -29,   546,   -29,
       5,   558,   178,   -29,    28,    65,    57,   -29,   576,   368,
     -29,    91,    91,   -19,   -19,   -19,    67,    67,    67,   416,
     416,   440,   440,   440,   440,   440,   440,   -19,   -19,   -29,
      18,   -29,   178,   -29,   108,   -29,   392,   -29,   588,   -29,
      -1,   113,   -29,   -29,   606,   -29,   -29,   618,   636,   -29,
      84,   -29,   -29,   -29,   -29,   648,   115,   -29,   -29
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_int8 yydefact[] =
{
       2,     0,     1,     0,     0,     0,     0,     0,    83,     0,
       0,     0,     0,     0,     0,     0,     0,     0,    39,    40,
      41,     0,    12,     0,     0,     0,     0,     0,    21,    22,
      23,     0,     0,     0,    24,     0,     0,     0,     0,     0,
       0,     0,     0,     3,    13,    26,    14,    15,    16,    17,
       0,     0,    18,    19,    20,     0,     0,     0,     0,     0,
       0,    71,     0,     0,     0,     0,    75,    76,    77,    78,
      79,    80,    81,    82,    43,     0,     0,     0,     0,    42,
      44,     0,     0,     0,     0,    30,    73,     0,    25,    29,
       4,     0,     0,     0,     7,     0,     0,    28,     0,    51,
      70,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    37,     0,    31,
       0,     0,     0,    72,     0,     0,     0,    50,     0,     0,
      46,    55,    56,    57,    58,    59,    52,    53,    54,    66,
      67,    60,    61,    64,    65,    62,    63,    69,    68,    48,
       0,    45,     0,    27,     0,    36,    74,     5,     0,     8,
       0,     0,     9,    33,     0,    47,    49,     0,     0,     6,
       0,    10,    32,    38,    35,     0,     0,    34,    11
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -29,   -29,    44,   -28,   -16,   -29,   -29,   -29,   -29,   -29,
     -29,   -29,   -29,   -29,   -29,   -29,   103,   -29,    19,   -29,
      -3
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_uint8 yydefgoto[] =
{
       0,     1,   134,    21,    22,    23,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    86,    60,    87,    79,
      80
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_uint8 yytable[] =
{
      10,    11,    12,    13,    14,    44,    34,    58,     8,    62,
      92,   102,    40,    50,    51,     8,   103,    93,    34,    59,
      45,     8,    66,    67,    68,    69,    70,    71,    72,    73,
      74,    75,    34,    61,    34,    63,    64,     8,   122,    35,
     129,    36,    44,    38,    76,   176,    44,   130,   123,     9,
      55,    37,   130,    88,    46,    34,   128,   169,    39,    34,
      77,    56,   170,   131,     8,    66,    67,    68,    69,    70,
      71,    72,    73,    74,    75,    85,     2,    41,    57,     3,
       4,    34,     5,     6,     7,    42,   172,    76,    34,    65,
     133,   170,   135,   135,    47,    48,    49,   102,    52,    83,
     140,    53,   103,    77,   168,   104,   105,   106,   107,   108,
     174,    54,    44,    82,    84,    44,    91,    95,    96,   171,
     161,   102,   132,   120,   121,    34,   103,   138,    34,    34,
     162,   106,   107,   108,   177,    34,   178,   181,   186,   188,
     136,   160,     0,     0,    78,    81,     0,   120,   121,     0,
     185,     0,    44,     0,     0,     0,     0,     0,    44,    34,
      89,    44,     0,     0,     0,    34,     0,   180,    97,    44,
       0,    34,     0,     0,    34,    34,     0,     0,    98,    99,
     100,     0,    34,    15,     0,   125,   126,    16,     0,     0,
      17,    18,    19,    20,     8,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   139,     0,   141,   142,   143,
     144,   145,   146,   147,   148,   149,   150,   151,   152,   153,
     154,   155,   156,   157,   158,     0,     0,     0,     0,     0,
       0,     0,     0,   166,     8,    66,    67,    68,    69,    70,
      71,    72,    73,    74,    75,   159,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    76,     0,     0,
       0,     0,     0,   101,     0,     0,   102,     0,     0,     0,
       0,   103,     0,    77,   104,   105,   106,   107,   108,   109,
     110,   111,   112,   113,   114,   115,   116,   117,   118,   119,
       0,   124,   120,   121,   102,     0,     0,     0,     0,   103,
       0,     0,   104,   105,   106,   107,   108,   109,   110,   111,
     112,   113,   114,   115,   116,   117,   118,   119,     0,   137,
     120,   121,   102,     0,     0,     0,     0,   103,     0,     0,
     104,   105,   106,   107,   108,   109,   110,   111,   112,   113,
     114,   115,   116,   117,   118,   119,     0,   164,   120,   121,
     102,     0,     0,     0,     0,   103,     0,     0,   104,   105,
     106,   107,   108,   109,   110,   111,   112,   113,   114,   115,
     116,   117,   118,   119,   102,   163,   120,   121,     0,   103,
       0,     0,   104,   105,   106,   107,   108,   109,   110,   111,
     112,   113,   114,   115,   116,   117,   118,   119,   102,   175,
     120,   121,     0,   103,     0,     0,   104,   105,   106,   107,
     108,   109,   110,   111,   112,   113,   114,   115,   116,   117,
     118,   119,   102,     0,   120,   121,     0,   103,     0,     0,
     104,   105,   106,   107,   108,   109,   110,   111,   112,   113,
     114,   115,   116,   117,   118,   119,   102,     0,   120,   121,
       0,   103,     0,     0,   104,   105,   106,   107,   108,   109,
     110,   111,     0,     0,   114,   115,   116,   117,   118,   119,
     102,     0,   120,   121,     0,   103,     0,     0,   104,   105,
     106,   107,   108,   109,   110,   111,     0,     0,     0,     0,
       0,    15,     0,     0,     0,    16,   120,   121,    17,    18,
      19,    20,     8,    15,     0,     0,     0,    16,     0,     0,
      17,    18,    19,    20,     8,    43,     0,     0,     0,     0,
       0,    15,     0,     0,     0,    16,     0,    90,    17,    18,
      19,    20,     8,    15,     0,     0,     0,    16,     0,     0,
      17,    18,    19,    20,     8,    94,     0,     0,     0,     0,
       0,    15,     0,     0,     0,    16,     0,   127,    17,    18,
      19,    20,     8,    15,     0,     0,     0,    16,     0,     0,
      17,    18,    19,    20,     8,   165,     0,     0,     0,     0,
       0,    15,     0,     0,     0,    16,     0,   167,    17,    18,
      19,    20,     8,    15,     0,     0,     0,    16,     0,     0,
      17,    18,    19,    20,     8,   173,     0,     0,     0,     0,
       0,    15,     0,     0,     0,    16,     0,   179,    17,    18,
      19,    20,     8,    15,     0,     0,     0,    16,     0,     0,
      17,    18,    19,    20,     8,   182,     0,     0,     0,     0,
       0,    15,     0,     0,     0,    16,     0,   183,    17,    18,
      19,    20,     8,    15,     0,     0,     0,    16,     0,     0,
      17,    18,    19,    20,     8,   184,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   187
};

static const yytype_int16 yycheck[] =
{
       3,     4,     5,     6,     7,    21,     9,    35,    16,    37,
      27,    30,    15,    10,    11,    16,    35,    34,    21,    27,
      23,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    35,    36,    37,    38,    39,    16,    26,    28,
      27,    26,    58,    33,    39,    27,    62,    34,    36,    28,
      26,    28,    34,    56,    32,    58,    84,    29,    33,    62,
      55,    37,    34,    91,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,     0,    26,    54,     3,
       4,    84,     6,     7,     8,    26,    29,    39,    91,    54,
      93,    34,    95,    96,    32,    32,    32,    30,    32,    26,
     103,    32,    35,    55,   132,    38,    39,    40,    41,    42,
     138,    32,   128,    30,    28,   131,    28,    28,    28,    54,
     123,    30,    28,    56,    57,   128,    35,    28,   131,   132,
      28,    40,    41,    42,   162,   138,    28,    24,    54,    24,
      96,   122,    -1,    -1,    41,    42,    -1,    56,    57,    -1,
     178,    -1,   168,    -1,    -1,    -1,    -1,    -1,   174,   162,
      57,   177,    -1,    -1,    -1,   168,    -1,   170,    65,   185,
      -1,   174,    -1,    -1,   177,   178,    -1,    -1,    75,    76,
      77,    -1,   185,     5,    -1,    82,    83,     9,    -1,    -1,
      12,    13,    14,    15,    16,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   102,    -1,   104,   105,   106,
     107,   108,   109,   110,   111,   112,   113,   114,   115,   116,
     117,   118,   119,   120,   121,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   130,    16,    17,    18,    19,    20,    21,
      22,    23,    24,    25,    26,    27,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    39,    -1,    -1,
      -1,    -1,    -1,    27,    -1,    -1,    30,    -1,    -1,    -1,
      -1,    35,    -1,    55,    38,    39,    40,    41,    42,    43,
      44,    45,    46,    47,    48,    49,    50,    51,    52,    53,
      -1,    27,    56,    57,    30,    -1,    -1,    -1,    -1,    35,
      -1,    -1,    38,    39,    40,    41,    42,    43,    44,    45,
      46,    47,    48,    49,    50,    51,    52,    53,    -1,    27,
      56,    57,    30,    -1,    -1,    -1,    -1,    35,    -1,    -1,
      38,    39,    40,    41,    42,    43,    44,    45,    46,    47,
      48,    49,    50,    51,    52,    53,    -1,    27,    56,    57,
      30,    -1,    -1,    -1,    -1,    35,    -1,    -1,    38,    39,
      40,    41,    42,    43,    44,    45,    46,    47,    48,    49,
      50,    51,    52,    53,    30,    31,    56,    57,    -1,    35,
      -1,    -1,    38,    39,    40,    41,    42,    43,    44,    45,
      46,    47,    48,    49,    50,    51,    52,    53,    30,    31,
      56,    57,    -1,    35,    -1,    -1,    38,    39,    40,    41,
      42,    43,    44,    45,    46,    47,    48,    49,    50,    51,
      52,    53,    30,    -1,    56,    57,    -1,    35,    -1,    -1,
      38,    39,    40,    41,    42,    43,    44,    45,    46,    47,
      48,    49,    50,    51,    52,    53,    30,    -1,    56,    57,
      -1,    35,    -1,    -1,    38,    39,    40,    41,    42,    43,
      44,    45,    -1,    -1,    48,    49,    50,    51,    52,    53,
      30,    -1,    56,    57,    -1,    35,    -1,    -1,    38,    39,
      40,    41,    42,    43,    44,    45,    -1,    -1,    -1,    -1,
      -1,     5,    -1,    -1,    -1,     9,    56,    57,    12,    13,
      14,    15,    16,     5,    -1,    -1,    -1,     9,    -1,    -1,
      12,    13,    14,    15,    16,    29,    -1,    -1,    -1,    -1,
      -1,     5,    -1,    -1,    -1,     9,    -1,    29,    12,    13,
      14,    15,    16,     5,    -1,    -1,    -1,     9,    -1,    -1,
      12,    13,    14,    15,    16,    29,    -1,    -1,    -1,    -1,
      -1,     5,    -1,    -1,    -1,     9,    -1,    29,    12,    13,
      14,    15,    16,     5,    -1,    -1,    -1,     9,    -1,    -1,
      12,    13,    14,    15,    16,    29,    -1,    -1,    -1,    -1,
      -1,     5,    -1,    -1,    -1,     9,    -1,    29,    12,    13,
      14,    15,    16,     5,    -1,    -1,    -1,     9,    -1,    -1,
      12,    13,    14,    15,    16,    29,    -1,    -1,    -1,    -1,
      -1,     5,    -1,    -1,    -1,     9,    -1,    29,    12,    13,
      14,    15,    16,     5,    -1,    -1,    -1,     9,    -1,    -1,
      12,    13,    14,    15,    16,    29,    -1,    -1,    -1,    -1,
      -1,     5,    -1,    -1,    -1,     9,    -1,    29,    12,    13,
      14,    15,    16,     5,    -1,    -1,    -1,     9,    -1,    -1,
      12,    13,    14,    15,    16,    29,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    29
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,    59,     0,     3,     4,     6,     7,     8,    16,    28,
      78,    78,    78,    78,    78,     5,     9,    12,    13,    14,
      15,    61,    62,    63,    64,    65,    66,    67,    68,    69,
      70,    71,    72,    73,    78,    28,    26,    28,    33,    33,
      78,    26,    26,    29,    62,    78,    32,    32,    32,    32,
      10,    11,    32,    32,    32,    26,    37,    54,    61,    27,
      75,    78,    61,    78,    78,    54,    17,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    39,    55,    74,    77,
      78,    74,    30,    26,    28,    27,    74,    76,    78,    74,
      29,    28,    27,    34,    29,    28,    28,    74,    74,    74,
      74,    27,    30,    35,    38,    39,    40,    41,    42,    43,
      44,    45,    46,    47,    48,    49,    50,    51,    52,    53,
      56,    57,    26,    36,    27,    74,    74,    29,    61,    27,
      34,    61,    28,    78,    60,    78,    60,    27,    28,    74,
      78,    74,    74,    74,    74,    74,    74,    74,    74,    74,
      74,    74,    74,    74,    74,    74,    74,    74,    74,    27,
      76,    78,    28,    31,    27,    29,    74,    29,    61,    29,
      34,    54,    29,    29,    61,    31,    27,    61,    28,    29,
      78,    24,    29,    29,    29,    61,    54,    29,    24
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr1[] =
{
       0,    58,    59,    59,    59,    59,    59,    59,    59,    59,
      60,    60,    61,    61,    62,    62,    62,    62,    62,    62,
      62,    62,    62,    62,    63,    63,    64,    64,    65,    66,
      67,    67,    68,    68,    68,    68,    69,    69,    70,    71,
      72,    73,    74,    74,    74,    74,    74,    74,    74,    74,
      74,    74,    74,    74,    74,    74,    74,    74,    74,    74,
      74,    74,    74,    74,    74,    74,    74,    74,    74,    74,
      74,    75,    75,    76,    76,    77,    77,    77,    77,    77,
      77,    77,    77,    78
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     0,     5,     6,     8,     9,     6,     8,     8,
       3,     5,     1,     2,     2,     2,     2,     2,     2,     2,
       2,     1,     1,     1,     1,     3,     2,     5,     4,     3,
       3,     4,     7,     6,     8,     7,     5,     4,     7,     1,
       1,     1,     1,     1,     1,     3,     3,     4,     3,     4,
       3,     2,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       2,     1,     3,     1,     3,     1,     1,     1,     1,     1,
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


/* Context of a parse error.  */
typedef struct
{
  yy_state_t *yyssp;
  yysymbol_kind_t yytoken;
  YYLTYPE *yylloc;
} yypcontext_t;

/* Put in YYARG at most YYARGN of the expected tokens given the
   current YYCTX, and return the number of tokens stored in YYARG.  If
   YYARG is null, return the number of expected tokens (guaranteed to
   be less than YYNTOKENS).  Return YYENOMEM on memory exhaustion.
   Return 0 if there are more than YYARGN expected tokens, yet fill
   YYARG up to YYARGN. */
static int
yypcontext_expected_tokens (const yypcontext_t *yyctx,
                            yysymbol_kind_t yyarg[], int yyargn)
{
  /* Actual size of YYARG. */
  int yycount = 0;
  int yyn = yypact[+*yyctx->yyssp];
  if (!yypact_value_is_default (yyn))
    {
      /* Start YYX at -YYN if negative to avoid negative indexes in
         YYCHECK.  In other words, skip the first -YYN actions for
         this state because they are default actions.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;
      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yyx;
      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
        if (yycheck[yyx + yyn] == yyx && yyx != YYSYMBOL_YYerror
            && !yytable_value_is_error (yytable[yyx + yyn]))
          {
            if (!yyarg)
              ++yycount;
            else if (yycount == yyargn)
              return 0;
            else
              yyarg[yycount++] = YY_CAST (yysymbol_kind_t, yyx);
          }
    }
  if (yyarg && yycount == 0 && 0 < yyargn)
    yyarg[0] = YYSYMBOL_YYEMPTY;
  return yycount;
}




#ifndef yystrlen
# if defined __GLIBC__ && defined _STRING_H
#  define yystrlen(S) (YY_CAST (YYPTRDIFF_T, strlen (S)))
# else
/* Return the length of YYSTR.  */
static YYPTRDIFF_T
yystrlen (const char *yystr)
{
  YYPTRDIFF_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
# endif
#endif

#ifndef yystpcpy
# if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#  define yystpcpy stpcpy
# else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
# endif
#endif



static int
yy_syntax_error_arguments (const yypcontext_t *yyctx,
                           yysymbol_kind_t yyarg[], int yyargn)
{
  /* Actual size of YYARG. */
  int yycount = 0;
  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yyctx->yytoken != YYSYMBOL_YYEMPTY)
    {
      int yyn;
      if (yyarg)
        yyarg[yycount] = yyctx->yytoken;
      ++yycount;
      yyn = yypcontext_expected_tokens (yyctx,
                                        yyarg ? yyarg + 1 : yyarg, yyargn - 1);
      if (yyn == YYENOMEM)
        return YYENOMEM;
      else
        yycount += yyn;
    }
  return yycount;
}

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return -1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return YYENOMEM if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYPTRDIFF_T *yymsg_alloc, char **yymsg,
                const yypcontext_t *yyctx)
{
  enum { YYARGS_MAX = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat: reported tokens (one for the "unexpected",
     one per "expected"). */
  yysymbol_kind_t yyarg[YYARGS_MAX];
  /* Cumulated lengths of YYARG.  */
  YYPTRDIFF_T yysize = 0;

  /* Actual size of YYARG. */
  int yycount = yy_syntax_error_arguments (yyctx, yyarg, YYARGS_MAX);
  if (yycount == YYENOMEM)
    return YYENOMEM;

  switch (yycount)
    {
#define YYCASE_(N, S)                       \
      case N:                               \
        yyformat = S;                       \
        break
    default: /* Avoid compiler warnings. */
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
#undef YYCASE_
    }

  /* Compute error message size.  Don't count the "%s"s, but reserve
     room for the terminator.  */
  yysize = yystrlen (yyformat) - 2 * yycount + 1;
  {
    int yyi;
    for (yyi = 0; yyi < yycount; ++yyi)
      {
        YYPTRDIFF_T yysize1
          = yysize + yystrlen (yysymbol_name (yyarg[yyi]));
        if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
          yysize = yysize1;
        else
          return YYENOMEM;
      }
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return -1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp = yystpcpy (yyp, yysymbol_name (yyarg[yyi++]));
          yyformat += 2;
        }
      else
        {
          ++yyp;
          ++yyformat;
        }
  }
  return 0;
}


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

  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYPTRDIFF_T yymsg_alloc = sizeof yymsgbuf;

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
#line 146 "parser.y"
                                                    {
                                                        if (g_ctx->proc != NULL)
                                                            // You can only have one proc
                                                            YYABORT;
                                                        g_ctx->proc = Block_new((yyvsp[-1].stmts));
                                                    }
#line 1794 "parser.c"
    break;

  case 4: /* program: program TPROC ident TLBRACE stmts TRBRACE  */
#line 153 "parser.y"
                                                    {
                                                        map_set(g_ctx->named_procs, (yyvsp[-3].ident), Block_new((yyvsp[-1].stmts)));
                                                        bhex_free((yyvsp[-3].ident));
                                                    }
#line 1803 "parser.c"
    break;

  case 5: /* program: program TFN ident TCLBRACE TCRBRACE TLBRACE stmts TRBRACE  */
#line 158 "parser.y"
                                                    {
                                                        map_set(g_ctx->functions, (yyvsp[-5].ident), Function_new((yyvsp[-5].ident), NULL, Block_new((yyvsp[-1].stmts))));
                                                        bhex_free((yyvsp[-5].ident));
                                                    }
#line 1812 "parser.c"
    break;

  case 6: /* program: program TFN ident TCLBRACE name_params TCRBRACE TLBRACE stmts TRBRACE  */
#line 163 "parser.y"
                                                    {
                                                        map_set(g_ctx->functions, (yyvsp[-6].ident), Function_new((yyvsp[-6].ident), (yyvsp[-4].params), Block_new((yyvsp[-1].stmts))));
                                                        bhex_free((yyvsp[-6].ident));
                                                    }
#line 1821 "parser.c"
    break;

  case 7: /* program: program TSTRUCT ident TLBRACE stmts TRBRACE  */
#line 168 "parser.y"
                                                    {
                                                        map_set(g_ctx->structs, (yyvsp[-3].ident), Block_new((yyvsp[-1].stmts)));
                                                        bhex_free((yyvsp[-3].ident));
                                                    }
#line 1830 "parser.c"
    break;

  case 8: /* program: program TENUM ident TCOLON ident TLBRACE enum_list TRBRACE  */
#line 173 "parser.y"
                                                    {
                                                        map_set(g_ctx->enums, (yyvsp[-5].ident), Enum_new((yyvsp[-3].ident), (yyvsp[-1].enum_list), 0));
                                                        bhex_free((yyvsp[-5].ident));
                                                        bhex_free((yyvsp[-3].ident));
                                                    }
#line 1840 "parser.c"
    break;

  case 9: /* program: program TORENUM ident TCOLON ident TLBRACE enum_list TRBRACE  */
#line 179 "parser.y"
                                                    {
                                                        map_set(g_ctx->enums, (yyvsp[-5].ident), Enum_new((yyvsp[-3].ident), (yyvsp[-1].enum_list), 1));
                                                        bhex_free((yyvsp[-5].ident));
                                                        bhex_free((yyvsp[-3].ident));
                                                    }
#line 1850 "parser.c"
    break;

  case 10: /* enum_list: ident TEQUAL TSNUM64  */
#line 186 "parser.y"
                                                    {
                                                        (yyval.enum_list) = DList_new();
                                                        DList_add((yyval.enum_list), EnumEntry_new((yyvsp[-2].ident), yysnumval));
                                                        bhex_free((yyvsp[-2].ident));
                                                    }
#line 1860 "parser.c"
    break;

  case 11: /* enum_list: enum_list TCOMMA ident TEQUAL TSNUM64  */
#line 191 "parser.y"
                                                    {
                                                        DList_add((yyvsp[-4].enum_list), EnumEntry_new((yyvsp[-2].ident), yysnumval));
                                                        bhex_free((yyvsp[-2].ident));
                                                    }
#line 1869 "parser.c"
    break;

  case 12: /* stmts: stmt  */
#line 197 "parser.y"
                                                   {
                                                        (yyval.stmts) = DList_new();
                                                        DList_add((yyval.stmts), (yyvsp[0].stmt));
                                                    }
#line 1878 "parser.c"
    break;

  case 13: /* stmts: stmts stmt  */
#line 201 "parser.y"
                                                    {
                                                        DList_add((yyvsp[-1].stmts), (yyvsp[0].stmt));
                                                    }
#line 1886 "parser.c"
    break;

  case 24: /* fvar_type: ident  */
#line 218 "parser.y"
                                                    {
                                                        (yyval.fvar_type) = Type_new((yyvsp[0].ident), NULL);
                                                        bhex_free((yyvsp[0].ident));
                                                    }
#line 1895 "parser.c"
    break;

  case 25: /* fvar_type: ident THASHTAG ident  */
#line 222 "parser.y"
                                                    {
                                                        (yyval.fvar_type) = Type_new((yyvsp[0].ident), (yyvsp[-2].ident));
                                                        bhex_free((yyvsp[-2].ident));
                                                        bhex_free((yyvsp[0].ident));
                                                    }
#line 1905 "parser.c"
    break;

  case 26: /* fvar_decl: fvar_type ident  */
#line 230 "parser.y"
                                                    {
                                                        size_t fvar_name_len = strlen((yyvsp[0].ident));
                                                        if ((u64_t)fvar_name_len > yymax_fvar_name_len)
                                                            yymax_fvar_name_len = (u64_t)fvar_name_len;

                                                        (yyval.stmt) = Stmt_FILE_VAR_DECL_new((yyvsp[-1].fvar_type), (yyvsp[0].ident), NULL);
                                                        Stmt_set_source_info((yyval.stmt), yy_line, yy_column);
                                                        bhex_free((yyvsp[0].ident));
                                                    }
#line 1919 "parser.c"
    break;

  case 27: /* fvar_decl: fvar_type ident SQLBRACE expr SQRBRACE  */
#line 240 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_FILE_VAR_DECL_new((yyvsp[-4].fvar_type), (yyvsp[-3].ident), (yyvsp[-1].expr));
                                                        Stmt_set_source_info((yyval.stmt), yy_line, yy_column);
                                                        bhex_free((yyvsp[-3].ident));
                                                    }
#line 1929 "parser.c"
    break;

  case 28: /* lvar_decl: TLOCAL ident TEQUAL expr  */
#line 247 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_LOCAL_VAR_DECL_new((yyvsp[-2].ident), (yyvsp[0].expr));
                                                        Stmt_set_source_info((yyval.stmt), yy_line, yy_column);
                                                        bhex_free((yyvsp[-2].ident));
                                                    }
#line 1939 "parser.c"
    break;

  case 29: /* lvar_ass: ident TEQUAL expr  */
#line 254 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_LOCAL_VAR_ASS_new((yyvsp[-2].ident), (yyvsp[0].expr));
                                                        Stmt_set_source_info((yyval.stmt), yy_line, yy_column);
                                                        bhex_free((yyvsp[-2].ident));
                                                    }
#line 1949 "parser.c"
    break;

  case 30: /* void_fcall: ident TCLBRACE TCRBRACE  */
#line 261 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_VOID_FUNC_CALL_new((yyvsp[-2].ident), NULL);
                                                        Stmt_set_source_info((yyval.stmt), yy_line, yy_column);
                                                        bhex_free((yyvsp[-2].ident));
                                                    }
#line 1959 "parser.c"
    break;

  case 31: /* void_fcall: ident TCLBRACE params TCRBRACE  */
#line 266 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_VOID_FUNC_CALL_new((yyvsp[-3].ident), (yyvsp[-1].params));
                                                        Stmt_set_source_info((yyval.stmt), yy_line, yy_column);
                                                        bhex_free((yyvsp[-3].ident));
                                                    }
#line 1969 "parser.c"
    break;

  case 32: /* if_elif: TIF TCLBRACE expr TCRBRACE TLBRACE stmts TRBRACE  */
#line 274 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_STMT_IF_new((yyvsp[-4].expr), Block_new((yyvsp[-1].stmts)));
                                                        Stmt_set_source_info((yyval.stmt), yy_line, yy_column);
                                                    }
#line 1978 "parser.c"
    break;

  case 33: /* if_elif: TIF TCLBRACE expr TCRBRACE TLBRACE TRBRACE  */
#line 279 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_STMT_IF_new((yyvsp[-3].expr), Block_new(DList_new()));
                                                        Stmt_set_source_info((yyval.stmt), yy_line, yy_column);
                                                    }
#line 1987 "parser.c"
    break;

  case 34: /* if_elif: if_elif TELIF TCLBRACE expr TCRBRACE TLBRACE stmts TRBRACE  */
#line 284 "parser.y"
                                                    {
                                                        Stmt_STMT_IF_add_cond((yyvsp[-7].stmt), (yyvsp[-4].expr), Block_new((yyvsp[-1].stmts)));
                                                        (yyval.stmt) = (yyvsp[-7].stmt);
                                                    }
#line 1996 "parser.c"
    break;

  case 35: /* if_elif: if_elif TELIF TCLBRACE expr TCRBRACE TLBRACE TRBRACE  */
#line 289 "parser.y"
                                                    {
                                                        Stmt_STMT_IF_add_cond((yyvsp[-6].stmt), (yyvsp[-3].expr), Block_new(DList_new()));
                                                        (yyval.stmt) = (yyvsp[-6].stmt);
                                                    }
#line 2005 "parser.c"
    break;

  case 36: /* else: if_elif TELSE TLBRACE stmts TRBRACE  */
#line 296 "parser.y"
                                                    {
                                                        Stmt_STMT_IF_add_else((yyvsp[-4].stmt), Block_new((yyvsp[-1].stmts)));
                                                        (yyval.stmt) = (yyvsp[-4].stmt);
                                                    }
#line 2014 "parser.c"
    break;

  case 37: /* else: if_elif TELSE TLBRACE TRBRACE  */
#line 300 "parser.y"
                                                    {
                                                        (yyval.stmt) = (yyvsp[-3].stmt);
                                                    }
#line 2022 "parser.c"
    break;

  case 38: /* while: TWHILE TCLBRACE expr TCRBRACE TLBRACE stmts TRBRACE  */
#line 306 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_WHILE_new((yyvsp[-4].expr), Block_new((yyvsp[-1].stmts)));
                                                        Stmt_set_source_info((yyval.stmt), yy_line, yy_column);
                                                    }
#line 2031 "parser.c"
    break;

  case 39: /* break: TBREAK  */
#line 312 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_BREAK_new();
                                                        Stmt_set_source_info((yyval.stmt), yy_line, yy_column);
                                                    }
#line 2040 "parser.c"
    break;

  case 40: /* continue: TCONTINUE  */
#line 318 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_CONTINUE_new();
                                                        Stmt_set_source_info((yyval.stmt), yy_line, yy_column);
                                                    }
#line 2049 "parser.c"
    break;

  case 41: /* return: TRETURN  */
#line 324 "parser.y"
                                                    {
                                                        (yyval.stmt) = Stmt_RETURN_new();
                                                        Stmt_set_source_info((yyval.stmt), yy_line, yy_column);
                                                    }
#line 2058 "parser.c"
    break;

  case 43: /* expr: TSTR  */
#line 331 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_STRING_new(yyheapbuf, yyheapbuf_len);
                                                    }
#line 2066 "parser.c"
    break;

  case 44: /* expr: ident  */
#line 334 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_VAR_new((yyvsp[0].ident));
                                                        bhex_free((yyvsp[0].ident));
                                                    }
#line 2075 "parser.c"
    break;

  case 45: /* expr: ident TCOLCOL ident  */
#line 338 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_ENUM_CONST_new((yyvsp[-2].ident), (yyvsp[0].ident));
                                                        bhex_free((yyvsp[-2].ident));
                                                        bhex_free((yyvsp[0].ident));
                                                    }
#line 2085 "parser.c"
    break;

  case 46: /* expr: expr TDOT ident  */
#line 343 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SUBSCR_new((yyvsp[-2].expr), (yyvsp[0].ident));
                                                        bhex_free((yyvsp[0].ident));
                                                    }
#line 2094 "parser.c"
    break;

  case 47: /* expr: expr SQLBRACE expr SQRBRACE  */
#line 347 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_ARRAY_SUB_new((yyvsp[-3].expr), (yyvsp[-1].expr));
                                                    }
#line 2102 "parser.c"
    break;

  case 48: /* expr: ident TCLBRACE TCRBRACE  */
#line 350 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_FUN_CALL_new((yyvsp[-2].ident), NULL);
                                                        bhex_free((yyvsp[-2].ident));
                                                    }
#line 2111 "parser.c"
    break;

  case 49: /* expr: ident TCLBRACE params TCRBRACE  */
#line 354 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_FUN_CALL_new((yyvsp[-3].ident), (yyvsp[-1].params));
                                                        bhex_free((yyvsp[-3].ident));
                                                    }
#line 2120 "parser.c"
    break;

  case 50: /* expr: TCLBRACE expr TCRBRACE  */
#line 358 "parser.y"
                                                    {
                                                        (yyval.expr) = (yyvsp[-1].expr);
                                                    }
#line 2128 "parser.c"
    break;

  case 51: /* expr: TSUB expr  */
#line 361 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SUB_new(Expr_SCONST_new(0, 8), (yyvsp[0].expr));
                                                    }
#line 2136 "parser.c"
    break;

  case 52: /* expr: expr TAND expr  */
#line 364 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_AND_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 2144 "parser.c"
    break;

  case 53: /* expr: expr TOR expr  */
#line 367 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_OR_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 2152 "parser.c"
    break;

  case 54: /* expr: expr TXOR expr  */
#line 370 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_XOR_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 2160 "parser.c"
    break;

  case 55: /* expr: expr TADD expr  */
#line 373 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_ADD_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 2168 "parser.c"
    break;

  case 56: /* expr: expr TSUB expr  */
#line 376 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SUB_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 2176 "parser.c"
    break;

  case 57: /* expr: expr TMUL expr  */
#line 379 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_MUL_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 2184 "parser.c"
    break;

  case 58: /* expr: expr TDIV expr  */
#line 382 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_DIV_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 2192 "parser.c"
    break;

  case 59: /* expr: expr TMOD expr  */
#line 385 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_MOD_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 2200 "parser.c"
    break;

  case 60: /* expr: expr TBEQ expr  */
#line 388 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BEQ_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 2208 "parser.c"
    break;

  case 61: /* expr: expr TBNEQ expr  */
#line 391 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BNOT_new(Expr_BEQ_new((yyvsp[-2].expr), (yyvsp[0].expr)));
                                                    }
#line 2216 "parser.c"
    break;

  case 62: /* expr: expr TBLT expr  */
#line 394 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BLT_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 2224 "parser.c"
    break;

  case 63: /* expr: expr TBLE expr  */
#line 397 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BLE_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 2232 "parser.c"
    break;

  case 64: /* expr: expr TBGT expr  */
#line 400 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BGT_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 2240 "parser.c"
    break;

  case 65: /* expr: expr TBGE expr  */
#line 403 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BGE_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 2248 "parser.c"
    break;

  case 66: /* expr: expr TBAND expr  */
#line 406 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BAND_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 2256 "parser.c"
    break;

  case 67: /* expr: expr TBOR expr  */
#line 409 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BOR_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 2264 "parser.c"
    break;

  case 68: /* expr: expr TSHR expr  */
#line 412 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SHR_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 2272 "parser.c"
    break;

  case 69: /* expr: expr TSHL expr  */
#line 415 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SHL_new((yyvsp[-2].expr), (yyvsp[0].expr));
                                                    }
#line 2280 "parser.c"
    break;

  case 70: /* expr: TBNOT expr  */
#line 418 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_BNOT_new((yyvsp[0].expr));
                                                    }
#line 2288 "parser.c"
    break;

  case 71: /* name_params: ident  */
#line 423 "parser.y"
                                                    {
                                                        (yyval.params) = DList_new();
                                                        DList_add((yyval.params), (yyvsp[0].ident));
                                                    }
#line 2297 "parser.c"
    break;

  case 72: /* name_params: name_params TCOMMA ident  */
#line 427 "parser.y"
                                                    {
                                                        DList_add((yyval.params), (yyvsp[0].ident));
                                                    }
#line 2305 "parser.c"
    break;

  case 73: /* params: expr  */
#line 431 "parser.y"
                                                    {
                                                        (yyval.params) = DList_new();
                                                        DList_add((yyval.params), (yyvsp[0].expr));
                                                    }
#line 2314 "parser.c"
    break;

  case 74: /* params: params TCOMMA expr  */
#line 435 "parser.y"
                                                    {
                                                        DList_add((yyval.params), (yyvsp[0].expr));
                                                    }
#line 2322 "parser.c"
    break;

  case 75: /* num: TUNUM8  */
#line 440 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_UCONST_new(yyunumval, 1);
                                                    }
#line 2330 "parser.c"
    break;

  case 76: /* num: TUNUM16  */
#line 443 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_UCONST_new(yyunumval, 2);
                                                    }
#line 2338 "parser.c"
    break;

  case 77: /* num: TUNUM32  */
#line 446 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_UCONST_new(yyunumval, 4);
                                                    }
#line 2346 "parser.c"
    break;

  case 78: /* num: TUNUM64  */
#line 449 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_UCONST_new(yyunumval, 8);
                                                    }
#line 2354 "parser.c"
    break;

  case 79: /* num: TSNUM8  */
#line 452 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SCONST_new(yysnumval, 1);
                                                    }
#line 2362 "parser.c"
    break;

  case 80: /* num: TSNUM16  */
#line 455 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SCONST_new(yysnumval, 2);
                                                    }
#line 2370 "parser.c"
    break;

  case 81: /* num: TSNUM32  */
#line 458 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SCONST_new(yysnumval, 4);
                                                    }
#line 2378 "parser.c"
    break;

  case 82: /* num: TSNUM64  */
#line 461 "parser.y"
                                                    {
                                                        (yyval.expr) = Expr_SCONST_new(yysnumval, 8);
                                                    }
#line 2386 "parser.c"
    break;

  case 83: /* ident: TIDENTIFIER  */
#line 466 "parser.y"
                                                    {
                                                        (yyval.ident) = bhex_strdup(yystrval);
                                                    }
#line 2394 "parser.c"
    break;


#line 2398 "parser.c"

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
      {
        yypcontext_t yyctx
          = {yyssp, yytoken, &yylloc};
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = yysyntax_error (&yymsg_alloc, &yymsg, &yyctx);
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == -1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = YY_CAST (char *,
                             YYSTACK_ALLOC (YY_CAST (YYSIZE_T, yymsg_alloc)));
            if (yymsg)
              {
                yysyntax_error_status
                  = yysyntax_error (&yymsg_alloc, &yymsg, &yyctx);
                yymsgp = yymsg;
              }
            else
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = YYENOMEM;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == YYENOMEM)
          YYNOMEM;
      }
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
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
  return yyresult;
}

#line 471 "parser.y"

