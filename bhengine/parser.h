/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

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

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_YY_PARSER_H_INCLUDED
# define YY_YY_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    TPROC = 258,                   /* TPROC  */
    TFN = 259,                     /* TFN  */
    TLOCAL = 260,                  /* TLOCAL  */
    TSTRUCT = 261,                 /* TSTRUCT  */
    TENUM = 262,                   /* TENUM  */
    TORENUM = 263,                 /* TORENUM  */
    TIF = 264,                     /* TIF  */
    TELIF = 265,                   /* TELIF  */
    TELSE = 266,                   /* TELSE  */
    TWHILE = 267,                  /* TWHILE  */
    TBREAK = 268,                  /* TBREAK  */
    TCONTINUE = 269,               /* TCONTINUE  */
    TRETURN = 270,                 /* TRETURN  */
    TIDENTIFIER = 271,             /* TIDENTIFIER  */
    TUNUM8 = 272,                  /* TUNUM8  */
    TUNUM16 = 273,                 /* TUNUM16  */
    TUNUM32 = 274,                 /* TUNUM32  */
    TUNUM64 = 275,                 /* TUNUM64  */
    TSNUM8 = 276,                  /* TSNUM8  */
    TSNUM16 = 277,                 /* TSNUM16  */
    TSNUM32 = 278,                 /* TSNUM32  */
    TSNUM64 = 279,                 /* TSNUM64  */
    TSTR = 280,                    /* TSTR  */
    TCLBRACE = 281,                /* TCLBRACE  */
    TCRBRACE = 282,                /* TCRBRACE  */
    TLBRACE = 283,                 /* TLBRACE  */
    TRBRACE = 284,                 /* TRBRACE  */
    SQLBRACE = 285,                /* SQLBRACE  */
    SQRBRACE = 286,                /* SQRBRACE  */
    TSEMICOLON = 287,              /* TSEMICOLON  */
    TCOLON = 288,                  /* TCOLON  */
    TCOMMA = 289,                  /* TCOMMA  */
    TDOT = 290,                    /* TDOT  */
    TCOLCOL = 291,                 /* TCOLCOL  */
    THASHTAG = 292,                /* THASHTAG  */
    TADD = 293,                    /* TADD  */
    TSUB = 294,                    /* TSUB  */
    TMUL = 295,                    /* TMUL  */
    TDIV = 296,                    /* TDIV  */
    TMOD = 297,                    /* TMOD  */
    TAND = 298,                    /* TAND  */
    TOR = 299,                     /* TOR  */
    TXOR = 300,                    /* TXOR  */
    TBAND = 301,                   /* TBAND  */
    TBOR = 302,                    /* TBOR  */
    TBEQ = 303,                    /* TBEQ  */
    TBNEQ = 304,                   /* TBNEQ  */
    TBGT = 305,                    /* TBGT  */
    TBGE = 306,                    /* TBGE  */
    TBLT = 307,                    /* TBLT  */
    TBLE = 308,                    /* TBLE  */
    TEQUAL = 309,                  /* TEQUAL  */
    TBNOT = 310,                   /* TBNOT  */
    TSHL = 311,                    /* TSHL  */
    TSHR = 312                     /* TSHR  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 102 "parser.y"

    Stmt*    stmt;
    DList*   stmts;
    DList*   params;
    DList*   enum_list;
    Expr*    expr;
    Type*    fvar_type;
    char*    ident;

#line 131 "parser.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif

/* Location type.  */
#if ! defined YYLTYPE && ! defined YYLTYPE_IS_DECLARED
typedef struct YYLTYPE YYLTYPE;
struct YYLTYPE
{
  int first_line;
  int first_column;
  int last_line;
  int last_column;
};
# define YYLTYPE_IS_DECLARED 1
# define YYLTYPE_IS_TRIVIAL 1
#endif


extern YYSTYPE yylval;
extern YYLTYPE yylloc;

int yyparse (void);


#endif /* !YY_YY_PARSER_H_INCLUDED  */
