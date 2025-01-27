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
    TLOCAL = 259,                  /* TLOCAL  */
    TSTRUCT = 260,                 /* TSTRUCT  */
    TENUM = 261,                   /* TENUM  */
    TORENUM = 262,                 /* TORENUM  */
    TIF = 263,                     /* TIF  */
    TELIF = 264,                   /* TELIF  */
    TELSE = 265,                   /* TELSE  */
    TWHILE = 266,                  /* TWHILE  */
    TBREAK = 267,                  /* TBREAK  */
    TIDENTIFIER = 268,             /* TIDENTIFIER  */
    TUNUM8 = 269,                  /* TUNUM8  */
    TUNUM16 = 270,                 /* TUNUM16  */
    TUNUM32 = 271,                 /* TUNUM32  */
    TUNUM64 = 272,                 /* TUNUM64  */
    TSNUM8 = 273,                  /* TSNUM8  */
    TSNUM16 = 274,                 /* TSNUM16  */
    TSNUM32 = 275,                 /* TSNUM32  */
    TSNUM64 = 276,                 /* TSNUM64  */
    TSTR = 277,                    /* TSTR  */
    TCLBRACE = 278,                /* TCLBRACE  */
    TCRBRACE = 279,                /* TCRBRACE  */
    TLBRACE = 280,                 /* TLBRACE  */
    TRBRACE = 281,                 /* TRBRACE  */
    SQLBRACE = 282,                /* SQLBRACE  */
    SQRBRACE = 283,                /* SQRBRACE  */
    TSEMICOLON = 284,              /* TSEMICOLON  */
    TCOLON = 285,                  /* TCOLON  */
    TCOMMA = 286,                  /* TCOMMA  */
    TDOT = 287,                    /* TDOT  */
    TADD = 288,                    /* TADD  */
    TSUB = 289,                    /* TSUB  */
    TMUL = 290,                    /* TMUL  */
    TDIV = 291,                    /* TDIV  */
    TMOD = 292,                    /* TMOD  */
    TAND = 293,                    /* TAND  */
    TOR = 294,                     /* TOR  */
    TXOR = 295,                    /* TXOR  */
    TBAND = 296,                   /* TBAND  */
    TBOR = 297,                    /* TBOR  */
    TBEQ = 298,                    /* TBEQ  */
    TBNEQ = 299,                   /* TBNEQ  */
    TBGT = 300,                    /* TBGT  */
    TBGE = 301,                    /* TBGE  */
    TBLT = 302,                    /* TBLT  */
    TBLE = 303,                    /* TBLE  */
    TEQUAL = 304,                  /* TEQUAL  */
    TBNOT = 305                    /* TBNOT  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 34 "parser.y"

    Stmt*    stmt;
    DList*   stmts;
    DList*   params;
    DList*   enum_list;
    Expr*    expr;
    char*    ident;

#line 123 "parser.h"

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
