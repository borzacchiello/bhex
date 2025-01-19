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
    TELSE = 264,                   /* TELSE  */
    TWHILE = 265,                  /* TWHILE  */
    TBREAK = 266,                  /* TBREAK  */
    TIDENTIFIER = 267,             /* TIDENTIFIER  */
    TUNUM8 = 268,                  /* TUNUM8  */
    TUNUM16 = 269,                 /* TUNUM16  */
    TUNUM32 = 270,                 /* TUNUM32  */
    TUNUM64 = 271,                 /* TUNUM64  */
    TSNUM8 = 272,                  /* TSNUM8  */
    TSNUM16 = 273,                 /* TSNUM16  */
    TSNUM32 = 274,                 /* TSNUM32  */
    TSNUM64 = 275,                 /* TSNUM64  */
    TSTR = 276,                    /* TSTR  */
    TCLBRACE = 277,                /* TCLBRACE  */
    TCRBRACE = 278,                /* TCRBRACE  */
    TLBRACE = 279,                 /* TLBRACE  */
    TRBRACE = 280,                 /* TRBRACE  */
    SQLBRACE = 281,                /* SQLBRACE  */
    SQRBRACE = 282,                /* SQRBRACE  */
    TSEMICOLON = 283,              /* TSEMICOLON  */
    TCOLON = 284,                  /* TCOLON  */
    TCOMMA = 285,                  /* TCOMMA  */
    TDOT = 286,                    /* TDOT  */
    TADD = 287,                    /* TADD  */
    TSUB = 288,                    /* TSUB  */
    TMUL = 289,                    /* TMUL  */
    TAND = 290,                    /* TAND  */
    TOR = 291,                     /* TOR  */
    TXOR = 292,                    /* TXOR  */
    TBEQ = 293,                    /* TBEQ  */
    TBGT = 294,                    /* TBGT  */
    TBGE = 295,                    /* TBGE  */
    TBLT = 296,                    /* TBLT  */
    TBLE = 297,                    /* TBLE  */
    TEQUAL = 298                   /* TEQUAL  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 33 "parser.y"

    Stmt*    stmt;
    DList*   stmts;
    DList*   params;
    DList*   enum_list;
    DList*   varchain;
    Expr*    expr;
    char*    ident;

#line 117 "parser.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;


int yyparse (void);


#endif /* !YY_YY_PARSER_H_INCLUDED  */
