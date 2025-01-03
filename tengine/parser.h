/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

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

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     TPROC = 258,
     TSTRUCT = 259,
     TENUM = 260,
     TIDENTIFIER = 261,
     TNUM = 262,
     TCLBRACE = 263,
     TCRBRACE = 264,
     TLBRACE = 265,
     TRBRACE = 266,
     SQLBRACE = 267,
     SQRBRACE = 268,
     TSEMICOLON = 269,
     TCOLON = 270,
     TCOMMA = 271,
     TDOT = 272,
     TADD = 273,
     TEQUAL = 274
   };
#endif
/* Tokens.  */
#define TPROC 258
#define TSTRUCT 259
#define TENUM 260
#define TIDENTIFIER 261
#define TNUM 262
#define TCLBRACE 263
#define TCRBRACE 264
#define TLBRACE 265
#define TRBRACE 266
#define SQLBRACE 267
#define SQRBRACE 268
#define TSEMICOLON 269
#define TCOLON 270
#define TCOMMA 271
#define TDOT 272
#define TADD 273
#define TEQUAL 274




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 27 "parser.y"
{
    Stmt*    stmt;
    DList*   stmts;
    DList*   params;
    DList*   enum_list;
    DList*   varchain;
    Expr*    expr;
    char*    ident;
}
/* Line 1529 of yacc.c.  */
#line 97 "parser.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;

