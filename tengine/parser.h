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
     TIF = 261,
     TELSE = 262,
     TIDENTIFIER = 263,
     TNUM = 264,
     TCLBRACE = 265,
     TCRBRACE = 266,
     TLBRACE = 267,
     TRBRACE = 268,
     SQLBRACE = 269,
     SQRBRACE = 270,
     TSEMICOLON = 271,
     TCOLON = 272,
     TCOMMA = 273,
     TDOT = 274,
     TADD = 275,
     TBEQ = 276,
     TEQUAL = 277
   };
#endif
/* Tokens.  */
#define TPROC 258
#define TSTRUCT 259
#define TENUM 260
#define TIF 261
#define TELSE 262
#define TIDENTIFIER 263
#define TNUM 264
#define TCLBRACE 265
#define TCRBRACE 266
#define TLBRACE 267
#define TRBRACE 268
#define SQLBRACE 269
#define SQRBRACE 270
#define TSEMICOLON 271
#define TCOLON 272
#define TCOMMA 273
#define TDOT 274
#define TADD 275
#define TBEQ 276
#define TEQUAL 277




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 29 "parser.y"
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
#line 103 "parser.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;

