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
     TLOCAL = 259,
     TSTRUCT = 260,
     TENUM = 261,
     TIF = 262,
     TELSE = 263,
     TWHILE = 264,
     TIDENTIFIER = 265,
     TNUM = 266,
     TCLBRACE = 267,
     TCRBRACE = 268,
     TLBRACE = 269,
     TRBRACE = 270,
     SQLBRACE = 271,
     SQRBRACE = 272,
     TSEMICOLON = 273,
     TCOLON = 274,
     TCOMMA = 275,
     TDOT = 276,
     TADD = 277,
     TSUB = 278,
     TMUL = 279,
     TBEQ = 280,
     TBGT = 281,
     TBGE = 282,
     TBLT = 283,
     TBLE = 284,
     TEQUAL = 285
   };
#endif
/* Tokens.  */
#define TPROC 258
#define TLOCAL 259
#define TSTRUCT 260
#define TENUM 261
#define TIF 262
#define TELSE 263
#define TWHILE 264
#define TIDENTIFIER 265
#define TNUM 266
#define TCLBRACE 267
#define TCRBRACE 268
#define TLBRACE 269
#define TRBRACE 270
#define SQLBRACE 271
#define SQRBRACE 272
#define TSEMICOLON 273
#define TCOLON 274
#define TCOMMA 275
#define TDOT 276
#define TADD 277
#define TSUB 278
#define TMUL 279
#define TBEQ 280
#define TBGT 281
#define TBGE 282
#define TBLT 283
#define TBLE 284
#define TEQUAL 285




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
#line 119 "parser.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;

