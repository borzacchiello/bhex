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
/* Line 1529 of yacc.c.  */
#line 165 "parser.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;

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

extern YYLTYPE yylloc;
