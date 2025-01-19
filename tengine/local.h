#ifndef TENGINE_LOCAL
#define TENGINE_LOCAL

#include <stdio.h>
#include "ast.h"

extern int  yyparse(void);
extern void yyset_in(FILE*);
extern void yyset_ctx(ASTCtx*);
extern int  yymax_ident_len;

#endif
