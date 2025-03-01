#ifndef TENGINE_H
#define TENGINE_H

#include <filebuffer.h>
#include "ast.h"

typedef enum Endianess { TE_LITTLE_ENDIAN = 40, TE_BIG_ENDIAN } Endianess;

struct Scope;
typedef struct TEngine {
    ASTCtx*       ast;
    struct Scope* proc_scope;

    Endianess endianess;
    int       print_in_hex;
    int       quiet_mode;
} TEngine;

ASTCtx* TEngine_parse_filename(const char* bhe);
ASTCtx* TEngine_parse_file(FILE* f);
ASTCtx* TEngine_parse_string(const char* str);

void TEngine_init(TEngine* engine, ASTCtx* ast);
void TEngine_deinit(TEngine* engine);

int TEngine_process_filename(FileBuffer* fb, const char* bhe);
int TEngine_process_file(FileBuffer* fb, FILE* f);
int TEngine_process_ast(FileBuffer* fb, ASTCtx* ast);
int TEngine_process_ast_struct(FileBuffer* fb, ASTCtx* ast, const char* s);

TEngine* TEngine_run_on_string(FileBuffer* fb, const char* str);

void TEngine_pp(TEngine* e);

#endif
