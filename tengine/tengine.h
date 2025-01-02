#ifndef TENGINE_H
#define TENGINE_H

#include "../filebuffer.h"
#include "ast.h"
#include "map.h"

typedef enum Endianess { TE_LITTLE_ENDIAN = 40, TE_BIG_ENDIAN } Endianess;

typedef struct TEngine {
    ASTCtx ast;
    map*   variables;

    Endianess endianess;
    int       print_in_hex;
} TEngine;

void TEngine_init(TEngine* engine);
void TEngine_deinit(TEngine* engine);

int TEngine_process_filename(TEngine* engine, FileBuffer* fb, const char* bhe);
int TEngine_process_file(TEngine* engine, FileBuffer* fb, FILE* f);

void TEngine_pp(TEngine* e);

#endif
