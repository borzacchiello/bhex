#ifndef TENGINE_H
#define TENGINE_H

#include "../filebuffer.h"
#include "ast.h"

typedef enum Endianess { LITTLE_ENDIAN = 40, BIG_ENDIAN } Endianess;

typedef struct TEngine {
    ASTCtx    ast;
    Endianess endiness;
} TEngine;

void TEngine_init(TEngine* engine);
void TEngine_deinit(TEngine* engine);

int TEngine_process_filename(TEngine* engine, FileBuffer* fb,
                             const char* template);
int TEngine_process_file(TEngine* engine, FileBuffer* fb, FILE* f);

#endif
