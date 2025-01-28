#ifndef TENGINE_BUILTIN_H
#define TENGINE_BUILTIN_H

#include "ast.h"

struct TEngineValue;
struct FileBuffer;
struct TEngine;
struct DList;

typedef struct TEngineBuiltinType {
    char name[MAX_IDENT_SIZE];
    struct TEngineValue* (*process)(struct TEngine* e, struct FileBuffer* fb);
} TEngineBuiltinType;

const TEngineBuiltinType* get_builtin_type(const char* type);

typedef struct TEngineBuiltinFunc {
    char  name[MAX_IDENT_SIZE];
    struct TEngineValue* (*process)(struct TEngine* e, struct FileBuffer* fb,
                                    struct DList* params);
} TEngineBuiltinFunc;

const TEngineBuiltinFunc* get_builtin_func(const char* name);

#endif
