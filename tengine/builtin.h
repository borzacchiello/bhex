#ifndef TENGINE_BUILTIN_H
#define TENGINE_BUILTIN_H

#include "ast.h"
#include "interpreter.h"

struct InterpreterContext;
struct TEngineValue;
struct FileBuffer;
struct DList;

typedef struct TEngineBuiltinType {
    char name[MAX_IDENT_SIZE];
    struct TEngineValue* (*process)(struct InterpreterContext* ctx);
} TEngineBuiltinType;

const TEngineBuiltinType* get_builtin_type(const char* type);

typedef struct TEngineBuiltinFunc {
    char name[MAX_IDENT_SIZE];
    struct TEngineValue* (*process)(struct InterpreterContext* ctx,
                                    struct DList*              params);
} TEngineBuiltinFunc;

const TEngineBuiltinFunc* get_builtin_func(const char* name);

#endif
