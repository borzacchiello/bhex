#ifndef TENGINE_BUILTIN_H
#define TENGINE_BUILTIN_H

#include "ast.h"
#include "interpreter.h"

struct InterpreterContext;
struct BHEngineValue;
struct FileBuffer;
struct DList;

typedef struct BHEngineBuiltinType {
    char name[MAX_IDENT_SIZE];
    struct BHEngineValue* (*process)(struct InterpreterContext* ctx);
} BHEngineBuiltinType;

const BHEngineBuiltinType* get_builtin_type(const char* type);

typedef struct BHEngineBuiltinFunc {
    char name[MAX_IDENT_SIZE];
    struct BHEngineValue* (*process)(struct InterpreterContext* ctx,
                                    struct DList*              params);
} BHEngineBuiltinFunc;

const BHEngineBuiltinFunc* get_builtin_func(const char* name);

#define is_builtin_type(t) (get_builtin_type(t) != NULL)
#define is_builtin_fun(t)  (get_builtin_func(t) != NULL)

#endif
