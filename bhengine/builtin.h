// Copyright (c) 2022-2026, bageyelet

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

// Number of parameters accepted by a builtin. max_params is BUILTIN_VARIADIC
// when there is no upper bound. The check is done once, by the interpreter,
// before the builtin runs: implementations can assume the arity is valid.
#define BUILTIN_VARIADIC (-1)

typedef struct BHEngineBuiltinFunc {
    char name[MAX_IDENT_SIZE];
    int  min_params;
    int  max_params;
    struct BHEngineValue* (*process)(struct InterpreterContext* ctx,
                                     struct DList*              params);
} BHEngineBuiltinFunc;

const BHEngineBuiltinFunc* get_builtin_func(const char* name);

// Raises an exception and returns 1 if `params` does not match the arity
// declared by `func`, otherwise returns 0.
int check_builtin_arity(struct InterpreterContext* ctx,
                        const BHEngineBuiltinFunc* func, struct DList* params);

#define is_builtin_type(t) (get_builtin_type(t) != NULL)
#define is_builtin_fun(t)  (get_builtin_func(t) != NULL)

#endif
