// Copyright (c) 2022-2026, bageyelet

#ifndef TENGINE_H
#define TENGINE_H

#include <filebuffer.h>
#include <strbuilder.h>

#include "formatter.h"
#include "ast.h"

typedef enum Endianess { TE_LITTLE_ENDIAN = 40, TE_BIG_ENDIAN } Endianess;
typedef ASTCtx* (*imported_cb_t)(void* ptr, const char* bhe);

struct Scope;

// Maximum nesting depth for function calls and struct expansions.
#define BHENGINE_MAX_CALL_DEPTH 256

// Maximum number of chained messages in a single exception.
#define BHENGINE_MAX_EXC_MSGS 8

typedef struct InterpreterException {
    StringBuilder* sb;
    int            nmsgs;
} InterpreterException;

typedef struct InterpreterContext {
    FileBuffer*   fb;
    ASTCtx*       ast;
    u64_t         initial_off;
    struct Scope* proc_scope;
    Formatter*    fmt;

    Endianess             endianess;
    Stmt*                 curr_stmt;
    InterpreterException* exc;

    // Nesting depth of function calls / struct expansions. Guards against
    // unbounded recursion (e.g. "fn f() { f(); }" or "struct A { A x; }")
    // exhausting the stack.
    int call_depth;

    int break_or_continue_allowed, return_allowed;
    int breaked, continued, returned;
    int halt; // halt the execution (exception or exit)
} InterpreterContext;

void bhengine_interpreter_set_fmt_type(fmt_t t);

int bhengine_interpreter_process_filename(FileBuffer* fb, const char* bhe);
int bhengine_interpreter_process_file(FileBuffer* fb, FILE* f);
int bhengine_interpreter_process_string(FileBuffer* fb, const char* str);
int bhengine_interpreter_process_ast(FileBuffer* fb, ASTCtx* ast);
int bhengine_interpreter_process_ast_struct(FileBuffer* fb, ASTCtx* ast,
                                            const char* s);
int bhengine_interpreter_process_ast_named_proc(FileBuffer* fb, ASTCtx* ast,
                                                const char* s);

void bhengine_raise_exception(InterpreterContext* ictx, const char* fmt, ...);
void bhengine_raise_exit_request(InterpreterContext* ctx);

struct Scope* bhengine_interpreter_run_on_string(FileBuffer* fb,
                                                 const char* str);

void bhengine_interpreter_context_pp(InterpreterContext* e);

// callback to process imported types
void bhengine_interpreter_set_imported_types_callback(imported_cb_t cb,
                                                      void*         userptr);
#endif
