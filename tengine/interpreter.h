#ifndef TENGINE_H
#define TENGINE_H

#include <filebuffer.h>
#include <strbuilder.h>
#include "ast.h"

typedef enum Endianess { TE_LITTLE_ENDIAN = 40, TE_BIG_ENDIAN } Endianess;
typedef ASTCtx* (*imported_cb_t)(void* ptr, const char* bhe);

struct Scope;

typedef struct InterpreterException {
    StringBuilder* sb;
} InterpreterException;

typedef struct InterpreterContext {
    FileBuffer*   fb;
    ASTCtx*       ast;
    u64_t         initial_off;
    struct Scope* proc_scope;

    u32_t alignment_off;
    u32_t print_off;

    Endianess endianess;
    int       print_in_hex;
    int       quiet_mode;

    Stmt*                 curr_stmt;
    InterpreterException* exc;
    int                   break_allowed;
    int                   halt;    // halt the execution (exception or exit)
    int                   breaked; // break in a loop
} InterpreterContext;

int tengine_interpreter_process_filename(FileBuffer* fb, const char* bhe);
int tengine_interpreter_process_file(FileBuffer* fb, FILE* f);
int tengine_interpreter_process_ast(FileBuffer* fb, ASTCtx* ast);
int tengine_interpreter_process_ast_struct(FileBuffer* fb, ASTCtx* ast,
                                           const char* s);

void tengine_raise_exception(InterpreterContext* ictx, const char* fmt, ...);
void tengine_raise_exit_request(InterpreterContext* ctx);

struct Scope* tengine_interpreter_run_on_string(FileBuffer* fb,
                                                const char* str);

void tengine_interpreter_context_pp(InterpreterContext* e);

// callback to process imported types
void tengine_interpreter_set_imported_types_callback(imported_cb_t cb,
                                                     void*         userptr);
#endif
