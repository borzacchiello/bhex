#ifndef TENGINE_H
#define TENGINE_H

#include <filebuffer.h>
#include "ast.h"

typedef enum Endianess { TE_LITTLE_ENDIAN = 40, TE_BIG_ENDIAN } Endianess;
typedef ASTCtx* (*imported_cb_t)(void* ptr, const char* bhe);

struct Scope;
typedef struct InterpreterContext {
    FileBuffer*   fb;
    ASTCtx*       ast;
    u64_t         initial_off;
    struct Scope* proc_scope;

    int       alignment_off;
    int       print_off;

    Endianess endianess;
    int       print_in_hex;
    int       quiet_mode;
    int       should_break;
} InterpreterContext;

int tengine_interpreter_process_filename(FileBuffer* fb, const char* bhe);
int tengine_interpreter_process_file(FileBuffer* fb, FILE* f);
int tengine_interpreter_process_ast(FileBuffer* fb, ASTCtx* ast);
int tengine_interpreter_process_ast_struct(FileBuffer* fb, ASTCtx* ast,
                                           const char* s);

struct Scope* tengine_interpreter_run_on_string(FileBuffer* fb,
                                                const char* str);

void tengine_interpreter_context_pp(InterpreterContext* e);

// callback to process imported types
void tengine_interpreter_set_imported_types_callback(imported_cb_t cb,
                                                     void*         userptr);
#endif
