// Copyright (c) 2022-2026, bageyelet

#ifndef TENGINE_H
#define TENGINE_H

#include <filebuffer.h>
#include <strbuilder.h>

#include "formatter.h"
#include "ast.h"

typedef enum Endianess { TE_LITTLE_ENDIAN = 40, TE_BIG_ENDIAN } Endianess;
// Resolves the AST of an imported template. When 'quiet' is set, a template
// that cannot be found (or parsed) must be reported as NULL without logging:
// the caller is only inspecting the types, not running them
typedef ASTCtx* (*imported_cb_t)(void* ptr, const char* bhe, int quiet);

struct Scope;

// Maximum nesting depth for function calls and struct expansions.
#define BHENGINE_MAX_CALL_DEPTH 256

// Maximum number of chained messages in a single exception.
#define BHENGINE_MAX_EXC_MSGS 8

// Name of the named proc a template declares to take part in the 'identify'
// scan. It answers a single question about the bytes at the current offset:
// "are you my format?".
#define BHENGINE_IDENTIFY_PROC "_identify"

// Name of the proc that declares, through magic() calls, the byte patterns
// without which BHENGINE_IDENTIFY_PROC cannot possibly succeed. It runs once,
// before the scan, and lets the scan skip every offset none of them match.
#define BHENGINE_IDENTIFY_MAGIC_PROC "_identify_magic"

// One pattern declared by magic(). `offset` is where the pattern sits inside
// the format, so a match at file offset X means the format may start at
// X - offset.
typedef struct BHEngineMagic {
    u8_t* pattern;
    u32_t size;
    u64_t offset;
} BHEngineMagic;

void BHEngineMagic_delete(BHEngineMagic* m);

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

    // Swallow exceptions instead of printing them. Set by the identify scan,
    // where a template refusing the bytes at an offset is the common case and
    // not something the user wants to read about a million times.
    int silent_exc;

    // Where magic() appends what it is told, i.e. a DList of BHEngineMagic*.
    // Only set while BHENGINE_IDENTIFY_MAGIC_PROC runs; magic() raises
    // anywhere else, since a declaration nobody collects is a template bug.
    DList* magics;
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

// A reusable runner for a template's "_identify" proc. It keeps the
// interpreter context (scope, formatter, name column widths) alive across
// invocations, because the identify scan runs the proc once per file offset
// and must not pay the setup cost every time.
typedef struct BHEngineIdentifier BHEngineIdentifier;

// Returns NULL when the AST declares no "_identify" proc, i.e. the template
// does not take part in the scan.
BHEngineIdentifier* bhengine_identifier_new(FileBuffer* fb, ASTCtx* ast);
void                bhengine_identifier_free(BHEngineIdentifier* id);

// The patterns the template declared through BHENGINE_IDENTIFY_MAGIC_PROC,
// collected once when the identifier was built. A DList of BHEngineMagic*,
// owned by the identifier.
//
// An EMPTY list means the template declared nothing: none of its patterns can
// be used to narrow the search, so the scan has to run its "_identify" at
// every offset. That is always correct -- "_identify" re-checks the magic
// itself and never relies on the scan having matched one first -- just slow.
const DList* bhengine_identifier_magics(BHEngineIdentifier* id);

// Runs "_identify" with the file positioned at 'off'. Returns what the proc
// assigned to 'result': 0 when it does not recognise the bytes, otherwise the
// number of bytes the scan may skip -- the size of the identified region when
// the proc could work it out, or at least the size of the header it just
// validated. A proc that answers with a plain 1/0 therefore still works, it
// simply never lets the scan skip anything.
//
// Nothing is printed: an exception raised along the way -- a failed assert, a
// read past the end of the file -- is just a "no".
u64_t bhengine_identifier_run(BHEngineIdentifier* id, u64_t off);

void bhengine_interpreter_context_pp(InterpreterContext* e);

// callback to process imported types
void bhengine_interpreter_set_imported_types_callback(imported_cb_t cb,
                                                      void*         userptr);

// The 'userptr' the callback is currently installed with, so that its owner can
// tell whether it is still the one answering
void* bhengine_interpreter_get_imported_types_userptr(void);
#endif
