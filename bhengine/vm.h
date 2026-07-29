// Copyright (c) 2022-2026, bageyelet

#ifndef TENGINE_CONTEXT_H
#define TENGINE_CONTEXT_H

#include <filebuffer.h>
#include <map.h>

#include "interpreter.h"
#include "formatter.h"
#include "ast.h"

typedef struct BHEngineVM {
    map* templates;
} BHEngineVM;

BHEngineVM* bhengine_vm_create(const char** dirs);
void        bhengine_vm_destroy(BHEngineVM* ctx);

// The one VM every command shares. The engine resolves imported types through
// a single global callback, so a second VM would silently take over type
// resolution for the first: there is exactly one, owned by the engine, built
// on first use and released at exit.
BHEngineVM* bhengine_vm_get(void);

// Just for testing purposes: when set before the first bhengine_vm_get(), no
// directory is searched and the VM comes up empty
extern int bhengine_vm_skip_search;

void bhengine_vm_set_fmt_type(fmt_t t);

int bhengine_vm_add_template(BHEngineVM* ctx, const char* name,
                             const char* path);

// Drops a template. Returns 1 when there was one to drop.
int bhengine_vm_remove_template(BHEngineVM* ctx, const char* name);

void bhengine_vm_iter_templates(BHEngineVM* ctx,
                                void (*cb)(const char* name, ASTCtx* ast));
void bhengine_vm_iter_structs(BHEngineVM* ctx,
                              void (*cb)(const char* name,
                                         const char* struct_name, ASTCtx* ast));
void bhengine_vm_iter_named_procs(BHEngineVM* ctx,
                                  void (*cb)(const char* bhe, const char* name,
                                             ASTCtx* ast));

// Iterates the templates that declare an "_identify" proc, handing the caller
// a runner for each. The runners belong to the caller, which frees them with
// bhengine_identifier_free()
void bhengine_vm_iter_identifiers(BHEngineVM* ctx, FileBuffer* fb,
                                  void (*cb)(const char*         name,
                                             BHEngineIdentifier* id,
                                             void*               user),
                                  void* user);

int bhengine_vm_has_template(BHEngineVM* ctx, const char* bhe);
int bhengine_vm_has_bhe_struct(BHEngineVM* ctx, const char* bhe,
                               const char* struct_name);
int bhengine_vm_has_bhe_proc(BHEngineVM* ctx, const char* bhe,
                             const char* proc_name);

int bhengine_vm_process_bhe(BHEngineVM* ctx, FileBuffer* fb, const char* bhe);
int bhengine_vm_process_bhe_struct(BHEngineVM* ctx, FileBuffer* fb,
                                   const char* bhe, const char* struct_name);
int bhengine_vm_process_bhe_proc(BHEngineVM* ctx, FileBuffer* fb,
                                 const char* bhe, const char* proc_name);
int bhengine_vm_process_file(BHEngineVM* ctx, FileBuffer* fb,
                             const char* fname);
int bhengine_vm_process_string(BHEngineVM* ctx, FileBuffer* fb,
                               const char* code);

#endif
