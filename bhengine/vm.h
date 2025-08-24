#ifndef TENGINE_CONTEXT_H
#define TENGINE_CONTEXT_H

#include <filebuffer.h>
#include <map.h>

#include "formatter.h"
#include "ast.h"

typedef struct BHEngineVM {
    map* templates;
} BHEngineVM;

BHEngineVM* bhengine_vm_create(const char** dirs);
void        bhengine_vm_destroy(BHEngineVM* ctx);

void bhengine_vm_set_fmt_type(fmt_t t);

int bhengine_vm_add_template(BHEngineVM* ctx, const char* name,
                             const char* path);

void bhengine_vm_iter_templates(BHEngineVM* ctx,
                                void (*cb)(const char* name, ASTCtx* ast));
void bhengine_vm_iter_structs(BHEngineVM* ctx,
                              void (*cb)(const char* name,
                                         const char* struct_name, ASTCtx* ast));
void bhengine_vm_iter_named_procs(BHEngineVM* ctx,
                                  void (*cb)(const char* bhe, const char* name,
                                             ASTCtx* ast));

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
