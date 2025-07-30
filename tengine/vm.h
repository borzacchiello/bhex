#ifndef TENGINE_CONTEXT_H
#define TENGINE_CONTEXT_H

#include <filebuffer.h>
#include <map.h>

#include "formatter.h"
#include "ast.h"

typedef struct TEngineVM {
    map* templates;
} TEngineVM;

TEngineVM* tengine_vm_create(const char** dirs);
void       tengine_vm_destroy(TEngineVM* ctx);

void tengine_vm_set_fmt_type(fmt_t t);

int tengine_vm_add_template(TEngineVM* ctx, const char* name, const char* path);

void tengine_vm_iter_templates(TEngineVM* ctx,
                               void (*cb)(const char* name, ASTCtx* ast));
void tengine_vm_iter_structs(TEngineVM* ctx,
                             void (*cb)(const char* name,
                                        const char* struct_name, ASTCtx* ast));
void tengine_vm_iter_named_procs(TEngineVM* ctx,
                                 void (*cb)(const char* bhe, const char* name,
                                            ASTCtx* ast));

int tengine_vm_has_template(TEngineVM* ctx, const char* bhe);
int tengine_vm_has_bhe_struct(TEngineVM* ctx, const char* bhe,
                              const char* struct_name);
int tengine_vm_has_bhe_proc(TEngineVM* ctx, const char* bhe,
                            const char* proc_name);

int tengine_vm_process_bhe(TEngineVM* ctx, FileBuffer* fb, const char* bhe);
int tengine_vm_process_bhe_struct(TEngineVM* ctx, FileBuffer* fb,
                                  const char* bhe, const char* struct_name);
int tengine_vm_process_bhe_proc(TEngineVM* ctx, FileBuffer* fb, const char* bhe,
                                const char* proc_name);
int tengine_vm_process_file(TEngineVM* ctx, FileBuffer* fb, const char* fname);
int tengine_vm_process_string(TEngineVM* ctx, FileBuffer* fb, const char* code);

#endif
