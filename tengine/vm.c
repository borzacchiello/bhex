#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <alloc.h>
#include <log.h>

#include "interpreter.h"
#include "filebuffer.h"
#include "scope.h"
#include "map.h"
#include "ast.h"
#include "vm.h"

static ASTCtx* tengine_vm_process_imported(TEngineVM* vm, const char* bhe)
{
    if (!map_contains(vm->templates, bhe)) {
        error("no such template file '%s'", bhe);
        return NULL;
    }
    return map_get(vm->templates, bhe);
}

TEngineVM* tengine_vm_create(const char** dirs)
{
    tengine_interpreter_set_fmt_type(FMT_TERM);

    TEngineVM* ctx = bhex_calloc(sizeof(TEngineVM));
    ctx->templates = map_create();
    map_set_dispose(ctx->templates, (void (*)(void*))ASTCtx_delete);

    char tmp[1024];

    const char** curr = dirs;
    while (*curr) {
        const char* dirpath = *curr;
        DIR*        dir     = opendir(dirpath);
        if (dir == NULL) {
            curr++;
            continue;
        }

        struct dirent* entry;
        while ((entry = readdir(dir)) != NULL) {
            // look for "*.bhe" files
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0)
                continue;
            size_t d_namelen = strlen(entry->d_name);
            if (d_namelen < 4 ||
                strcmp(entry->d_name + (d_namelen - 4), ".bhe") != 0)
                continue;

            memset(tmp, 0, sizeof(tmp));
            snprintf(tmp, sizeof(tmp) - 1, "%s/%s", dirpath, entry->d_name);

            // Remove extension
            entry->d_name[d_namelen - 4] = '\0';
            if (map_contains(ctx->templates, entry->d_name)) {
                warning("template '%s' already loaded, skipping file '%s'",
                        entry->d_name, tmp);
                continue;
            }

            ASTCtx* ast = tengine_parse_filename(tmp);
            if (ast == NULL) {
                // Invalid bhe file
                warning("template '%s' invalid, skipping file '%s'",
                        entry->d_name, tmp);
                continue;
            }

            // Remove extension
            entry->d_name[d_namelen - 4] = '\0';
            map_set(ctx->templates, entry->d_name, ast);
            // info("loaded template '%s' from '%s'", entry->d_name, tmp);
        }

        closedir(dir);
        curr++;
    }

    tengine_interpreter_set_imported_types_callback(
        (imported_cb_t)tengine_vm_process_imported, ctx);
    return ctx;
}

void tengine_vm_set_fmt_type(fmt_t t) { tengine_interpreter_set_fmt_type(t); }

int tengine_vm_add_template(TEngineVM* ctx, const char* name, const char* path)
{
    if (map_contains(ctx->templates, name)) {
        warning("template '%s' already loaded, overwriting template '%s'",
                name);
    }

    ASTCtx* ast = tengine_parse_filename(path);
    if (ast == NULL) {
        // Invalid bhe file
        warning("template @ '%s' invalid", path);
        return 1;
    }

    map_set(ctx->templates, name, ast);
    return 0;
}

void tengine_vm_destroy(TEngineVM* ctx)
{
    tengine_interpreter_set_imported_types_callback(NULL, NULL);
    map_destroy(ctx->templates);
    bhex_free(ctx);
}

void tengine_vm_iter_templates(TEngineVM* ctx,
                               void (*cb)(const char* name, ASTCtx* ast))
{
    for (const char* key = map_first(ctx->templates); key != NULL;
         key             = map_next(ctx->templates, key)) {
        ASTCtx* ast = map_get(ctx->templates, key);
        cb(key, ast);
    }
}

void tengine_vm_iter_structs(TEngineVM* ctx,
                             void (*cb)(const char* bhe, const char* name,
                                        ASTCtx* ast))
{
    for (const char* key = map_first(ctx->templates); key != NULL;
         key             = map_next(ctx->templates, key)) {
        ASTCtx* ast = map_get(ctx->templates, key);
        for (const char* str = map_first(ast->structs); str != NULL;
             str             = map_next(ast->structs, str)) {
            cb(key, str, ast);
        }
    }
}

void tengine_vm_iter_named_procs(TEngineVM* ctx,
                                 void (*cb)(const char* bhe, const char* name,
                                            ASTCtx* ast))
{
    for (const char* key = map_first(ctx->templates); key != NULL;
         key             = map_next(ctx->templates, key)) {
        ASTCtx* ast = map_get(ctx->templates, key);
        for (const char* str = map_first(ast->named_procs); str != NULL;
             str             = map_next(ast->named_procs, str)) {
            cb(key, str, ast);
        }
    }
}

int tengine_vm_has_template(TEngineVM* ctx, const char* bhe)
{
    return map_contains(ctx->templates, bhe);
}

int tengine_vm_has_bhe_struct(TEngineVM* ctx, const char* bhe,
                              const char* struct_name)
{
    if (!map_contains(ctx->templates, bhe))
        return 0;

    ASTCtx* ast = map_get(ctx->templates, bhe);
    if (!map_contains(ast->structs, struct_name))
        return 0;
    return 1;
}

int tengine_vm_has_bhe_proc(TEngineVM* ctx, const char* bhe,
                            const char* proc_name)
{
    if (!map_contains(ctx->templates, bhe))
        return 0;

    ASTCtx* ast = map_get(ctx->templates, bhe);
    if (!map_contains(ast->named_procs, proc_name))
        return 0;
    return 1;
}

int tengine_vm_process_bhe(TEngineVM* ctx, FileBuffer* fb, const char* bhe)
{
    if (!map_contains(ctx->templates, bhe))
        return 1;

    ASTCtx* ast = map_get(ctx->templates, bhe);
    if (!ast->proc) {
        error("'%s' has not proc", bhe);
        return 1;
    }
    return tengine_interpreter_process_ast(fb, ast);
}

int tengine_vm_process_bhe_struct(TEngineVM* ctx, FileBuffer* fb,
                                  const char* bhe, const char* struct_name)
{
    if (!map_contains(ctx->templates, bhe))
        return 1;

    ASTCtx* ast = map_get(ctx->templates, bhe);
    if (!map_contains(ast->structs, struct_name))
        return 1;
    return tengine_interpreter_process_ast_struct(fb, ast, struct_name);
}

int tengine_vm_process_bhe_proc(TEngineVM* ctx, FileBuffer* fb, const char* bhe,
                                const char* proc_name)
{
    if (!map_contains(ctx->templates, bhe))
        return 1;

    ASTCtx* ast = map_get(ctx->templates, bhe);
    if (!map_contains(ast->named_procs, proc_name))
        return 1;
    return tengine_interpreter_process_ast_named_proc(fb, ast, proc_name);
}

int tengine_vm_process_file(TEngineVM* ctx, FileBuffer* fb, const char* fname)
{
    return tengine_interpreter_process_filename(fb, fname);
}

int tengine_vm_process_string(TEngineVM* ctx, FileBuffer* fb, const char* code)
{
    u64_t orig_off = fb->off;

    size_t prog_size = strlen(code) + 32;
    char*  prog      = bhex_calloc(prog_size);
    snprintf(prog, prog_size - 1, "proc { %s }", code);

    Scope* scope = tengine_interpreter_run_on_string(fb, prog);
    if (!scope) {
        bhex_free(prog);
        fb->off = orig_off;
        return 1;
    }

    Scope_free(scope);
    bhex_free(prog);
    fb->off = orig_off;
    return 0;
}
