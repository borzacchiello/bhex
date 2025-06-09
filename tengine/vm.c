#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <alloc.h>
#include <log.h>

#include "interpreter.h"
#include "filebuffer.h"
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

            ASTCtx* ast = tengine_interpreter_parse_filename(tmp);
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

void tengine_vm_destroy(TEngineVM* ctx)
{
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

int tengine_vm_has_template(TEngineVM* ctx, const char* bhe)
{
    return map_contains(ctx->templates, bhe);
}

int tengine_vm_process_bhe(TEngineVM* ctx, FileBuffer* fb, const char* bhe)
{
    if (!map_contains(ctx->templates, bhe))
        return 1;

    ASTCtx* ast = map_get(ctx->templates, bhe);
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

int tengine_vm_process_file(TEngineVM* ctx, FileBuffer* fb, const char* fname)
{
    return tengine_interpreter_process_filename(fb, fname);
}

int tengine_vm_process_string(TEngineVM* ctx, FileBuffer* fb, const char* code)
{
    size_t prog_size = strlen(code) + 32;
    char*  prog      = bhex_calloc(prog_size);
    snprintf(prog, prog_size - 1, "proc { %s ; }", code);

    TEngineInterpreter* e = tengine_interpreter_run_on_string(fb, prog);
    if (!e) {
        bhex_free(prog);
        return 1;
    }

    tengine_interpreter_deinit(e);
    bhex_free(e);
    bhex_free(prog);
    return 0;
}
