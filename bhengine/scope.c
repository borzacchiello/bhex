// Copyright (c) 2022-2026, bageyelet

#include "scope.h"
#include "value.h"
#include <alloc.h>

Scope* Scope_new(void)
{
    Scope* s    = bhex_calloc(sizeof(Scope));
    s->locals   = map_create();
    s->filevars = map_create();
    s->parent   = NULL;
    map_set_dispose(s->locals, (void (*)(void*))BHEngineValue_release);
    map_set_dispose(s->filevars, (void (*)(void*))BHEngineValue_release);
    return s;
}

Scope* Scope_push(Scope* parent)
{
    Scope* s  = Scope_new();
    s->parent = parent;
    return s;
}

Scope* Scope_pop(Scope* child)
{
    Scope* parent = child->parent;
    map_destroy(child->locals);
    map_destroy(child->filevars);
    bhex_free(child);
    return parent;
}

void Scope_free(Scope* s)
{
    if (!s)
        return;

    map_destroy(s->locals);
    map_destroy(s->filevars);
    bhex_free(s);
}

BHEngineValue* Scope_get_filevar(Scope* s, const char* name)
{
    while (s != NULL) {
        BHEngineValue* v = map_get_or_null(s->filevars, name);
        if (v != NULL)
            return v;
        s = s->parent;
    }
    return NULL;
}

BHEngineValue* Scope_get_local(Scope* s, const char* name)
{
    while (s != NULL) {
        BHEngineValue* v = map_get_or_null(s->locals, name);
        if (v != NULL)
            return v;
        s = s->parent;
    }
    return NULL;
}

BHEngineValue* Scope_get_anyvar(Scope* s, const char* name)
{
    BHEngineValue* v = Scope_get_filevar(s, name);
    if (v == NULL)
        return Scope_get_local(s, name);
    return v;
}

void Scope_add_filevar(Scope* s, const char* name, BHEngineValue* value)
{
    // File variables always go to the root (fn/struct/proc) scope so that
    // conditional field declarations inside if/while blocks remain accessible
    // in the enclosing struct or function body.
    while (s->parent != NULL)
        s = s->parent;
    map_set(s->filevars, name, value);
}

void Scope_add_local(Scope* s, const char* name, BHEngineValue* value)
{
    map_set(s->locals, name, value);
}

void Scope_update_local(Scope* s, const char* name, BHEngineValue* value)
{
    while (s != NULL) {
        if (map_contains(s->locals, name)) {
            map_set(s->locals, name, value);
            return;
        }
        s = s->parent;
    }
}

map* Scope_free_and_get_filevars(Scope* s)
{
    map_destroy(s->locals);
    map* r = s->filevars;
    bhex_free(s);
    return r;
}

map* Scope_free_and_get_locals(Scope* s)
{
    map_destroy(s->filevars);
    map* r = s->locals;
    bhex_free(s);
    return r;
}

BHEngineValue* Scope_free_and_get_result(Scope* s)
{
    BHEngineValue* r = NULL;
    if (map_contains(s->locals, "result"))
        r = map_remove(s->locals, "result");

    Scope_free(s);
    return r;
}
