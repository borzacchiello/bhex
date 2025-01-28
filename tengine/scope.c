#include "scope.h"
#include "value.h"
#include <alloc.h>

Scope* Scope_new(void)
{
    Scope* s    = bhex_calloc(sizeof(Scope));
    s->locals   = map_create();
    s->filevars = map_create();
    map_set_dispose(s->locals, (void (*)(void*))TEngineValue_free);
    map_set_dispose(s->filevars, (void (*)(void*))TEngineValue_free);
    return s;
}

void Scope_free(Scope* s)
{
    if (!s)
        return;

    map_destroy(s->locals);
    map_destroy(s->filevars);
    bhex_free(s);
}

TEngineValue* Scope_get_filevar(Scope* s, const char* name)
{
    if (!map_contains(s->filevars, name))
        return NULL;
    return map_get(s->filevars, name);
}

TEngineValue* Scope_get_local(Scope* s, const char* name)
{
    if (!map_contains(s->locals, name))
        return NULL;
    return map_get(s->locals, name);
}

TEngineValue* Scope_get_anyvar(Scope* s, const char* name)
{
    TEngineValue* v = Scope_get_filevar(s, name);
    if (v == NULL)
        return Scope_get_local(s, name);
    return v;
}

void Scope_add_filevar(Scope* s, const char* name, TEngineValue* value)
{
    map_set(s->filevars, name, value);
}

void Scope_add_local(Scope* s, const char* name, TEngineValue* value)
{
    map_set(s->locals, name, value);
}

map* Scope_free_and_get_filevars(Scope* s)
{
    // Destroy only the locals
    map_destroy(s->locals);
    map* r = s->filevars;
    bhex_free(s);
    return r;
}

TEngineValue* Scope_free_and_get_result(Scope* s)
{
    TEngineValue* r = NULL;
    if (map_contains(s->locals, "result"))
        r = map_remove(s->locals, "result");

    Scope_free(s);
    return r;
}
