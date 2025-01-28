#ifndef TENGINE_SCOPE_H
#define TENGINE_SCOPE_H

#include <map.h>
#include "value.h"

typedef struct Scope {
    map* filevars;
    map* locals;
} Scope;

Scope*        Scope_new(void);
void          Scope_free(Scope* s);
TEngineValue* Scope_get_filevar(Scope* s, const char* name);
TEngineValue* Scope_get_local(Scope* s, const char* name);
TEngineValue* Scope_get_anyvar(Scope* s, const char* name);
void Scope_add_filevar(Scope* s, const char* name, TEngineValue* value);
void Scope_add_local(Scope* s, const char* name, TEngineValue* value);
map* Scope_free_and_get_filevars(Scope* s);
TEngineValue* Scope_free_and_get_result(Scope* s);

#endif
