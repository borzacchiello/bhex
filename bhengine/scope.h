// Copyright (c) 2022-2026, bageyelet

#ifndef TENGINE_SCOPE_H
#define TENGINE_SCOPE_H

#include <map.h>
#include "value.h"

typedef struct Scope {
    map*          filevars;
    map*          locals;
    struct Scope* parent; // NULL for root scopes (proc, fn, struct)
} Scope;

// Create a fresh root scope (no parent). Used for proc, fn, and struct bodies.
Scope* Scope_new(void);

// Push a child scope onto the scope stack.
// Used for if/elif/else and while blocks.
Scope* Scope_push(Scope* parent);

// Pop a child scope from the stack: free child and return its parent.
Scope* Scope_pop(Scope* child);

void           Scope_free(Scope* s);
BHEngineValue* Scope_get_filevar(Scope* s, const char* name);
BHEngineValue* Scope_get_local(Scope* s, const char* name);
BHEngineValue* Scope_get_anyvar(Scope* s, const char* name);
void Scope_add_filevar(Scope* s, const char* name, BHEngineValue* value);

// Declare a new local in the current scope frame.
void Scope_add_local(Scope* s, const char* name, BHEngineValue* value);

// Update an existing local variable, searching up the parent chain.
void Scope_update_local(Scope* s, const char* name, BHEngineValue* value);

map*           Scope_free_and_get_filevars(Scope* s);
map*           Scope_free_and_get_locals(Scope* s);
BHEngineValue* Scope_free_and_get_result(Scope* s);

#endif
