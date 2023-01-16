#ifndef LL_H
#define LL_H

#include "defs.h"

typedef struct LLNode {
    struct LLNode* next;
    uptr_t          data;
} LLNode;

typedef struct LL {
    LLNode* head;
    u32_t   size;
} LL;

typedef void (*func_on_el_t)(uptr_t);

LL   ll_create();
void ll_clear(LL* ll, func_on_el_t destroy_el);

void    ll_add(LL* ll, uptr_t data);
void    ll_add_tail(LL* ll, uptr_t data);
LLNode* ll_pop(LL* ll);
LLNode* ll_getref(LL* ll, u32_t i);

void ll_invert(LL* ll);
void ll_foreach(LL* ll, func_on_el_t f);

void ll_print(LL* ll, func_on_el_t print_el);

#endif
