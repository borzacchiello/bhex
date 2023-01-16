#ifndef LL_H
#define LL_H

#include <stdint.h>

typedef struct LLNode {
    struct LLNode* next;
    uintptr_t      data;
} LLNode;

typedef struct LL {
    LLNode*  head;
    uint32_t size;
} LL;

typedef void(*func_on_el_t)(uintptr_t);

LL   ll_create();
void ll_clear(LL* ll, func_on_el_t destroy_el);

void    ll_add(LL* ll, uintptr_t data);
void    ll_add_tail(LL* ll, uintptr_t data);
LLNode* ll_pop(LL* ll);
LLNode* ll_getref(LL* ll, uint32_t i);

void ll_invert(LL* ll);
void ll_foreach(LL* ll, func_on_el_t f);

void ll_print(LL* ll, func_on_el_t print_el);

#endif
