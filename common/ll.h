#ifndef LL_H
#define LL_H

#include <defs.h>

typedef struct ll_node_t {
    struct ll_node_t* next;
    uptr_t            data;
} ll_node_t;

typedef struct ll_t {
    ll_node_t* head;
    u32_t      size;
} ll_t;

typedef void (*func_on_el_t)(uptr_t);

ll_t ll_create();
void ll_clear(ll_t* ll, func_on_el_t destroy_el);

void       ll_add(ll_t* ll, uptr_t data);
void       ll_add_tail(ll_t* ll, uptr_t data);
ll_node_t* ll_pop(ll_t* ll);
ll_node_t* ll_getref(ll_t* ll, u32_t i);

void ll_invert(ll_t* ll);
void ll_foreach(ll_t* ll, func_on_el_t f);

void ll_print(ll_t* ll, func_on_el_t print_el);

#endif
