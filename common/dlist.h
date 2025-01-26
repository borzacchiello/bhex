#ifndef DLIST_H
#define DLIST_H

#include <defs.h>

typedef struct DList {
    void** data;
    u64_t  size;
    u64_t  capacity;
} DList;

DList* DList_new();
void   DList_destroy(DList* l, void (*dispose)(void*));
void   DList_init(DList* l);
void   DList_deinit(DList* l);

void DList_add(DList* l, void* item);
void DList_foreach(DList* l, void (*f)(void*));

#endif
