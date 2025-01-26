#include <string.h>

#include <dlist.h>
#include <alloc.h>

#define INITIAL_CAPACITY 8

DList* DList_new(void)
{
    DList* l = bhex_calloc(sizeof(DList));
    DList_init(l);
    return l;
}

void DList_destroy(DList* l, void (*dispose)(void*))
{
    if (dispose)
        DList_foreach(l, dispose);
    DList_deinit(l);
    bhex_free(l);
}

void DList_init(DList* l)
{
    l->size     = 0;
    l->capacity = INITIAL_CAPACITY;
    l->data     = bhex_calloc(sizeof(void*) * l->capacity);
}

void DList_deinit(DList* l)
{
    memset(l->data, 0, l->capacity * sizeof(void*));
    bhex_free(l->data);
    memset(l, 0, sizeof(DList));
}

void DList_add(DList* l, void* item)
{
    if (l->size == l->capacity) {
        l->capacity = l->capacity * 3 / 2;
        l->data     = bhex_realloc(l->data, sizeof(void*) * l->capacity);
    }
    l->data[l->size++] = item;
}

void DList_foreach(DList* l, void (*f)(void*))
{
    for (u64_t i = 0; i < l->size; ++i) {
        f(l->data[i]);
    }
}
