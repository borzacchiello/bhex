#include "ll.h"
#include "alloc.h"

#include <stdio.h>

LL ll_create()
{
    LL ll = {.head = NULL, .size = 0};
    return ll;
}

void ll_clear(LL* ll, func_on_el_t destroy_el)
{
    LLNode* curr = ll->head;
    while (curr != NULL) {
        LLNode* tmp = curr->next;
        if (destroy_el)
            destroy_el(curr->data);
        bhex_free(curr);
        curr = tmp;
    }

    ll->head = NULL;
    ll->size = 0;
}

void ll_add(LL* ll, uintptr_t data)
{
    LLNode* node = bhex_malloc(sizeof(LLNode));
    node->next   = ll->head;
    node->data   = data;

    ll->head = node;
    ll->size++;
}

void ll_add_tail(LL* ll, uintptr_t data)
{
    LLNode* node = bhex_malloc(sizeof(LLNode));
    node->next   = NULL;
    node->data   = data;
    ll->size++;

    if (ll->head == NULL) {
        ll->head = node;
        return;
    }

    LLNode* curr = ll->head;
    while (curr->next != NULL) {
        curr = curr->next;
    }
    curr->next = node;
}

LLNode* ll_pop(LL* ll)
{
    if (ll->head == NULL)
        return NULL;

    LLNode* r = ll->head;
    ll->head  = ll->head->next;
    ll->size--;
    return r;
}

LLNode* ll_getref(LL* ll, uint32_t i)
{
    LLNode* curr = ll->head;
    while (i != 0) {
        if (curr == NULL)
            return NULL;
        curr = curr->next;
        i--;
    }
    return curr;
}

void ll_invert(LL* ll)
{
    LLNode* prev = NULL;
    LLNode* curr = ll->head;

    while (curr) {
        LLNode* tmp = curr->next;
        curr->next  = prev;
        prev        = curr;
        curr        = tmp;
    }
    ll->head = prev;
}

void ll_foreach(LL* ll, func_on_el_t f)
{
    LLNode* curr = ll->head;
    while (curr) {
        f(curr->data);
        curr = curr->next;
    }
}

void ll_print(LL* ll, func_on_el_t print_el)
{
    LLNode* curr = ll->head;
    while (curr) {
        if (print_el) {
            print_el(curr->data);
        } else {
            printf("%lx", curr->data);
        }
        printf("\nV\n");
        curr = curr->next;
    }
    printf("nil\n");
}
