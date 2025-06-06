#include <ll.h>
#include <alloc.h>

#include <stdio.h>

ll_t ll_create(void)
{
    ll_t ll = {.head = NULL, .size = 0};
    return ll;
}

void ll_clear(ll_t* ll, func_on_el_t destroy_el)
{
    ll_node_t* curr = ll->head;
    while (curr != NULL) {
        ll_node_t* tmp = curr->next;
        if (destroy_el)
            destroy_el(curr->data);
        bhex_free(curr);
        curr = tmp;
    }

    ll->head = NULL;
    ll->size = 0;
}

void ll_add(ll_t* ll, uptr_t data)
{
    ll_node_t* node = bhex_malloc(sizeof(ll_node_t));
    node->next      = ll->head;
    node->data      = data;

    ll->head = node;
    ll->size++;
}

void ll_add_tail(ll_t* ll, uptr_t data)
{
    ll_node_t* node = bhex_malloc(sizeof(ll_node_t));
    node->next      = NULL;
    node->data      = data;
    ll->size++;

    if (ll->head == NULL) {
        ll->head = node;
        return;
    }

    ll_node_t* curr = ll->head;
    while (curr->next != NULL) {
        curr = curr->next;
    }
    curr->next = node;
}

ll_node_t* ll_pop(ll_t* ll)
{
    if (ll->head == NULL)
        return NULL;

    ll_node_t* r = ll->head;
    ll->head     = ll->head->next;
    ll->size--;
    return r;
}

ll_node_t* ll_getref(ll_t* ll, u32_t i)
{
    ll_node_t* curr = ll->head;
    while (i != 0) {
        if (curr == NULL)
            return NULL;
        curr = curr->next;
        i--;
    }
    return curr;
}

void ll_invert(ll_t* ll)
{
    ll_node_t* prev = NULL;
    ll_node_t* curr = ll->head;

    while (curr) {
        ll_node_t* tmp = curr->next;
        curr->next     = prev;
        prev           = curr;
        curr           = tmp;
    }
    ll->head = prev;
}

void ll_foreach(ll_t* ll, func_on_el_t f)
{
    ll_node_t* curr = ll->head;
    while (curr) {
        f(curr->data);
        curr = curr->next;
    }
}

void ll_print(ll_t* ll, func_on_el_t print_el)
{
    ll_node_t* curr = ll->head;
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
