#include <stdlib.h>
#include <stdio.h>

#include <ll.h>
#include <alloc.h>

#ifndef TEST
#define TEST(name) test_##name
#endif

static int ll_check_eq(ll_t* ll, uptr_t* arr, size_t size)
{
    ll_node_t* curr = ll->head;
    u32_t      i    = 0;
    while (curr) {
        if (i >= size)
            return 0;
        if (curr->data != arr[i])
            return 0;
        curr = curr->next;
        i++;
    }
    return 1;
}

int TEST(add)()
{
    ll_t ll = ll_create();
    ll_add(&ll, 0);
    ll_add(&ll, 1);
    ll_add(&ll, 2);

    uptr_t exp[] = {2, 1, 0};
    int    r = ll_check_eq(&ll, (uptr_t*)&exp, sizeof(exp) / sizeof(uptr_t));

    ll_clear(&ll, NULL);
    return r;
}

int TEST(add_tail)()
{
    ll_t ll = ll_create();
    ll_add_tail(&ll, 0);
    ll_add_tail(&ll, 1);
    ll_add_tail(&ll, 2);

    uptr_t exp[] = {0, 1, 2};
    int    r = ll_check_eq(&ll, (uptr_t*)&exp, sizeof(exp) / sizeof(uptr_t));

    ll_clear(&ll, NULL);
    return r;
}

int TEST(getref_contained)()
{
    ll_t ll = ll_create();
    ll_add(&ll, 0);
    ll_add(&ll, 1);
    ll_add(&ll, 2);

    ll_node_t* d = ll_getref(&ll, 1);
    int        r = d && d->data == 1;

    ll_clear(&ll, NULL);
    return r;
}

int TEST(getref_not_contained)()
{
    ll_t ll = ll_create();
    ll_add(&ll, 0);
    ll_add(&ll, 1);
    ll_add(&ll, 2);

    ll_node_t* d = ll_getref(&ll, 3);
    int        r = !d;

    ll_clear(&ll, NULL);
    return r;
}

int TEST(getref_first)()
{
    ll_t ll = ll_create();
    ll_add(&ll, 0);
    ll_add(&ll, 1);
    ll_add(&ll, 2);

    ll_node_t* d = ll_getref(&ll, 0);
    int        r = d && d->data == 2;

    ll_clear(&ll, NULL);
    return r;
}

int TEST(getref_last)()
{
    ll_t ll = ll_create();
    ll_add(&ll, 0);
    ll_add(&ll, 1);
    ll_add(&ll, 2);

    ll_node_t* d = ll_getref(&ll, ll.size - 1);
    int        r = d && d->data == 0;

    ll_clear(&ll, NULL);
    return r;
}

int TEST(pop_with_el)()
{
    ll_t ll = ll_create();
    ll_add(&ll, 0);
    ll_add(&ll, 1);
    ll_add(&ll, 2);

    ll_node_t* e = ll_pop(&ll);
    int        r = e && e->data == 2;

    bhex_free(e);
    ll_clear(&ll, NULL);
    return r;
}

int TEST(pop_without_el)()
{
    ll_t       ll = ll_create();
    ll_node_t* e  = ll_pop(&ll);
    int        r  = !e;

    ll_clear(&ll, NULL);
    return r;
}

int TEST(invert)()
{
    ll_t ll = ll_create();
    ll_add(&ll, 0);
    ll_add(&ll, 1);
    ll_add(&ll, 2);
    ll_invert(&ll);

    uptr_t exp[] = {0, 1, 2};
    int    r = ll_check_eq(&ll, (uptr_t*)&exp, sizeof(exp) / sizeof(uptr_t));

    ll_clear(&ll, NULL);
    return r;
}
