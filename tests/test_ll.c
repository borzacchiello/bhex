#include <stdlib.h>
#include <stdio.h>

#include "test.h"
#include "../ll.h"
#include "../alloc.h"

static int check_eq(LL* ll, uptr_t* arr, size_t size)
{
    LLNode* curr = ll->head;
    u32_t   i    = 0;
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

static int test_add()
{
    LL ll = ll_create();
    ll_add(&ll, 0);
    ll_add(&ll, 1);
    ll_add(&ll, 2);

    uptr_t exp[] = {2, 1, 0};
    int    r     = check_eq(&ll, (uptr_t*)&exp, sizeof(exp) / sizeof(uptr_t));

    ll_clear(&ll, NULL);
    return r;
}

static int test_add_tail()
{
    LL ll = ll_create();
    ll_add_tail(&ll, 0);
    ll_add_tail(&ll, 1);
    ll_add_tail(&ll, 2);

    uptr_t exp[] = {0, 1, 2};
    int    r     = check_eq(&ll, (uptr_t*)&exp, sizeof(exp) / sizeof(uptr_t));

    ll_clear(&ll, NULL);
    return r;
}

static int test_getref_contained()
{
    LL ll = ll_create();
    ll_add(&ll, 0);
    ll_add(&ll, 1);
    ll_add(&ll, 2);

    LLNode* d = ll_getref(&ll, 1);
    int     r = d && d->data == 1;

    ll_clear(&ll, NULL);
    return r;
}

static int test_getref_not_contained()
{
    LL ll = ll_create();
    ll_add(&ll, 0);
    ll_add(&ll, 1);
    ll_add(&ll, 2);

    LLNode* d = ll_getref(&ll, 3);
    int     r = !d;

    ll_clear(&ll, NULL);
    return r;
}

static int test_getref_first()
{
    LL ll = ll_create();
    ll_add(&ll, 0);
    ll_add(&ll, 1);
    ll_add(&ll, 2);

    LLNode* d = ll_getref(&ll, 0);
    int     r = d && d->data == 2;

    ll_clear(&ll, NULL);
    return r;
}

static int test_getref_last()
{
    LL ll = ll_create();
    ll_add(&ll, 0);
    ll_add(&ll, 1);
    ll_add(&ll, 2);

    LLNode* d = ll_getref(&ll, ll.size - 1);
    int     r = d && d->data == 0;

    ll_clear(&ll, NULL);
    return r;
}

static int test_pop_with_el()
{
    LL ll = ll_create();
    ll_add(&ll, 0);
    ll_add(&ll, 1);
    ll_add(&ll, 2);

    LLNode* e = ll_pop(&ll);
    int     r = e && e->data == 2;

    bhex_free(e);
    ll_clear(&ll, NULL);
    return r;
}

static int test_pop_without_el()
{
    LL      ll = ll_create();
    LLNode* e  = ll_pop(&ll);
    int     r  = !e;

    ll_clear(&ll, NULL);
    return r;
}

static int test_invert()
{
    LL ll = ll_create();
    ll_add(&ll, 0);
    ll_add(&ll, 1);
    ll_add(&ll, 2);
    ll_invert(&ll);

    uptr_t exp[] = {0, 1, 2};
    int    r     = check_eq(&ll, (uptr_t*)&exp, sizeof(exp) / sizeof(uptr_t));

    ll_clear(&ll, NULL);
    return r;
}

static test_t tests[] = {
    {.name = "add", .fptr = &test_add},
    {.name = "add_tail", .fptr = &test_add_tail},
    {.name = "test_getref_contained", .fptr = &test_getref_contained},
    {.name = "test_getref_not_contained", .fptr = &test_getref_not_contained},
    {.name = "test_getref_first", .fptr = &test_getref_first},
    {.name = "test_getref_last", .fptr = &test_getref_last},
    {.name = "test_pop_with_el", .fptr = &test_pop_with_el},
    {.name = "test_pop_without_el", .fptr = &test_pop_without_el},
    {.name = "invert", .fptr = &test_invert},
};

int main(int argc, char const* argv[])
{
    RUN_TESTS(tests);
    return 0;
}
