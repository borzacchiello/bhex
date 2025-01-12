#ifndef TEST_H
#define TEST_H

#include <defs.h>
#include <stdio.h>

typedef int (*test_uptr_t)();

typedef struct test_t {
    const char* name;
    test_uptr_t  fptr;
} test_t;

#define RUN_TESTS(tests)                                                       \
    do {                                                                       \
        u32_t i;                                                               \
        for (i = 0; i < sizeof(tests) / sizeof(test_t); ++i) {                 \
            int r = tests[i].fptr();                                           \
            if (r)                                                             \
                printf("OK: test %s\n", tests[i].name);                        \
            else                                                               \
                printf("KO: test %s\n", tests[i].name);                        \
        }                                                                      \
    } while (0)

#endif
