#ifndef TEST_H
#define TEST_H

#include <stdio.h>

typedef int (*test_ptr_t)();

typedef struct test_t {
    const char* name;
    test_ptr_t  fptr;
} test_t;

#define RUN_TESTS(tests)                                                       \
    do {                                                                       \
        uint32_t i;                                                            \
        for (i = 0; i < sizeof(tests) / sizeof(test_t); ++i) {                 \
            int r = tests[i].fptr();                                           \
            if (r)                                                             \
                printf("OK: test %s\n", tests[i].name);                        \
            else                                                               \
                printf("KO: test %s\n", tests[i].name);                        \
        }                                                                      \
    } while (0)

#endif
