#ifndef TEST_H
#define TEST_H

#include <defs.h>

typedef int (*test_uptr_t)();

typedef struct test_t {
    const char* name;
    test_uptr_t fptr;
} test_t;

#define TESTS_MAIN_BODY(tests)                                                 \
    u32_t ntests = 0;                                                          \
    u32_t nsucc  = 0;                                                          \
    u32_t i;                                                                   \
    for (i = 0; i < sizeof(tests) / sizeof(test_t); ++i) {                     \
        ntests += 1;                                                           \
        int r = tests[i].fptr();                                               \
        if (!r)                                                                \
            printf("[!] test %s failed\n", tests[i].name);                     \
        else                                                                   \
            nsucc += 1;                                                        \
    }                                                                          \
    printf("[+] %u/%u tests succeeded\n", nsucc, ntests);                      \
    return nsucc != ntests;

#define TEST_FAILED    0
#define TEST_SUCCEEDED 1

#endif
