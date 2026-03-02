#ifndef TEST_H
#define TEST_H

#include <defs.h>

typedef int (*test_uptr_t)();

typedef struct test_t {
    const char* name;
    test_uptr_t fptr;
} test_t;

#define TESTS_MAIN_BODY(tests)                                                 \
    u32_t ntests   = 0;                                                        \
    u32_t nsucc    = 0;                                                        \
    u32_t nskipped = 0;                                                        \
    u32_t i;                                                                   \
    for (i = 0; i < sizeof(tests) / sizeof(test_t); ++i) {                     \
        if (argc > 1 && strstr(tests[i].name, argv[1]) == NULL)                \
            continue;                                                          \
        reset_global_state();                                                  \
        printf("[+] %s... ", tests[i].name);                                   \
        ntests += 1;                                                           \
        int r = tests[i].fptr();                                               \
        if (r == TEST_FAILED)                                                  \
            printf("\033[91mFAIL\033[0m\n");                                   \
        else if (r == TEST_SKIPPED) {                                          \
            nskipped += 1;                                                     \
            printf("\033[93mSKIPPED\033[0m\n");                                \
        } else {                                                               \
            nsucc += 1;                                                        \
            printf("\033[92mOK\033[0m\n");                                     \
        }                                                                      \
    }                                                                          \
    printf("\n[+] %u/%u tests succeeded", nsucc, ntests);                      \
    if (nskipped > 0)                                                          \
        printf(", %u skipped", nskipped);                                      \
    if (nsucc + nskipped < ntests)                                             \
        printf(", %d failed", ntests - nsucc - nskipped);                      \
    printf("\n");                                                              \
    return (nsucc + nskipped) != ntests;

#define TEST_FAILED    0
#define TEST_SUCCEEDED 1
#define TEST_SKIPPED   2

#define ASSERT(cond)                                                           \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("[!] assertion (" #cond ") failed\n");                      \
            goto fail;                                                         \
        }                                                                      \
    } while (0)

#endif
