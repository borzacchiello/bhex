// Copyright (c) 2022-2026, bageyelet

#ifndef TEST_H
#define TEST_H

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <defs.h>

typedef int (*test_uptr_t)();

typedef struct test_t {
    const char* name;
    test_uptr_t fptr;
} test_t;

// The tests are meant to be independent of one another: nothing may depend on
// having run after (or before) anything else. Setting BHEX_TESTS_SEED to a
// number runs them in a shuffled order derived from it, which is how that
// property gets checked -- a suite that only passes in one order has a bug.
#define TESTS_SHUFFLE(tests, order, n)                                         \
    do {                                                                       \
        for (u32_t k = 0; k < (n); ++k)                                        \
            (order)[k] = k;                                                    \
        const char* seed_s = getenv("BHEX_TESTS_SEED");                        \
        if (seed_s == NULL)                                                    \
            break;                                                             \
        unsigned seed = (unsigned)strtoul(seed_s, NULL, 0);                    \
        printf("[+] shuffling tests with seed %u\n", seed);                    \
        for (u32_t k = (n) - 1; k > 0; --k) {                                  \
            u32_t j    = (u32_t)(rand_r(&seed) % (k + 1));                     \
            u32_t tmp  = (order)[k];                                           \
            (order)[k] = (order)[j];                                           \
            (order)[j] = tmp;                                                  \
        }                                                                      \
    } while (0)

// Wall clock milliseconds, for the BHEX_TESTS_TIMING report
static inline double tests_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

#define TESTS_MAIN_BODY(tests)                                                 \
    u32_t       ntests   = 0;                                                  \
    u32_t       nsucc    = 0;                                                  \
    u32_t       nskipped = 0;                                                  \
    u32_t       i;                                                             \
    const u32_t ntot  = sizeof(tests) / sizeof(test_t);                        \
    u32_t*      order = malloc(ntot * sizeof(u32_t));                          \
    if (order == NULL)                                                         \
        return 1;                                                              \
    /* BHEX_TESTS_TIMING=1 prints how long every test took, slowest first */   \
    const int timing = getenv("BHEX_TESTS_TIMING") != NULL;                    \
    double*   times  = timing ? calloc(ntot, sizeof(double)) : NULL;           \
    if (timing && times == NULL)                                               \
        return 1;                                                              \
    TESTS_SHUFFLE(tests, order, ntot);                                         \
    for (u32_t o = 0; o < ntot; ++o) {                                         \
        i = order[o];                                                          \
        if (argc > 1 && strstr(tests[i].name, argv[1]) == NULL)                \
            continue;                                                          \
        reset_global_state();                                                  \
        ntests += 1;                                                           \
        double t0 = timing ? tests_now_ms() : 0;                               \
        int    r  = tests[i].fptr();                                           \
        if (timing)                                                            \
            times[i] = tests_now_ms() - t0;                                    \
        if (r == TEST_FAILED) {                                                \
            printf("[+] %s... \033[91mFAIL\033[0m\n", tests[i].name);          \
        } else if (r == TEST_SKIPPED) {                                        \
            nskipped += 1;                                                     \
        } else {                                                               \
            nsucc += 1;                                                        \
        }                                                                      \
    }                                                                          \
    free(order);                                                               \
    if (timing) {                                                              \
        printf("\n[+] test durations, slowest first:\n");                      \
        for (u32_t a = 0; a < ntot; ++a) {                                     \
            u32_t worst = ntot;                                                \
            for (u32_t b = 0; b < ntot; ++b)                                   \
                if (times[b] > 0 &&                                            \
                    (worst == ntot || times[b] > times[worst]))                \
                    worst = b;                                                 \
            if (worst == ntot)                                                 \
                break;                                                         \
            printf("    %9.2f ms  %s\n", times[worst], tests[worst].name);     \
            times[worst] = -1;                                                 \
        }                                                                      \
    }                                                                          \
    free(times);                                                               \
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
