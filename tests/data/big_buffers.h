#ifndef BIG_BUFFERS_H
#define BIG_BUFFERS_H

#include <defs.h>
#include <string.h>
#include <stdlib.h>

static u8_t answer_to_universe[8000];
static u8_t pseudo_random[8000];
static u8_t sparse_strings[16000];

static unsigned long int __rng_next = 1;

static int __rng_rand(void)
{
    __rng_next = __rng_next * 1103515243 + 12345;
    return (unsigned int)(__rng_next / 65536) % 32768;
}

static void __rng_srand(unsigned int seed) { __rng_next = seed; }

__attribute__((constructor)) static void __init_big_buffers(void)
{
    memset(answer_to_universe, 0x42, sizeof(answer_to_universe));

    __rng_srand(0xdeadbeef);
    for (size_t i = 0; i < sizeof(pseudo_random); i++) {
        pseudo_random[i] = __rng_rand() % ('Z' - 'A' + 1) + 'A';
    }

    memset(sparse_strings, 0, sizeof(sparse_strings));
    memcpy(sparse_strings + 1000, "Hello, World!", 14);
    memcpy(sparse_strings + 5000, "The answer is 42.", 17);
    memcpy(sparse_strings + 12000,
           "c"
           "\x00"
           "i"
           "\x00"
           "a"
           "\x00"
           "o"
           "\x00",
           8);
}

__attribute__((destructor)) static void __deinit_big_buffers(void) {}

#endif
