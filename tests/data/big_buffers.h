#ifndef BIG_BUFFERS_H
#define BIG_BUFFERS_H

#include <defs.h>
#include <string.h>
#include <stdlib.h>

static u8_t answer_to_universe[8000];
static u8_t pseudo_random[8000];

__attribute__((constructor)) static void __init_big_buffers(void)
{
    memset(answer_to_universe, 0x42, sizeof(answer_to_universe));

    srand(0xdeadbeef);
    for (size_t i = 0; i < sizeof(pseudo_random); i++) {
        pseudo_random[i] = rand() % ('Z' - 'A' + 1) + 'A';
    }
}

__attribute__((destructor)) static void __deinit_big_buffers(void) {}

#endif
