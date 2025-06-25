#ifndef BIG_BUFFERS_H
#define BIG_BUFFERS_H

#include <defs.h>
#include <string.h>

static u8_t answer_to_universe[8000];

__attribute__((constructor)) static void __init_big_buffers(void)
{
    memset(answer_to_universe, 0x42, sizeof(answer_to_universe));
}

__attribute__((destructor)) static void __deinit_big_buffers(void) {}

#endif
