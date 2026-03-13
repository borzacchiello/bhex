// Copyright (c) 2022-2026, bageyelet

#ifndef CHECKSUMS_H
#define CHECKSUMS_H

#include <defs.h>

typedef struct checksum_state_t {
    u64_t s1;
    u64_t s2;
    u64_t count;
} checksum_state_t;

typedef struct checksum_algo_t {
    const char* name;
    u8_t        width;   // result width in bits
    u8_t        decimal; // 1 if result is a decimal digit
    checksum_state_t (*init)(void);
    checksum_state_t (*step)(checksum_state_t, const u8_t*, u32_t);
    u32_t (*finalize)(checksum_state_t);
} checksum_algo_t;

u32_t calculate_checksum(const u8_t* buffer, u32_t size,
                         const checksum_algo_t* algo);

const checksum_algo_t* get_checksum_by_name(const char* name);
const char* const*     get_all_checksum_names(void);

#endif
