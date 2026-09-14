// Copyright (c) 2022-2026, bageyelet

/*
 *  XXH3, by Yann Collet (BSD-2-Clause): the third-generation xxHash, faster
 *  than XXH32 and XXH64 and much better behaved on short inputs. It produces
 *  either 64 or 128 bits of the same computation.
 *
 *  As with the older variants the digest is the canonical, big-endian
 *  representation of the value; for the 128-bit one that is the high half
 *  first, which is what xxhsum prints.
 */

#ifndef XXH3_H
#define XXH3_H

#include <stddef.h>
#include <defs.h>

#define XXH3_64_DIGEST_LENGTH  8
#define XXH3_128_DIGEST_LENGTH 16

#define XXH3_ACC_NB             8
#define XXH3_INTERNALBUFFER_LEN 256

typedef struct Xxh3Ctx {
    u64_t acc[XXH3_ACC_NB];
    u64_t total_len;
    u64_t nb_stripes_so_far; // position inside the current block of stripes
    u8_t  buffer[XXH3_INTERNALBUFFER_LEN];
    u32_t buffered;
    int   is_128;
} Xxh3Ctx;

void xxh3_64_init(Xxh3Ctx* ctx);
void xxh3_128_init(Xxh3Ctx* ctx);

void xxh3_update(Xxh3Ctx* ctx, const u8_t* data, size_t len);
void xxh3_final(u8_t* out, Xxh3Ctx* ctx);

#endif
