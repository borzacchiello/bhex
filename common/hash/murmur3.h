// Copyright (c) 2022-2026, bageyelet

/*
 *  MurmurHash3, by Austin Appleby (public domain).
 *
 *  Not a cryptographic hash: it is the one that turns up in hash tables,
 *  bloom filters and the indices of a good many file formats.
 *
 *  Two of the three variants are here: "x86_32", by far the most used, and
 *  "x64_128". They are different functions, not different encodings of one --
 *  the author tuned each for its word size -- so a value has to say which one
 *  produced it.
 *
 *  The digest is the hash written big-endian, i.e. the way the number reads,
 *  and for the 128-bit variant h1 comes first. Implementations that hand back
 *  raw bytes (mmh3.hash_bytes and friends) write the same words little-endian
 *  instead, so the halves look byte-swapped against these.
 */

#ifndef MURMUR3_H
#define MURMUR3_H

#include <stddef.h>
#include <defs.h>

#define MURMUR3_32_DIGEST_LENGTH  4
#define MURMUR3_128_DIGEST_LENGTH 16

typedef struct Murmur3Ctx {
    u64_t h1;
    u64_t h2;
    u64_t len;        // total bytes fed so far
    u8_t  buf[16];    // a block that is not complete yet
    u32_t buflen;     //
    u32_t block_size; // 4 for x86_32, 16 for x64_128
    int   is_128;
} Murmur3Ctx;

void murmur3_x86_32_init(Murmur3Ctx* ctx);
void murmur3_x64_128_init(Murmur3Ctx* ctx);

void murmur3_update(Murmur3Ctx* ctx, const u8_t* data, size_t len);
void murmur3_final(u8_t* out, Murmur3Ctx* ctx);

#endif
