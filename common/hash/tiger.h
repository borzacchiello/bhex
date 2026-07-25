/*
 *  tiger.h
 *
 *  Tiger, a 192-bit hash function designed for 64-bit platforms
 *  (Ross Anderson, Eli Biham).
 *
 *  Two variants are exposed: Tiger (Tiger1), which pads with 0x01, and
 *  Tiger2, which pads with 0x80 as MD4-style functions do. They differ only
 *  in that padding byte, so both produce a 192-bit digest.
 *
 *  Derived from the RHash implementation.
 *  Copyright (c) 2007 Aleksey Kravchenko. See tiger.c for the full license.
 */

#ifndef TIGER_H
#define TIGER_H

#include <defs.h>

#define TIGER_DIGEST_LENGTH 24

/* Streaming hash state.
 *
 *  - hash holds the three 64-bit state words.
 *  - pad is the padding byte that starts the tail (0x01 for Tiger, 0x80 for
 *    Tiger2), which is the only difference between the two variants. */
typedef struct {
    u64_t hash[3];
    u8_t  buffer[64];
    u64_t count; /* total message bytes fed so far */
    u8_t  pad;
} TigerCtx;

void tiger_init(TigerCtx* ctx);
void tiger2_init(TigerCtx* ctx);

void tiger_update(TigerCtx* ctx, const u8_t* data, u64_t len);
void tiger_final(u8_t* digest, TigerCtx* ctx);

#endif /* TIGER_H */
