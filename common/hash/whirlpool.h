/*
 *  whirlpool.h
 *
 *  Whirlpool, a 512-bit hash function built on a dedicated block cipher
 *  used in Miyaguchi-Preneel mode (Paulo Barreto, Vincent Rijmen).
 *
 *  This is the final, tweaked version of the algorithm (2003), the one
 *  standardized by ISO/IEC 10118-3.
 *
 *  Derived from the RHash implementation.
 *  Copyright (c) 2009 Aleksey Kravchenko. See whirlpool.c for the full
 *  license.
 */

#ifndef WHIRLPOOL_H
#define WHIRLPOOL_H

#include <defs.h>

#define WHIRLPOOL_DIGEST_LENGTH 64

/* Streaming hash state.
 *
 *  - hash holds the eight 64-bit state words.
 *  - count is a 64-bit byte counter. The algorithm specifies a 256-bit one,
 *    but the extra bits are only reachable by messages larger than 2^64 bits
 *    (2 EiB), so the padding tail stores the low 64 bits and zeroes the rest.
 */
typedef struct {
    u64_t hash[8];
    u8_t  buffer[64];
    u64_t count; /* total message bytes fed so far */
} WhirlpoolCtx;

void whirlpool_init(WhirlpoolCtx* ctx);
void whirlpool_update(WhirlpoolCtx* ctx, const u8_t* data, u64_t len);
void whirlpool_final(u8_t* digest, WhirlpoolCtx* ctx);

#endif /* WHIRLPOOL_H */
