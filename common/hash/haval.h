/*
 *  haval.h
 *
 *  HAVAL, a one-way hashing algorithm with variable length of output
 *  (Yuliang Zheng, Josef Pieprzyk, Jennifer Seberry).
 *
 *  HAVAL is parameterized on two axes: the digest length (128, 160, 192, 224
 *  or 256 bits) and the number of passes (3, 4 or 5), for 15 variants in
 *  total. All 15 are exposed here.
 *
 *  Derived from the sph HAVAL implementation.
 *  Copyright (c) 2007-2010 Projet RNRT SAPHIR. See haval.c for the full
 *  license.
 */

#ifndef HAVAL_H
#define HAVAL_H

#include <defs.h>

#define HAVAL_128_DIGEST_LENGTH 16
#define HAVAL_160_DIGEST_LENGTH 20
#define HAVAL_192_DIGEST_LENGTH 24
#define HAVAL_224_DIGEST_LENGTH 28
#define HAVAL_256_DIGEST_LENGTH 32

/* Streaming hash state.
 *
 *  - state holds the 8-word chaining value.
 *  - olen is the digest length in 32-bit words (4, 5, 6, 7 or 8).
 *  - passes is 3, 4 or 5. Both are folded into the padding tail, so a digest
 *    is bound to the exact variant that produced it. */
typedef struct {
    u32_t    state[8];
    u8_t     buffer[128];
    u64_t    count; /* total message bytes fed so far */
    unsigned olen;
    unsigned passes;
} HavalCtx;

void haval_128_3_init(HavalCtx* ctx);
void haval_128_4_init(HavalCtx* ctx);
void haval_128_5_init(HavalCtx* ctx);
void haval_160_3_init(HavalCtx* ctx);
void haval_160_4_init(HavalCtx* ctx);
void haval_160_5_init(HavalCtx* ctx);
void haval_192_3_init(HavalCtx* ctx);
void haval_192_4_init(HavalCtx* ctx);
void haval_192_5_init(HavalCtx* ctx);
void haval_224_3_init(HavalCtx* ctx);
void haval_224_4_init(HavalCtx* ctx);
void haval_224_5_init(HavalCtx* ctx);
void haval_256_3_init(HavalCtx* ctx);
void haval_256_4_init(HavalCtx* ctx);
void haval_256_5_init(HavalCtx* ctx);

void haval_update(HavalCtx* ctx, const u8_t* data, u64_t len);
void haval_final(u8_t* digest, HavalCtx* ctx);

#endif /* HAVAL_H */
