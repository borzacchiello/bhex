// Copyright (c) 2022-2026, bageyelet

/*
 *  Streebog, GOST R 34.11-2012 (RFC 6986), in its 256 and 512 bit forms.
 *
 *  The Russian standard hash function, and the one that replaced the
 *  GOST R 34.11-94 of gost.h: software of Russian origin written since 2012
 *  uses this one, and the two answer differently, so a digest has to say
 *  which of them produced it.
 */

#ifndef STREEBOG_H
#define STREEBOG_H

#include <stddef.h>
#include <defs.h>

#define STREEBOG_256_DIGEST_LENGTH 32
#define STREEBOG_512_DIGEST_LENGTH 64

#define STREEBOG_BLOCK_SIZE 64

typedef struct StreebogCtx {
    // the 512-bit values of the standard, each held as eight little-endian
    // words: h is the state, N counts the bits and Sigma sums the blocks
    u64_t h[8];
    u64_t N[8];
    u64_t Sigma[8];

    u8_t  buffer[STREEBOG_BLOCK_SIZE];
    u32_t buffered;
    u32_t digest_bits; // 256 or 512
} StreebogCtx;

void streebog_256_init(StreebogCtx* ctx);
void streebog_512_init(StreebogCtx* ctx);

void streebog_update(StreebogCtx* ctx, const u8_t* data, size_t len);
void streebog_final(u8_t* out, StreebogCtx* ctx);

#endif
