/*
 *  snefru.h
 *
 *  Snefru, the Xerox Secure Hash Function (Ralph C. Merkle).
 *  Streaming wrapper around the 2.5a reference implementation, adapted to the
 *  bhex hashing API.
 *
 *  Copyright (c) Xerox Corporation 1989. All rights reserved. See snefru.c for
 *  the full license; these notices must be retained.
 */

#ifndef SNEFRU_H
#define SNEFRU_H

#include <defs.h>

#define SNEFRU_128_DIGEST_LENGTH 16
#define SNEFRU_256_DIGEST_LENGTH 32

/* Streaming hash state.
 *
 *  - state holds the 16-word Merkle-chaining block: words [0..output_words-1]
 *    carry the running digest, the rest are filled from the input stream.
 *  - output_words is 4 (snefru-128) or 8 (snefru-256). */
typedef struct {
    u32_t state[16];
    u8_t  buffer[48]; /* up to one full chunk: (16 - output_words) * 4 bytes */
    int   buffered;
    int   output_words;
    int   security_level;
    u64_t total_bits;
} SnefruCtx;

void snefru_128_init(SnefruCtx* ctx);
void snefru_256_init(SnefruCtx* ctx);
void snefru_update(SnefruCtx* ctx, const u8_t* data, u64_t len);
void snefru_final(u8_t* digest, SnefruCtx* ctx);

#endif /* SNEFRU_H */
