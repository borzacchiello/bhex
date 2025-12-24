#ifndef SHA3_H
#define SHA3_H

#include <defs.h>

/* -------------------------------------------------------------------------
 * Works when compiled for either 32-bit or 64-bit targets, optimized for
 * 64 bit.
 *
 * Canonical implementation of Init/Update/Finalize for SHA-3 byte input.
 *
 * SHA3-256, SHA3-384, SHA-512 are implemented. SHA-224 can easily be added.
 *
 * Based on code from http://keccak.noekeon.org/ .
 *
 * I place the code that I wrote into public domain, free to use.
 *
 * I would appreciate if you give credits to this work if you used it to
 * write or test * your code.
 *
 * Aug 2015. Andrey Jivsov. crypto@brainhub.org
 * ---------------------------------------------------------------------- */

/* 'Words' here refers to u64_t */
#define SHA3_KECCAK_SPONGE_WORDS (((1600) / 8 /*bits to byte*/) / sizeof(u64_t))
typedef struct sha3_context_ {
    u64_t saved; /* the portion of the input message that we
                  * didn't consume yet */
    union {      /* Keccak's state */
        u64_t s[SHA3_KECCAK_SPONGE_WORDS];
        u8_t  sb[SHA3_KECCAK_SPONGE_WORDS * 8];
    } u;
    u32_t bitsize;       /* desired hash size in bits */
    u32_t byteIndex;     /* 0..7--the next byte after the set one
                          * (starts from 0; 0--none are buffered) */
    u32_t wordIndex;     /* 0..24--the next word to integrate input
                          * (starts from 0) */
    u32_t capacityWords; /* the double size of the hash output in
                          * words (e.g. 16 for Keccak 512) */
} sha3_context;

enum SHA3_FLAGS { SHA3_FLAGS_NONE = 0, SHA3_FLAGS_KECCAK = 1 };

enum SHA3_RETURN { SHA3_RETURN_OK = 0, SHA3_RETURN_BAD_PARAMS = 1 };
typedef enum SHA3_RETURN sha3_return_t;

#define SHA3_128_DIGEST_LENGTH 16
#define SHA3_224_DIGEST_LENGTH 28
#define SHA3_256_DIGEST_LENGTH 32
#define SHA3_384_DIGEST_LENGTH 48
#define SHA3_512_DIGEST_LENGTH 64

void SHA3Init(sha3_context*, u32_t bitSize);
void SHA3Update(sha3_context*, const u8_t* bufIn, u32_t len);
void SHA3Finalize(u8_t* hash, sha3_context*);

enum SHA3_FLAGS SHA3SetFlags(sha3_context*, enum SHA3_FLAGS flags);

#define SHA3_128_Init(ctx) SHA3Init(ctx, SHA3_128_DIGEST_LENGTH * 8)
#define SHA3_224_Init(ctx) SHA3Init(ctx, SHA3_224_DIGEST_LENGTH * 8)
#define SHA3_256_Init(ctx) SHA3Init(ctx, SHA3_256_DIGEST_LENGTH * 8)
#define SHA3_384_Init(ctx) SHA3Init(ctx, SHA3_384_DIGEST_LENGTH * 8)
#define SHA3_512_Init(ctx) SHA3Init(ctx, SHA3_512_DIGEST_LENGTH * 8)

/* Single-call hashing */
void SHA3Hash(u32_t bitSize, enum SHA3_FLAGS flags, const void* in,
              u32_t inBytes, void* out,
              u32_t outBytes); /* up to bitSize/8; truncation OK */

#endif
