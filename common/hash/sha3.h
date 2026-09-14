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

/* The original Keccak, as submitted to the SHA-3 competition: the same sponge,
 * with the padding NIST replaced on standardisation (0x01 instead of 0x06).
 * Software written before FIPS 202, Ethereum included, calls this one "SHA-3",
 * so the two have to be told apart rather than aliased. */
void KECCAKInit(sha3_context*, u32_t bitSize);

#define KECCAK_224_Init(ctx) KECCAKInit(ctx, SHA3_224_DIGEST_LENGTH * 8)
#define KECCAK_256_Init(ctx) KECCAKInit(ctx, SHA3_256_DIGEST_LENGTH * 8)
#define KECCAK_384_Init(ctx) KECCAKInit(ctx, SHA3_384_DIGEST_LENGTH * 8)
#define KECCAK_512_Init(ctx) KECCAKInit(ctx, SHA3_512_DIGEST_LENGTH * 8)

/* SHAKE128 and SHAKE256, the two extendable-output functions of FIPS 202.
 * Same sponge and same rates as SHA3-128 and SHA3-256, with the suffix 1111
 * (0x1f once padded) and an output of any length: the finalize squeezes as
 * many blocks as it is asked for.
 *
 * An XOF has no natural digest size, so the registry names the length it
 * wants: "shake128-256" is SHAKE128 squeezed to 256 bits. */
#define SHAKE128_Init(ctx) SHA3Init(ctx, 128)
#define SHAKE256_Init(ctx) SHA3Init(ctx, 256)

void SHAKEFinalize(u8_t* out, u32_t outBytes, sha3_context*);

void SHAKE128_256Final(u8_t* out, sha3_context*);
void SHAKE256_512Final(u8_t* out, sha3_context*);

/* Single-call hashing */
void SHA3Hash(u32_t bitSize, enum SHA3_FLAGS flags, const void* in,
              u32_t inBytes, void* out,
              u32_t outBytes); /* up to bitSize/8; truncation OK */

#endif
