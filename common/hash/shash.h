/*
 *  shash.h
 *
 *  Spectral Hash (s-hash), a SHA-3 round-1 candidate.
 *  Streaming wrapper adapted to the bhex hashing API.
 */

#ifndef SHASH_H
#define SHASH_H

#include <defs.h>

#define SHASH_256_DIGEST_LENGTH 32
#define SHASH_512_DIGEST_LENGTH 64

/* A single 4-bit "cell"; stored one per byte. */
typedef u8_t scell;
typedef u8_t pcell;

typedef struct sh_s_prism {
    scell cell[4][4][8];
} sh_s_prism;

typedef struct sh_h_prism {
    scell cell[4][4][8];
} sh_h_prism;

typedef struct sh_p_prism {
    pcell cell[4][4][8];
} sh_p_prism;

typedef struct SpectralHashCtx {
    int        hashbitlen;
    sh_s_prism sPrism;
    sh_p_prism pPrism;
    sh_h_prism hPrism;
    u8_t       remainder[64];
    int        remainderbitlen;
    u64_t      mesagelen;
    int        started;
} SpectralHashCtx;

void shash_256_init(SpectralHashCtx* ctx);
void shash_512_init(SpectralHashCtx* ctx);
void shash_update(SpectralHashCtx* ctx, const u8_t* data, u64_t len);
void shash_final(u8_t* digest, SpectralHashCtx* ctx);

#endif /* SHASH_H */
