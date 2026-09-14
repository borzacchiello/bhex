// Copyright (c) 2022-2026, bageyelet

/*
 *  FNV-1 and FNV-1a, by Glenn Fowler, Landon Curt Noll and Phong Vo.
 *
 *  Not a cryptographic hash: a multiply and an xor per byte, which is why it
 *  turns up wherever a short hash has to be computed with almost no code --
 *  shellcode resolving imports by name among the rest.
 *
 *  The two differ only in the order of the two operations, and that order is
 *  what makes FNV-1a the one worth reaching for: it mixes the byte in before
 *  the multiply, so the low bits of the input reach the whole word.
 */

#ifndef FNV_H
#define FNV_H

#include <stddef.h>
#include <defs.h>

#define FNV_32_DIGEST_LENGTH 4
#define FNV_64_DIGEST_LENGTH 8

typedef struct FnvCtx {
    u64_t hash;
    u64_t prime;
    u32_t width;     // bytes of the digest: 4 or 8
    int   xor_first; // FNV-1a xors the byte in before multiplying
} FnvCtx;

void fnv1_32_init(FnvCtx* ctx);
void fnv1a_32_init(FnvCtx* ctx);
void fnv1_64_init(FnvCtx* ctx);
void fnv1a_64_init(FnvCtx* ctx);

void fnv_update(FnvCtx* ctx, const u8_t* data, size_t len);

// The digest is the hash written big-endian, which is how FNV values are
// quoted everywhere
void fnv_final(u8_t* out, FnvCtx* ctx);

#endif
