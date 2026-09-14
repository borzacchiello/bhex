// Copyright (c) 2022-2026, bageyelet

/*
 *  xxHash, by Yann Collet (BSD-2-Clause).
 *
 *  Not a cryptographic hash: it is the fast checksum that containers reach
 *  for, so it is the one to try when a header carries four or eight bytes
 *  that are not a CRC -- an LZ4 frame checksums its content with XXH32, a
 *  Zstandard one with XXH64.
 *
 *  The digest is the canonical representation of the value, which xxHash
 *  defines as big-endian (see XXH32_canonical_t); that is what xxhsum prints.
 */

#ifndef XXHASH_H
#define XXHASH_H

#include <stddef.h>
#include <defs.h>

#define XXH32_DIGEST_LENGTH 4
#define XXH64_DIGEST_LENGTH 8

typedef struct XxhCtx {
    u64_t acc[4];
    u64_t total_len;
    u8_t  buf[32];    // a block that is not complete yet
    u32_t buflen;     //
    u32_t block_size; // 16 for XXH32, 32 for XXH64
    int   is_64;
} XxhCtx;

void xxh32_init(XxhCtx* ctx);
void xxh64_init(XxhCtx* ctx);

void xxh_update(XxhCtx* ctx, const u8_t* data, size_t len);
void xxh_final(u8_t* out, XxhCtx* ctx);

#endif
