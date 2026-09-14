// Copyright (c) 2022-2026, bageyelet
//
// XXH32 and XXH64, following the reference xxhash.h by Yann Collet. The
// reference is one header of dispatch and vector paths; this is the scalar
// arithmetic it falls back to, driven one block at a time so that a file can
// be fed through it.
//
// The seed is 0 throughout: a seeded xxHash is a keyed function, and the 'hh'
// command has no key to give it.

#include "xxhash.h"

#include <string.h>

#define XXH_ROTL32(x, r) (((x) << (r)) | ((x) >> (32 - (r))))
#define XXH_ROTL64(x, r) (((x) << (r)) | ((x) >> (64 - (r))))

#define XXH_PRIME32_1 0x9E3779B1U
#define XXH_PRIME32_2 0x85EBCA77U
#define XXH_PRIME32_3 0xC2B2AE3DU
#define XXH_PRIME32_4 0x27D4EB2FU
#define XXH_PRIME32_5 0x165667B1U

#define XXH_PRIME64_1 0x9E3779B185EBCA87ULL
#define XXH_PRIME64_2 0xC2B2AE3D27D4EB4FULL
#define XXH_PRIME64_3 0x165667B19E3779F9ULL
#define XXH_PRIME64_4 0x85EBCA77C2B2AE63ULL
#define XXH_PRIME64_5 0x27D4EB2F165667C5ULL

static u32_t read32_le(const u8_t* p)
{
    return (u32_t)p[0] | ((u32_t)p[1] << 8) | ((u32_t)p[2] << 16) |
           ((u32_t)p[3] << 24);
}

static u64_t read64_le(const u8_t* p)
{
    return (u64_t)read32_le(p) | ((u64_t)read32_le(p + 4) << 32);
}

static u32_t xxh32_round(u32_t acc, u32_t input)
{
    acc += input * XXH_PRIME32_2;
    acc = XXH_ROTL32(acc, 13);
    acc *= XXH_PRIME32_1;
    return acc;
}

static u32_t xxh32_avalanche(u32_t h)
{
    h ^= h >> 15;
    h *= XXH_PRIME32_2;
    h ^= h >> 13;
    h *= XXH_PRIME32_3;
    h ^= h >> 16;
    return h;
}

static u64_t xxh64_round(u64_t acc, u64_t input)
{
    acc += input * XXH_PRIME64_2;
    acc = XXH_ROTL64(acc, 31);
    acc *= XXH_PRIME64_1;
    return acc;
}

static u64_t xxh64_merge_round(u64_t acc, u64_t val)
{
    val = xxh64_round(0, val);
    acc ^= val;
    acc = acc * XXH_PRIME64_1 + XXH_PRIME64_4;
    return acc;
}

static u64_t xxh64_avalanche(u64_t h)
{
    h ^= h >> 33;
    h *= XXH_PRIME64_2;
    h ^= h >> 29;
    h *= XXH_PRIME64_3;
    h ^= h >> 32;
    return h;
}

void xxh32_init(XxhCtx* ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->block_size = 16;
    ctx->is_64      = 0;
    // the accumulators of a zero seed
    ctx->acc[0] = (u32_t)(XXH_PRIME32_1 + XXH_PRIME32_2);
    ctx->acc[1] = XXH_PRIME32_2;
    ctx->acc[2] = 0;
    ctx->acc[3] = (u32_t)(0 - XXH_PRIME32_1);
}

void xxh64_init(XxhCtx* ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->block_size = 32;
    ctx->is_64      = 1;
    ctx->acc[0]     = XXH_PRIME64_1 + XXH_PRIME64_2;
    ctx->acc[1]     = XXH_PRIME64_2;
    ctx->acc[2]     = 0;
    ctx->acc[3]     = 0 - XXH_PRIME64_1;
}

static void xxh_block(XxhCtx* ctx, const u8_t* p)
{
    if (ctx->is_64) {
        for (int i = 0; i < 4; ++i)
            ctx->acc[i] = xxh64_round(ctx->acc[i], read64_le(p + i * 8));
    } else {
        for (int i = 0; i < 4; ++i)
            ctx->acc[i] = xxh32_round((u32_t)ctx->acc[i], read32_le(p + i * 4));
    }
}

void xxh_update(XxhCtx* ctx, const u8_t* data, size_t len)
{
    ctx->total_len += len;

    if (ctx->buflen > 0) {
        size_t want = ctx->block_size - ctx->buflen;
        if (want > len)
            want = len;
        memcpy(ctx->buf + ctx->buflen, data, want);
        ctx->buflen += (u32_t)want;
        data += want;
        len -= want;
        if (ctx->buflen < ctx->block_size)
            return;
        xxh_block(ctx, ctx->buf);
        ctx->buflen = 0;
    }

    while (len >= ctx->block_size) {
        xxh_block(ctx, data);
        data += ctx->block_size;
        len -= ctx->block_size;
    }

    if (len > 0) {
        memcpy(ctx->buf, data, len);
        ctx->buflen = (u32_t)len;
    }
}

static u32_t xxh32_digest(XxhCtx* ctx)
{
    const u8_t* p   = ctx->buf;
    size_t      len = ctx->buflen;
    u32_t       h;

    // the accumulators only mean anything once a whole block has gone through
    // them; a message shorter than one never touched them
    if (ctx->total_len >= 16)
        h = XXH_ROTL32((u32_t)ctx->acc[0], 1) +
            XXH_ROTL32((u32_t)ctx->acc[1], 7) +
            XXH_ROTL32((u32_t)ctx->acc[2], 12) +
            XXH_ROTL32((u32_t)ctx->acc[3], 18);
    else
        h = (u32_t)ctx->acc[2] + XXH_PRIME32_5;

    h += (u32_t)ctx->total_len;

    while (len >= 4) {
        h += read32_le(p) * XXH_PRIME32_3;
        p += 4;
        h = XXH_ROTL32(h, 17) * XXH_PRIME32_4;
        len -= 4;
    }
    while (len > 0) {
        h += (*p++) * XXH_PRIME32_5;
        h = XXH_ROTL32(h, 11) * XXH_PRIME32_1;
        --len;
    }
    return xxh32_avalanche(h);
}

static u64_t xxh64_digest(XxhCtx* ctx)
{
    const u8_t* p   = ctx->buf;
    size_t      len = ctx->buflen;
    u64_t       h;

    if (ctx->total_len >= 32) {
        h = XXH_ROTL64(ctx->acc[0], 1) + XXH_ROTL64(ctx->acc[1], 7) +
            XXH_ROTL64(ctx->acc[2], 12) + XXH_ROTL64(ctx->acc[3], 18);
        h = xxh64_merge_round(h, ctx->acc[0]);
        h = xxh64_merge_round(h, ctx->acc[1]);
        h = xxh64_merge_round(h, ctx->acc[2]);
        h = xxh64_merge_round(h, ctx->acc[3]);
    } else {
        h = ctx->acc[2] + XXH_PRIME64_5;
    }

    h += ctx->total_len;

    while (len >= 8) {
        h ^= xxh64_round(0, read64_le(p));
        p += 8;
        h = XXH_ROTL64(h, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
        len -= 8;
    }
    if (len >= 4) {
        h ^= (u64_t)read32_le(p) * XXH_PRIME64_1;
        p += 4;
        h = XXH_ROTL64(h, 23) * XXH_PRIME64_2 + XXH_PRIME64_3;
        len -= 4;
    }
    while (len > 0) {
        h ^= (*p++) * XXH_PRIME64_5;
        h = XXH_ROTL64(h, 11) * XXH_PRIME64_1;
        --len;
    }
    return xxh64_avalanche(h);
}

void xxh_final(u8_t* out, XxhCtx* ctx)
{
    if (ctx->is_64) {
        u64_t h = xxh64_digest(ctx);
        for (int i = 0; i < 8; ++i)
            out[i] = (u8_t)(h >> (8 * (7 - i)));
    } else {
        u32_t h = xxh32_digest(ctx);
        for (int i = 0; i < 4; ++i)
            out[i] = (u8_t)(h >> (8 * (3 - i)));
    }
}
