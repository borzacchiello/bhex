// Copyright (c) 2022-2026, bageyelet
//
// Ported from the reference MurmurHash3.cpp, which Austin Appleby placed in
// the public domain. The reference is a one-shot over a whole buffer; this is
// the same arithmetic driven one block at a time, so that a file can be fed
// through it without being held in memory: the only additions are the buffer
// that holds a block until it is complete and the running length, which the
// finalization needs.
//
// The reference reads its blocks with a plain cast, so its results are those
// of a little-endian machine. The loads here are explicitly little-endian:
// same answer there, and the published values on a big-endian one too.

#include "murmur3.h"

#include <string.h>

#define ROTL32(x, r) (((x) << (r)) | ((x) >> (32 - (r))))
#define ROTL64(x, r) (((x) << (r)) | ((x) >> (64 - (r))))

#define C1_32 0xcc9e2d51U
#define C2_32 0x1b873593U

#define C1_64 0x87c37b91114253d5ULL
#define C2_64 0x4cf5ad432745937fULL

static u32_t fmix32(u32_t h)
{
    h ^= h >> 16;
    h *= 0x85ebca6bU;
    h ^= h >> 13;
    h *= 0xc2b2ae35U;
    h ^= h >> 16;
    return h;
}

static u64_t fmix64(u64_t k)
{
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53ULL;
    k ^= k >> 33;
    return k;
}

static u32_t load32_le(const u8_t* p)
{
    return (u32_t)p[0] | ((u32_t)p[1] << 8) | ((u32_t)p[2] << 16) |
           ((u32_t)p[3] << 24);
}

static u64_t load64_le(const u8_t* p)
{
    return (u64_t)load32_le(p) | ((u64_t)load32_le(p + 4) << 32);
}

static void murmur3_init(Murmur3Ctx* ctx, u32_t block_size, int is_128)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->block_size = block_size;
    ctx->is_128     = is_128;
    // the seed is 0: the variants that take one are keyed, and the 'hh'
    // command has no key to give them
}

void murmur3_x86_32_init(Murmur3Ctx* ctx) { murmur3_init(ctx, 4, 0); }

void murmur3_x64_128_init(Murmur3Ctx* ctx) { murmur3_init(ctx, 16, 1); }

static void block_x86_32(Murmur3Ctx* ctx, const u8_t* p)
{
    u32_t h1 = (u32_t)ctx->h1;
    u32_t k1 = load32_le(p);

    k1 *= C1_32;
    k1 = ROTL32(k1, 15);
    k1 *= C2_32;

    h1 ^= k1;
    h1      = ROTL32(h1, 13);
    h1      = h1 * 5 + 0xe6546b64U;
    ctx->h1 = h1;
}

static void block_x64_128(Murmur3Ctx* ctx, const u8_t* p)
{
    u64_t h1 = ctx->h1, h2 = ctx->h2;
    u64_t k1 = load64_le(p);
    u64_t k2 = load64_le(p + 8);

    k1 *= C1_64;
    k1 = ROTL64(k1, 31);
    k1 *= C2_64;
    h1 ^= k1;

    h1 = ROTL64(h1, 27);
    h1 += h2;
    h1 = h1 * 5 + 0x52dce729U;

    k2 *= C2_64;
    k2 = ROTL64(k2, 33);
    k2 *= C1_64;
    h2 ^= k2;

    h2 = ROTL64(h2, 31);
    h2 += h1;
    h2 = h2 * 5 + 0x38495ab5U;

    ctx->h1 = h1;
    ctx->h2 = h2;
}

static void block(Murmur3Ctx* ctx, const u8_t* p)
{
    if (ctx->is_128)
        block_x64_128(ctx, p);
    else
        block_x86_32(ctx, p);
}

void murmur3_update(Murmur3Ctx* ctx, const u8_t* data, size_t len)
{
    ctx->len += len;

    // top up a block left over from the previous call
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
        block(ctx, ctx->buf);
        ctx->buflen = 0;
    }

    while (len >= ctx->block_size) {
        block(ctx, data);
        data += ctx->block_size;
        len -= ctx->block_size;
    }

    // what is left is shorter than a block: it is either the tail of the
    // message or the head of a block the next call completes
    if (len > 0) {
        memcpy(ctx->buf, data, len);
        ctx->buflen = (u32_t)len;
    }
}

static void store32_be(u8_t* out, u32_t v)
{
    out[0] = (u8_t)(v >> 24);
    out[1] = (u8_t)(v >> 16);
    out[2] = (u8_t)(v >> 8);
    out[3] = (u8_t)v;
}

static void store64_be(u8_t* out, u64_t v)
{
    store32_be(out, (u32_t)(v >> 32));
    store32_be(out + 4, (u32_t)v);
}

static void final_x86_32(u8_t* out, Murmur3Ctx* ctx)
{
    const u8_t* tail = ctx->buf;
    u32_t       h1   = (u32_t)ctx->h1;
    u32_t       k1   = 0;

    switch (ctx->buflen & 3) {
        case 3:
            k1 ^= (u32_t)tail[2] << 16;
            /* fallthrough */
        case 2:
            k1 ^= (u32_t)tail[1] << 8;
            /* fallthrough */
        case 1:
            k1 ^= (u32_t)tail[0];
            k1 *= C1_32;
            k1 = ROTL32(k1, 15);
            k1 *= C2_32;
            h1 ^= k1;
            break;
        default:
            break;
    }

    h1 ^= (u32_t)ctx->len;
    h1 = fmix32(h1);
    store32_be(out, h1);
}

static void final_x64_128(u8_t* out, Murmur3Ctx* ctx)
{
    const u8_t* tail = ctx->buf;
    u64_t       h1 = ctx->h1, h2 = ctx->h2;
    u64_t       k1 = 0, k2 = 0;

    switch (ctx->buflen & 15) {
        case 15:
            k2 ^= (u64_t)tail[14] << 48;
            /* fallthrough */
        case 14:
            k2 ^= (u64_t)tail[13] << 40;
            /* fallthrough */
        case 13:
            k2 ^= (u64_t)tail[12] << 32;
            /* fallthrough */
        case 12:
            k2 ^= (u64_t)tail[11] << 24;
            /* fallthrough */
        case 11:
            k2 ^= (u64_t)tail[10] << 16;
            /* fallthrough */
        case 10:
            k2 ^= (u64_t)tail[9] << 8;
            /* fallthrough */
        case 9:
            k2 ^= (u64_t)tail[8];
            k2 *= C2_64;
            k2 = ROTL64(k2, 33);
            k2 *= C1_64;
            h2 ^= k2;
            /* fallthrough */
        case 8:
            k1 ^= (u64_t)tail[7] << 56;
            /* fallthrough */
        case 7:
            k1 ^= (u64_t)tail[6] << 48;
            /* fallthrough */
        case 6:
            k1 ^= (u64_t)tail[5] << 40;
            /* fallthrough */
        case 5:
            k1 ^= (u64_t)tail[4] << 32;
            /* fallthrough */
        case 4:
            k1 ^= (u64_t)tail[3] << 24;
            /* fallthrough */
        case 3:
            k1 ^= (u64_t)tail[2] << 16;
            /* fallthrough */
        case 2:
            k1 ^= (u64_t)tail[1] << 8;
            /* fallthrough */
        case 1:
            k1 ^= (u64_t)tail[0];
            k1 *= C1_64;
            k1 = ROTL64(k1, 31);
            k1 *= C2_64;
            h1 ^= k1;
            break;
        default:
            break;
    }

    h1 ^= ctx->len;
    h2 ^= ctx->len;

    h1 += h2;
    h2 += h1;

    h1 = fmix64(h1);
    h2 = fmix64(h2);

    h1 += h2;
    h2 += h1;

    store64_be(out, h1);
    store64_be(out + 8, h2);
}

void murmur3_final(u8_t* out, Murmur3Ctx* ctx)
{
    if (ctx->is_128)
        final_x64_128(out, ctx);
    else
        final_x86_32(out, ctx);
}
