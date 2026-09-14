// Copyright (c) 2022-2026, bageyelet

#include "fnv.h"

#define FNV_32_OFFSET_BASIS 0x811c9dc5ULL
#define FNV_32_PRIME        0x01000193ULL
#define FNV_64_OFFSET_BASIS 0xcbf29ce484222325ULL
#define FNV_64_PRIME        0x00000100000001b3ULL

static void fnv_init(FnvCtx* ctx, u64_t basis, u64_t prime, u32_t width,
                     int xor_first)
{
    ctx->hash      = basis;
    ctx->prime     = prime;
    ctx->width     = width;
    ctx->xor_first = xor_first;
}

void fnv1_32_init(FnvCtx* ctx)
{
    fnv_init(ctx, FNV_32_OFFSET_BASIS, FNV_32_PRIME, 4, 0);
}

void fnv1a_32_init(FnvCtx* ctx)
{
    fnv_init(ctx, FNV_32_OFFSET_BASIS, FNV_32_PRIME, 4, 1);
}

void fnv1_64_init(FnvCtx* ctx)
{
    fnv_init(ctx, FNV_64_OFFSET_BASIS, FNV_64_PRIME, 8, 0);
}

void fnv1a_64_init(FnvCtx* ctx)
{
    fnv_init(ctx, FNV_64_OFFSET_BASIS, FNV_64_PRIME, 8, 1);
}

void fnv_update(FnvCtx* ctx, const u8_t* data, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        if (ctx->xor_first) {
            ctx->hash ^= (u64_t)data[i];
            ctx->hash *= ctx->prime;
        } else {
            ctx->hash *= ctx->prime;
            ctx->hash ^= (u64_t)data[i];
        }
        // the 32-bit variants are the same arithmetic modulo 2^32
        if (ctx->width == 4)
            ctx->hash &= 0xffffffffULL;
    }
}

void fnv_final(u8_t* out, FnvCtx* ctx)
{
    for (u32_t i = 0; i < ctx->width; ++i)
        out[i] = (u8_t)(ctx->hash >> (8 * (ctx->width - 1 - i)));
}
