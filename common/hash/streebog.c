// Copyright (c) 2022-2026, bageyelet
//
// Streebog (GOST R 34.11-2012, RFC 6986).
//
// The tables below are the precomputed A-matrix multiplication and the round
// constants of the reference implementation by Alexey Degtyarev, which is
// distributed under the 2-clause BSD licence:
//
//   Copyright (c) 2013, Alexey Degtyarev <alexey@renatasystems.org>.
//   All rights reserved.
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions are
//   met:
//   1. Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the following disclaimer.
//   2. Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in the
//      documentation and/or other materials provided with the distribution.
//   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
//   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED.
//
// The code around them is written against RFC 6986 rather than ported: the
// reference keeps its 512-bit values in a union of words and bytes and so
// needs a separate path per byte order, while everything here goes in and out
// of the state through explicit little-endian loads and stores.

#include "streebog.h"

#include <string.h>

#include "streebog_tables.h"

static u64_t read64_le(const u8_t* p)
{
    u64_t r = 0;
    for (int i = 0; i < 8; ++i)
        r |= (u64_t)p[i] << (8 * i);
    return r;
}

static void write64_le(u8_t* p, u64_t v)
{
    for (int i = 0; i < 8; ++i)
        p[i] = (u8_t)(v >> (8 * i));
}

// out = LPS(x ^ y), the substitution, permutation and linear transform the
// standard applies together, read straight out of the precomputed table
static void xlps(const u64_t* x, const u64_t* y, u64_t* out)
{
    u64_t r[8];
    u64_t t[8];

    for (int i = 0; i < 8; ++i)
        r[i] = x[i] ^ y[i];

    for (int j = 0; j < 8; ++j) {
        u64_t v = 0;
        for (int k = 0; k < 8; ++k)
            v ^= Ax[k][(r[k] >> (j * 8)) & 0xFF];
        t[j] = v;
    }

    memcpy(out, t, sizeof(t));
}

static void xor512(const u64_t* x, const u64_t* y, u64_t* out)
{
    for (int i = 0; i < 8; ++i)
        out[i] = x[i] ^ y[i];
}

// 512-bit addition, the words being little-endian: the carry walks up from
// the low one
static void add512(u64_t* x, const u64_t* y)
{
    u32_t carry = 0;
    for (int i = 0; i < 8; ++i) {
        u64_t const left = x[i];
        u64_t const sum  = left + y[i] + carry;
        if (sum != left)
            carry = (sum < left);
        x[i] = sum;
    }
}

// The compression function g(N, h, m)
static void g(u64_t* h, const u64_t* N, const u64_t* m)
{
    u64_t K[8], data[8];

    xlps(h, N, data);

    // E(K, m)
    memcpy(K, data, sizeof(K));
    xlps(K, m, data);

    for (int i = 0; i < 11; ++i) {
        xlps(K, C[i], K);
        xlps(K, data, data);
    }

    xlps(K, C[11], K);
    xor512(K, data, data);

    xor512(data, h, data);
    xor512(data, m, h);
}

static void streebog_init(StreebogCtx* ctx, u32_t digest_bits)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->digest_bits = digest_bits;
    if (digest_bits == 256)
        for (int i = 0; i < 8; ++i)
            ctx->h[i] = 0x0101010101010101ULL;
}

void streebog_256_init(StreebogCtx* ctx) { streebog_init(ctx, 256); }

void streebog_512_init(StreebogCtx* ctx) { streebog_init(ctx, 512); }

static void block(StreebogCtx* ctx, const u8_t* data)
{
    u64_t m[8];
    for (int i = 0; i < 8; ++i)
        m[i] = read64_le(data + i * 8);

    g(ctx->h, ctx->N, m);

    {
        // N counts the bits consumed, so a whole block adds 512
        u64_t const block_bits[8] = {512, 0, 0, 0, 0, 0, 0, 0};
        add512(ctx->N, block_bits);
    }
    add512(ctx->Sigma, m);
}

void streebog_update(StreebogCtx* ctx, const u8_t* data, size_t len)
{
    if (ctx->buffered) {
        size_t chunk = STREEBOG_BLOCK_SIZE - ctx->buffered;
        if (chunk > len)
            chunk = len;
        memcpy(ctx->buffer + ctx->buffered, data, chunk);
        ctx->buffered += (u32_t)chunk;
        data += chunk;
        len -= chunk;
        if (ctx->buffered == STREEBOG_BLOCK_SIZE) {
            block(ctx, ctx->buffer);
            ctx->buffered = 0;
        }
    }

    while (len >= STREEBOG_BLOCK_SIZE) {
        block(ctx, data);
        data += STREEBOG_BLOCK_SIZE;
        len -= STREEBOG_BLOCK_SIZE;
    }

    if (len) {
        memcpy(ctx->buffer, data, len);
        ctx->buffered = (u32_t)len;
    }
}

void streebog_final(u8_t* out, StreebogCtx* ctx)
{
    u64_t const zero[8] = {0};
    u64_t       tail_bits[8];
    u64_t       m[8];
    u8_t        padded[STREEBOG_BLOCK_SIZE];

    // the last block is padded with a single 1 bit and then zeroes
    memcpy(padded, ctx->buffer, ctx->buffered);
    memset(padded + ctx->buffered, 0, STREEBOG_BLOCK_SIZE - ctx->buffered);
    if (ctx->buffered < STREEBOG_BLOCK_SIZE)
        padded[ctx->buffered] = 0x01;

    for (int i = 0; i < 8; ++i)
        m[i] = read64_le(padded + i * 8);

    g(ctx->h, ctx->N, m);

    memset(tail_bits, 0, sizeof(tail_bits));
    tail_bits[0] = (u64_t)ctx->buffered << 3;
    add512(ctx->N, tail_bits);
    add512(ctx->Sigma, m);

    // the two closing rounds, over the bit count and over the block sum
    g(ctx->h, zero, ctx->N);
    g(ctx->h, zero, ctx->Sigma);

    // the 256-bit digest is the upper half of the state
    if (ctx->digest_bits == 256) {
        for (int i = 0; i < 4; ++i)
            write64_le(out + i * 8, ctx->h[4 + i]);
    } else {
        for (int i = 0; i < 8; ++i)
            write64_le(out + i * 8, ctx->h[i]);
    }
}
