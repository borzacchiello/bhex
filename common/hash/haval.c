/*
 * HAVAL implementation.
 *
 * The HAVAL reference paper is of questionable clarity with regards to
 * some details such as endianness of bits within a byte, bytes within
 * a 32-bit word, or the actual ordering of words within a stream of
 * words. This implementation has been made compatible with the reference
 * implementation available on: http://labs.calyptix.com/haval.php
 *
 * Derived from the sph implementation by Thomas Pornin. The sph version
 * generates the 3-, 4- and 5-pass cores as three fully unrolled copies via
 * repeated inclusion of a helper file; this adaptation keeps the compact
 * table-driven form instead (word-order permutations MP2..MP5 and round
 * constants RK2..RK5), so a single core serves all three pass counts with
 * the pass count carried in the context.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#include "haval.h"

#include <string.h>

#define HAVAL_BLOCK_SIZE 128

static u32_t rotr32(u32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static u32_t rotl32(u32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static u32_t dec32le(const u8_t* p)
{
    return (u32_t)p[0] | ((u32_t)p[1] << 8) | ((u32_t)p[2] << 16) |
           ((u32_t)p[3] << 24);
}

static void enc32le(u8_t* p, u32_t v)
{
    p[0] = (u8_t)v;
    p[1] = (u8_t)(v >> 8);
    p[2] = (u8_t)(v >> 16);
    p[3] = (u8_t)(v >> 24);
}

/* The five boolean functions, in the optimized forms used by sph. Arguments
 * are named after the reference paper's x6..x0. */

static u32_t f1(u32_t x6, u32_t x5, u32_t x4, u32_t x3, u32_t x2, u32_t x1,
                u32_t x0)
{
    return (x1 & (x0 ^ x4)) ^ (x2 & x5) ^ (x3 & x6) ^ x0;
}

static u32_t f2(u32_t x6, u32_t x5, u32_t x4, u32_t x3, u32_t x2, u32_t x1,
                u32_t x0)
{
    return (x2 & ((x1 & ~x3) ^ (x4 & x5) ^ x6 ^ x0)) ^ (x4 & (x1 ^ x5)) ^
           ((x3 & x5) ^ x0);
}

static u32_t f3(u32_t x6, u32_t x5, u32_t x4, u32_t x3, u32_t x2, u32_t x1,
                u32_t x0)
{
    return (x3 & ((x1 & x2) ^ x6 ^ x0)) ^ (x1 & x4) ^ (x2 & x5) ^ x0;
}

static u32_t f4(u32_t x6, u32_t x5, u32_t x4, u32_t x3, u32_t x2, u32_t x1,
                u32_t x0)
{
    return (x3 & ((x1 & x2) ^ (x4 | x6) ^ x5)) ^
           (x4 & ((~x2 & x5) ^ x1 ^ x6 ^ x0)) ^ (x2 & x6) ^ x0;
}

static u32_t f5(u32_t x6, u32_t x5, u32_t x4, u32_t x3, u32_t x2, u32_t x1,
                u32_t x0)
{
    return (x0 & ~((x1 & x2 & x3) ^ x5)) ^ (x1 & x4) ^ (x2 & x5) ^ (x3 & x6);
}

typedef u32_t (*haval_f_t)(u32_t, u32_t, u32_t, u32_t, u32_t, u32_t, u32_t);

static const haval_f_t FN[5] = {f1, f2, f3, f4, f5};

/* Each pass applies one of f1..f5 to a permutation of the state words: the
 * phi permutation, which depends on both the pass number and the total pass
 * count. PERM[passes-3][pass-1] lists the state indices to feed as the f
 * arguments, in argument order (x6 first, x0 last). */
static const u8_t PERM[3][5][7] = {
    /* 3 passes */
    {{1, 0, 3, 5, 6, 2, 4},
     {4, 2, 1, 0, 5, 3, 6},
     {6, 1, 2, 3, 4, 5, 0},
     {0},
     {0}},
    /* 4 passes */
    {{2, 6, 1, 4, 5, 3, 0},
     {3, 5, 2, 0, 1, 6, 4},
     {1, 4, 3, 6, 0, 2, 5},
     {6, 4, 0, 5, 2, 1, 3},
     {0}},
    /* 5 passes */
    {{3, 4, 1, 0, 5, 2, 6},
     {6, 2, 1, 0, 3, 4, 5},
     {2, 6, 0, 4, 3, 1, 5},
     {1, 5, 3, 2, 0, 4, 6},
     {2, 5, 0, 6, 4, 3, 1}},
};

/* Word-order permutations for passes 2..5. Pass 1 reads the message words in
 * order, so it has no table. */
static const u8_t MP[4][32] = {
    {5,  14, 26, 18, 11, 28, 7,  16, 0,  23, 20, 22, 1, 10, 4,  8,
     30, 3,  21, 9,  17, 24, 29, 6,  19, 12, 15, 13, 2, 25, 31, 27},
    {19, 9,  4, 20, 28, 17, 8,  22, 29, 14, 25, 12, 24, 30, 16, 26,
     31, 15, 7, 3,  1,  0,  18, 27, 13, 6,  21, 10, 23, 11, 5,  2},
    {24, 4,  0,  14, 2, 7,  28, 23, 26, 6,  30, 20, 18, 25, 19, 3,
     22, 11, 31, 21, 8, 27, 12, 9,  1,  29, 5,  15, 17, 10, 16, 13},
    {27, 3, 21, 26, 17, 11, 20, 29, 19, 0,  12, 7,  13, 8, 31, 10,
     5,  9, 14, 30, 18, 6,  28, 24, 2,  23, 16, 22, 4,  1, 25, 15},
};

/* Round constants for passes 2..5 (digits of pi). Pass 1 uses zero. */
static const u32_t RK[4][32] = {
    {0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C, 0xC0AC29B7, 0xC97C50DD,
     0x3F84D5B5, 0xB5470917, 0x9216D5D9, 0x8979FB1B, 0xD1310BA6, 0x98DFB5AC,
     0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96, 0xBA7C9045, 0xF12C7F99,
     0x24A19947, 0xB3916CF7, 0x0801F2E2, 0x858EFC16, 0x636920D8, 0x71574E69,
     0xA458FEA3, 0xF4933D7E, 0x0D95748F, 0x728EB658, 0x718BCD58, 0x82154AEE,
     0x7B54A41D, 0xC25A59B5},
    {0x9C30D539, 0x2AF26013, 0xC5D1B023, 0x286085F0, 0xCA417918, 0xB8DB38EF,
     0x8E79DCB0, 0x603A180E, 0x6C9E0E8B, 0xB01E8A3E, 0xD71577C1, 0xBD314B27,
     0x78AF2FDA, 0x55605C60, 0xE65525F3, 0xAA55AB94, 0x57489862, 0x63E81440,
     0x55CA396A, 0x2AAB10B6, 0xB4CC5C34, 0x1141E8CE, 0xA15486AF, 0x7C72E993,
     0xB3EE1411, 0x636FBC2A, 0x2BA9C55D, 0x741831F6, 0xCE5C3E16, 0x9B87931E,
     0xAFD6BA33, 0x6C24CF5C},
    {0x7A325381, 0x28958677, 0x3B8F4898, 0x6B4BB9AF, 0xC4BFE81B, 0x66282193,
     0x61D809CC, 0xFB21A991, 0x487CAC60, 0x5DEC8032, 0xEF845D5D, 0xE98575B1,
     0xDC262302, 0xEB651B88, 0x23893E81, 0xD396ACC5, 0x0F6D6FF3, 0x83F44239,
     0x2E0B4482, 0xA4842004, 0x69C8F04A, 0x9E1F9B5E, 0x21C66842, 0xF6E96C9A,
     0x670C9C61, 0xABD388F0, 0x6A51A0D2, 0xD8542F68, 0x960FA728, 0xAB5133A3,
     0x6EEF0B6C, 0x137A3BE4},
    {0xBA3BF050, 0x7EFB2A98, 0xA1F1651D, 0x39AF0176, 0x66CA593E, 0x82430E88,
     0x8CEE8619, 0x456F9FB4, 0x7D84A5C3, 0x3B8B5EBE, 0xE06F75D8, 0x85C12073,
     0x401A449F, 0x56C16AA6, 0x4ED3AA62, 0x363F7706, 0x1BFEDF72, 0x429B023D,
     0x37D0D724, 0xD00A1248, 0xDB0FEAD3, 0x49F1C09B, 0x075372C9, 0x80991B7B,
     0x25D479D8, 0xF6E8DEF7, 0xE3FE501A, 0xB6794C3B, 0x976CE0BD, 0x04C006BA,
     0xC1A94FB6, 0x409F60C4},
};

/* Compress one 128-byte block into ctx->state. */
static void haval_compress(HavalCtx* ctx, const u8_t* block)
{
    u32_t    in[32];
    u32_t    s[8];
    unsigned pass, i, k;

    for (i = 0; i < 32; i++)
        in[i] = dec32le(block + 4 * i);
    for (i = 0; i < 8; i++)
        s[i] = ctx->state[i];

    for (pass = 1; pass <= ctx->passes; pass++) {
        const u8_t* perm = PERM[ctx->passes - 3][pass - 1];
        haval_f_t   fn   = FN[pass - 1];

        for (i = 0; i < 32; i++) {
            /* Step i updates state word (7 - i) mod 8; the other seven words
             * feed the boolean function, read starting just past it. */
            unsigned t = (7 - i) & 7;
            u32_t    x[7];
            u32_t    v, w, c;

            for (k = 0; k < 7; k++)
                x[k] = s[(k + t + 1) & 7];

            v = fn(x[perm[0]], x[perm[1]], x[perm[2]], x[perm[3]], x[perm[4]],
                   x[perm[5]], x[perm[6]]);

            if (pass == 1) {
                w = in[i];
                c = 0;
            } else {
                w = in[MP[pass - 2][i]];
                c = RK[pass - 2][i];
            }

            s[t] = rotr32(v, 7) + rotr32(s[t], 11) + w + c;
        }
    }

    for (i = 0; i < 8; i++)
        ctx->state[i] += s[i];
}

/* Mixing operation used for 128-bit output tailoring: take byte 0 from a0,
 * byte 1 from a1, byte 2 from a2 and byte 3 from a3, then rotate left by n. */
static u32_t mix128(u32_t a0, u32_t a1, u32_t a2, u32_t a3, int n)
{
    u32_t tmp = (a0 & 0x000000FF) | (a1 & 0x0000FF00) | (a2 & 0x00FF0000) |
                (a3 & 0xFF000000);
    if (n > 0)
        tmp = rotl32(tmp, n);
    return tmp;
}

/* Mixing operations for 160-bit output, one per output word. */

static u32_t mix160_0(u32_t x5, u32_t x6, u32_t x7)
{
    return rotl32((x5 & 0x01F80000) | (x6 & 0xFE000000) | (x7 & 0x0000003F),
                  13);
}

static u32_t mix160_1(u32_t x5, u32_t x6, u32_t x7)
{
    return rotl32((x5 & 0xFE000000) | (x6 & 0x0000003F) | (x7 & 0x00000FC0), 7);
}

static u32_t mix160_2(u32_t x5, u32_t x6, u32_t x7)
{
    return (x5 & 0x0000003F) | (x6 & 0x00000FC0) | (x7 & 0x0007F000);
}

static u32_t mix160_3(u32_t x5, u32_t x6, u32_t x7)
{
    return ((x5 & 0x00000FC0) | (x6 & 0x0007F000) | (x7 & 0x01F80000)) >> 6;
}

static u32_t mix160_4(u32_t x5, u32_t x6, u32_t x7)
{
    return ((x5 & 0x0007F000) | (x6 & 0x01F80000) | (x7 & 0xFE000000)) >> 12;
}

/* Mixing operations for 192-bit output, one per output word. */

static u32_t mix192_0(u32_t x6, u32_t x7)
{
    return rotl32((x6 & 0xFC000000) | (x7 & 0x0000001F), 6);
}

static u32_t mix192_1(u32_t x6, u32_t x7)
{
    return (x6 & 0x0000001F) | (x7 & 0x000003E0);
}

static u32_t mix192_2(u32_t x6, u32_t x7)
{
    return ((x6 & 0x000003E0) | (x7 & 0x0000FC00)) >> 5;
}

static u32_t mix192_3(u32_t x6, u32_t x7)
{
    return ((x6 & 0x0000FC00) | (x7 & 0x001F0000)) >> 10;
}

static u32_t mix192_4(u32_t x6, u32_t x7)
{
    return ((x6 & 0x001F0000) | (x7 & 0x03E00000)) >> 16;
}

static u32_t mix192_5(u32_t x6, u32_t x7)
{
    return ((x6 & 0x03E00000) | (x7 & 0xFC000000)) >> 21;
}

/* Fold the 256-bit chaining value down to the requested digest length. */
static void haval_out(HavalCtx* ctx, u8_t* dst)
{
    u32_t s0 = ctx->state[0], s1 = ctx->state[1], s2 = ctx->state[2],
          s3 = ctx->state[3], s4 = ctx->state[4], s5 = ctx->state[5],
          s6 = ctx->state[6], s7 = ctx->state[7];

    switch (ctx->olen) {
        case 4:
            enc32le(dst, s0 + mix128(s7, s4, s5, s6, 24));
            enc32le(dst + 4, s1 + mix128(s6, s7, s4, s5, 16));
            enc32le(dst + 8, s2 + mix128(s5, s6, s7, s4, 8));
            enc32le(dst + 12, s3 + mix128(s4, s5, s6, s7, 0));
            break;
        case 5:
            enc32le(dst, s0 + mix160_0(s5, s6, s7));
            enc32le(dst + 4, s1 + mix160_1(s5, s6, s7));
            enc32le(dst + 8, s2 + mix160_2(s5, s6, s7));
            enc32le(dst + 12, s3 + mix160_3(s5, s6, s7));
            enc32le(dst + 16, s4 + mix160_4(s5, s6, s7));
            break;
        case 6:
            enc32le(dst, s0 + mix192_0(s6, s7));
            enc32le(dst + 4, s1 + mix192_1(s6, s7));
            enc32le(dst + 8, s2 + mix192_2(s6, s7));
            enc32le(dst + 12, s3 + mix192_3(s6, s7));
            enc32le(dst + 16, s4 + mix192_4(s6, s7));
            enc32le(dst + 20, s5 + mix192_5(s6, s7));
            break;
        case 7:
            enc32le(dst, s0 + ((s7 >> 27) & 0x1F));
            enc32le(dst + 4, s1 + ((s7 >> 22) & 0x1F));
            enc32le(dst + 8, s2 + ((s7 >> 18) & 0x0F));
            enc32le(dst + 12, s3 + ((s7 >> 13) & 0x1F));
            enc32le(dst + 16, s4 + ((s7 >> 9) & 0x0F));
            enc32le(dst + 20, s5 + ((s7 >> 4) & 0x1F));
            enc32le(dst + 24, s6 + (s7 & 0x0F));
            break;
        case 8:
            enc32le(dst, s0);
            enc32le(dst + 4, s1);
            enc32le(dst + 8, s2);
            enc32le(dst + 12, s3);
            enc32le(dst + 16, s4);
            enc32le(dst + 20, s5);
            enc32le(dst + 24, s6);
            enc32le(dst + 28, s7);
            break;
    }
}

static void haval_init(HavalCtx* ctx, unsigned olen, unsigned passes)
{
    memset(ctx, 0, sizeof(*ctx));

    ctx->state[0] = 0x243F6A88;
    ctx->state[1] = 0x85A308D3;
    ctx->state[2] = 0x13198A2E;
    ctx->state[3] = 0x03707344;
    ctx->state[4] = 0xA4093822;
    ctx->state[5] = 0x299F31D0;
    ctx->state[6] = 0x082EFA98;
    ctx->state[7] = 0xEC4E6C89;

    ctx->olen   = olen;
    ctx->passes = passes;
}

void haval_update(HavalCtx* ctx, const u8_t* data, u64_t len)
{
    unsigned current = (unsigned)(ctx->count & (HAVAL_BLOCK_SIZE - 1));

    ctx->count += len;

    while (len > 0) {
        u64_t take = HAVAL_BLOCK_SIZE - current;
        if (take > len)
            take = len;
        memcpy(ctx->buffer + current, data, (size_t)take);
        current += (unsigned)take;
        data += take;
        len -= take;

        if (current == HAVAL_BLOCK_SIZE) {
            haval_compress(ctx, ctx->buffer);
            current = 0;
        }
    }
}

void haval_final(u8_t* digest, HavalCtx* ctx)
{
    unsigned current = (unsigned)(ctx->count & (HAVAL_BLOCK_SIZE - 1));
    u64_t    bits    = ctx->count << 3;

    ctx->buffer[current++] = 0x01;

    /* The tail occupies the last 10 bytes, so a block with no room for it
     * gets padded out and compressed first. */
    if (current > 118) {
        memset(ctx->buffer + current, 0, HAVAL_BLOCK_SIZE - current);
        haval_compress(ctx, ctx->buffer);
        current = 0;
    }
    memset(ctx->buffer + current, 0, 118 - current);

    /* Version (1), pass count and digest length go into the tail alongside
     * the message length, so variants of different shape never collide. */
    ctx->buffer[118] = (u8_t)(0x01 | (ctx->passes << 3));
    ctx->buffer[119] = (u8_t)(ctx->olen << 3);
    enc32le(ctx->buffer + 120, (u32_t)bits);
    enc32le(ctx->buffer + 124, (u32_t)(bits >> 32));

    haval_compress(ctx, ctx->buffer);
    haval_out(ctx, digest);
}

#define GEN_HAVAL_INIT(bits, passes)                                           \
    void haval_##bits##_##passes##_init(HavalCtx* ctx)                         \
    {                                                                          \
        haval_init(ctx, (bits) >> 5, passes);                                  \
    }

GEN_HAVAL_INIT(128, 3)
GEN_HAVAL_INIT(128, 4)
GEN_HAVAL_INIT(128, 5)
GEN_HAVAL_INIT(160, 3)
GEN_HAVAL_INIT(160, 4)
GEN_HAVAL_INIT(160, 5)
GEN_HAVAL_INIT(192, 3)
GEN_HAVAL_INIT(192, 4)
GEN_HAVAL_INIT(192, 5)
GEN_HAVAL_INIT(224, 3)
GEN_HAVAL_INIT(224, 4)
GEN_HAVAL_INIT(224, 5)
GEN_HAVAL_INIT(256, 3)
GEN_HAVAL_INIT(256, 4)
GEN_HAVAL_INIT(256, 5)
