// Copyright (c) 2022-2026, bageyelet
//
// XXH3, ported from the reference xxhash.h by Yann Collet. The reference
// carries SSE2/AVX2/AVX512/NEON paths and a scalar one they all have to agree
// with; this is that scalar path, driven one buffer at a time so that a file
// can be fed through it.
//
// The shape of the thing: inputs up to 240 bytes take one of five one-shot
// mixes chosen by length, and longer ones go through the sponge-ish loop of
// 64-byte stripes over a 192-byte secret, scrambled every 16 stripes. The
// streaming state is what lets the long path see the input in pieces: the
// accumulators, how far into the block of stripes it is, and a buffer holding
// what is not yet a whole stripe.
//
// The seed is 0 throughout: a seeded XXH3 is a keyed function, and the 'hh'
// command has no key to give it.

#include "xxh3.h"

#include <string.h>

#define XXH_PRIME32_1 0x9E3779B1U
#define XXH_PRIME32_2 0x85EBCA77U
#define XXH_PRIME32_3 0xC2B2AE3DU

#define XXH_PRIME64_1 0x9E3779B185EBCA87ULL
#define XXH_PRIME64_2 0xC2B2AE3D27D4EB4FULL
#define XXH_PRIME64_3 0x165667B19E3779F9ULL
#define XXH_PRIME64_4 0x85EBCA77C2B2AE63ULL
#define XXH_PRIME64_5 0x27D4EB2F165667C5ULL

#define PRIME_MX1 0x165667919E3779F9ULL
#define PRIME_MX2 0x9FB21C651E98DF25ULL

#define SECRET_SIZE      192
#define SECRET_SIZE_MIN  136
#define STRIPE_LEN       64
#define SECRET_CONSUME   8
#define MIDSIZE_MAX      240
#define MIDSIZE_START    3
#define MIDSIZE_LAST     17
#define SECRET_LASTACC   7
#define SECRET_MERGEACCS 11

// stripes between two scrambles, and where the scramble reads its secret
#define NB_STRIPES_PER_BLOCK ((SECRET_SIZE - STRIPE_LEN) / SECRET_CONSUME)
#define SECRET_LIMIT         (SECRET_SIZE - STRIPE_LEN)

// clang-format off
static const u8_t kSecret[SECRET_SIZE] = {
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
};
// clang-format on

#define ROTL32(x, r) (((x) << (r)) | ((x) >> (32 - (r))))
#define ROTL64(x, r) (((x) << (r)) | ((x) >> (64 - (r))))

typedef struct u128 {
    u64_t low64;
    u64_t high64;
} u128;

static u32_t read32(const u8_t* p)
{
    return (u32_t)p[0] | ((u32_t)p[1] << 8) | ((u32_t)p[2] << 16) |
           ((u32_t)p[3] << 24);
}

static u64_t read64(const u8_t* p)
{
    return (u64_t)read32(p) | ((u64_t)read32(p + 4) << 32);
}

static u32_t swap32(u32_t x)
{
    return ((x << 24) & 0xff000000U) | ((x << 8) & 0x00ff0000U) |
           ((x >> 8) & 0x0000ff00U) | ((x >> 24) & 0x000000ffU);
}

static u64_t swap64(u64_t x)
{
    return ((x << 56) & 0xff00000000000000ULL) |
           ((x << 40) & 0x00ff000000000000ULL) |
           ((x << 24) & 0x0000ff0000000000ULL) |
           ((x << 8) & 0x000000ff00000000ULL) |
           ((x >> 8) & 0x00000000ff000000ULL) |
           ((x >> 24) & 0x0000000000ff0000ULL) |
           ((x >> 40) & 0x000000000000ff00ULL) |
           ((x >> 56) & 0x00000000000000ffULL);
}

#define mult32to64(x, y) ((u64_t)(u32_t)(x) * (u64_t)(u32_t)(y))

// 64x64 -> 128 the long way: __int128 is not there on every target this
// builds for, and the schoolbook version is the same answer everywhere
static u128 mult64to128(u64_t lhs, u64_t rhs)
{
    u64_t const lo_lo = mult32to64(lhs & 0xFFFFFFFF, rhs & 0xFFFFFFFF);
    u64_t const hi_lo = mult32to64(lhs >> 32, rhs & 0xFFFFFFFF);
    u64_t const lo_hi = mult32to64(lhs & 0xFFFFFFFF, rhs >> 32);
    u64_t const hi_hi = mult32to64(lhs >> 32, rhs >> 32);

    u64_t const cross = (lo_lo >> 32) + (hi_lo & 0xFFFFFFFF) + lo_hi;
    u64_t const upper = (hi_lo >> 32) + (cross >> 32) + hi_hi;
    u64_t const lower = (cross << 32) | (lo_lo & 0xFFFFFFFF);

    u128 r;
    r.low64  = lower;
    r.high64 = upper;
    return r;
}

static u64_t mul128_fold64(u64_t lhs, u64_t rhs)
{
    u128 product = mult64to128(lhs, rhs);
    return product.low64 ^ product.high64;
}

static u64_t xorshift64(u64_t v, int shift) { return v ^ (v >> shift); }

static u64_t xxh64_avalanche(u64_t h)
{
    h ^= h >> 33;
    h *= XXH_PRIME64_2;
    h ^= h >> 29;
    h *= XXH_PRIME64_3;
    h ^= h >> 32;
    return h;
}

static u64_t xxh3_avalanche(u64_t h)
{
    h = xorshift64(h, 37);
    h *= PRIME_MX1;
    h = xorshift64(h, 32);
    return h;
}

static u64_t xxh3_rrmxmx(u64_t h, u64_t len)
{
    h ^= ROTL64(h, 49) ^ ROTL64(h, 24);
    h *= PRIME_MX2;
    h ^= (h >> 35) + len;
    h *= PRIME_MX2;
    return xorshift64(h, 28);
}

/* ===================== short inputs, 64 bit ===================== */

static u64_t len_1to3_64b(const u8_t* input, size_t len, const u8_t* secret)
{
    u8_t const  c1       = input[0];
    u8_t const  c2       = input[len >> 1];
    u8_t const  c3       = input[len - 1];
    u32_t const combined = ((u32_t)c1 << 16) | ((u32_t)c2 << 24) |
                           ((u32_t)c3 << 0) | ((u32_t)len << 8);
    u64_t const bitflip  = (u64_t)(read32(secret) ^ read32(secret + 4));
    return xxh64_avalanche((u64_t)combined ^ bitflip);
}

static u64_t len_4to8_64b(const u8_t* input, size_t len, const u8_t* secret)
{
    u32_t const input1  = read32(input);
    u32_t const input2  = read32(input + len - 4);
    u64_t const bitflip = read64(secret + 8) ^ read64(secret + 16);
    u64_t const input64 = input2 + (((u64_t)input1) << 32);
    return xxh3_rrmxmx(input64 ^ bitflip, len);
}

static u64_t len_9to16_64b(const u8_t* input, size_t len, const u8_t* secret)
{
    u64_t const bitflip1 = read64(secret + 24) ^ read64(secret + 32);
    u64_t const bitflip2 = read64(secret + 40) ^ read64(secret + 48);
    u64_t const input_lo = read64(input) ^ bitflip1;
    u64_t const input_hi = read64(input + len - 8) ^ bitflip2;
    u64_t const acc =
        len + swap64(input_lo) + input_hi + mul128_fold64(input_lo, input_hi);
    return xxh3_avalanche(acc);
}

static u64_t len_0to16_64b(const u8_t* input, size_t len, const u8_t* secret)
{
    if (len > 8)
        return len_9to16_64b(input, len, secret);
    if (len >= 4)
        return len_4to8_64b(input, len, secret);
    if (len)
        return len_1to3_64b(input, len, secret);
    return xxh64_avalanche(read64(secret + 56) ^ read64(secret + 64));
}

static u64_t mix16B(const u8_t* input, const u8_t* secret)
{
    u64_t const input_lo = read64(input);
    u64_t const input_hi = read64(input + 8);
    return mul128_fold64(input_lo ^ read64(secret),
                         input_hi ^ read64(secret + 8));
}

static u64_t len_17to128_64b(const u8_t* input, size_t len, const u8_t* secret)
{
    u64_t acc = len * XXH_PRIME64_1;

    if (len > 32) {
        if (len > 64) {
            if (len > 96) {
                acc += mix16B(input + 48, secret + 96);
                acc += mix16B(input + len - 64, secret + 112);
            }
            acc += mix16B(input + 32, secret + 64);
            acc += mix16B(input + len - 48, secret + 80);
        }
        acc += mix16B(input + 16, secret + 32);
        acc += mix16B(input + len - 32, secret + 48);
    }
    acc += mix16B(input + 0, secret + 0);
    acc += mix16B(input + len - 16, secret + 16);

    return xxh3_avalanche(acc);
}

static u64_t len_129to240_64b(const u8_t* input, size_t len, const u8_t* secret)
{
    u64_t    acc       = len * XXH_PRIME64_1;
    u64_t    acc_end   = 0;
    unsigned nb_rounds = (unsigned)len / 16;
    unsigned i;

    for (i = 0; i < 8; i++)
        acc += mix16B(input + (16 * i), secret + (16 * i));

    acc_end = mix16B(input + len - 16, secret + SECRET_SIZE_MIN - MIDSIZE_LAST);
    acc     = xxh3_avalanche(acc);

    for (i = 8; i < nb_rounds; i++)
        acc_end +=
            mix16B(input + (16 * i), secret + (16 * (i - 8)) + MIDSIZE_START);

    return xxh3_avalanche(acc + acc_end);
}

/* ===================== short inputs, 128 bit ===================== */

static u128 len_1to3_128b(const u8_t* input, size_t len, const u8_t* secret)
{
    u8_t const  c1        = input[0];
    u8_t const  c2        = input[len >> 1];
    u8_t const  c3        = input[len - 1];
    u32_t const combinedl = ((u32_t)c1 << 16) | ((u32_t)c2 << 24) |
                            ((u32_t)c3 << 0) | ((u32_t)len << 8);
    u32_t const combinedh = ROTL32(swap32(combinedl), 13);
    u64_t const bitflipl  = (u64_t)(read32(secret) ^ read32(secret + 4));
    u64_t const bitfliph  = (u64_t)(read32(secret + 8) ^ read32(secret + 12));

    u128 h128;
    h128.low64  = xxh64_avalanche((u64_t)combinedl ^ bitflipl);
    h128.high64 = xxh64_avalanche((u64_t)combinedh ^ bitfliph);
    return h128;
}

static u128 len_4to8_128b(const u8_t* input, size_t len, const u8_t* secret)
{
    u32_t const input_lo = read32(input);
    u32_t const input_hi = read32(input + len - 4);
    u64_t const input_64 = input_lo + ((u64_t)input_hi << 32);
    u64_t const bitflip  = read64(secret + 16) ^ read64(secret + 24);
    u64_t const keyed    = input_64 ^ bitflip;

    // len is shifted left so that it is even, which avoids an even multiply
    u128 m128 = mult64to128(keyed, XXH_PRIME64_1 + (len << 2));

    m128.high64 += (m128.low64 << 1);
    m128.low64 ^= (m128.high64 >> 3);

    m128.low64 = xorshift64(m128.low64, 35);
    m128.low64 *= PRIME_MX2;
    m128.low64  = xorshift64(m128.low64, 28);
    m128.high64 = xxh3_avalanche(m128.high64);
    return m128;
}

static u128 len_9to16_128b(const u8_t* input, size_t len, const u8_t* secret)
{
    u64_t const bitflipl = read64(secret + 32) ^ read64(secret + 40);
    u64_t const bitfliph = read64(secret + 48) ^ read64(secret + 56);
    u64_t const input_lo = read64(input);
    u64_t       input_hi = read64(input + len - 8);
    u128 m128 = mult64to128(input_lo ^ input_hi ^ bitflipl, XXH_PRIME64_1);

    // len goes in the middle of m128, so that it reaches both halves of the
    // 128x64 multiply below
    m128.low64 += (u64_t)(len - 1) << 54;
    input_hi ^= bitfliph;
    m128.high64 += input_hi + mult32to64((u32_t)input_hi, XXH_PRIME32_2 - 1);

    m128.low64 ^= swap64(m128.high64);

    {
        u128 h128 = mult64to128(m128.low64, XXH_PRIME64_2);
        h128.high64 += m128.high64 * XXH_PRIME64_2;

        h128.low64  = xxh3_avalanche(h128.low64);
        h128.high64 = xxh3_avalanche(h128.high64);
        return h128;
    }
}

static u128 len_0to16_128b(const u8_t* input, size_t len, const u8_t* secret)
{
    if (len > 8)
        return len_9to16_128b(input, len, secret);
    if (len >= 4)
        return len_4to8_128b(input, len, secret);
    if (len)
        return len_1to3_128b(input, len, secret);
    {
        u128        h128;
        u64_t const bitflipl = read64(secret + 64) ^ read64(secret + 72);
        u64_t const bitfliph = read64(secret + 80) ^ read64(secret + 88);
        h128.low64           = xxh64_avalanche(bitflipl);
        h128.high64          = xxh64_avalanche(bitfliph);
        return h128;
    }
}

static u128 mix32B(u128 acc, const u8_t* input_1, const u8_t* input_2,
                   const u8_t* secret)
{
    acc.low64 += mix16B(input_1, secret + 0);
    acc.low64 ^= read64(input_2) + read64(input_2 + 8);
    acc.high64 += mix16B(input_2, secret + 16);
    acc.high64 ^= read64(input_1) + read64(input_1 + 8);
    return acc;
}

// the same tail for both mid-size 128-bit paths
static u128 midsize_128b_final(u128 acc, size_t len)
{
    u128 h128;
    h128.low64  = acc.low64 + acc.high64;
    h128.high64 = (acc.low64 * XXH_PRIME64_1) + (acc.high64 * XXH_PRIME64_4) +
                  (len * XXH_PRIME64_2);
    h128.low64  = xxh3_avalanche(h128.low64);
    h128.high64 = (u64_t)0 - xxh3_avalanche(h128.high64);
    return h128;
}

static u128 len_17to128_128b(const u8_t* input, size_t len, const u8_t* secret)
{
    u128 acc;
    acc.low64  = len * XXH_PRIME64_1;
    acc.high64 = 0;

    if (len > 32) {
        if (len > 64) {
            if (len > 96) {
                acc = mix32B(acc, input + 48, input + len - 64, secret + 96);
            }
            acc = mix32B(acc, input + 32, input + len - 48, secret + 64);
        }
        acc = mix32B(acc, input + 16, input + len - 32, secret + 32);
    }
    acc = mix32B(acc, input, input + len - 16, secret);

    return midsize_128b_final(acc, len);
}

static u128 len_129to240_128b(const u8_t* input, size_t len, const u8_t* secret)
{
    u128     acc;
    unsigned i;
    acc.low64  = len * XXH_PRIME64_1;
    acc.high64 = 0;

    for (i = 32; i < 160; i += 32)
        acc = mix32B(acc, input + i - 32, input + i - 16, secret + i - 32);

    acc.low64  = xxh3_avalanche(acc.low64);
    acc.high64 = xxh3_avalanche(acc.high64);

    // NB: "i <= len" repeats the last 32 bytes when len % 32 is zero. It is
    // what the reference does, and the hash would change without it
    for (i = 160; i <= len; i += 32)
        acc = mix32B(acc, input + i - 32, input + i - 16,
                     secret + MIDSIZE_START + i - 160);

    acc = mix32B(acc, input + len - 16, input + len - 32,
                 secret + SECRET_SIZE_MIN - MIDSIZE_LAST - 16);

    return midsize_128b_final(acc, len);
}

/* ===================== long inputs ===================== */

static void accumulate_512(u64_t* acc, const u8_t* input, const u8_t* secret)
{
    for (size_t lane = 0; lane < XXH3_ACC_NB; lane++) {
        u64_t const data_val = read64(input + lane * 8);
        u64_t const data_key = data_val ^ read64(secret + lane * 8);
        acc[lane ^ 1] += data_val; // swap adjacent lanes
        acc[lane] += mult32to64(data_key & 0xFFFFFFFF, data_key >> 32);
    }
}

static void accumulate(u64_t* acc, const u8_t* input, const u8_t* secret,
                       size_t nb_stripes)
{
    for (size_t n = 0; n < nb_stripes; n++)
        accumulate_512(acc, input + n * STRIPE_LEN,
                       secret + n * SECRET_CONSUME);
}

static void scramble_acc(u64_t* acc, const u8_t* secret)
{
    for (size_t lane = 0; lane < XXH3_ACC_NB; lane++) {
        u64_t const key64 = read64(secret + lane * 8);
        u64_t       acc64 = acc[lane];
        acc64             = xorshift64(acc64, 47);
        acc64 ^= key64;
        acc64 *= XXH_PRIME32_1;
        acc[lane] = acc64;
    }
}

static u64_t mix2accs(const u64_t* acc, const u8_t* secret)
{
    return mul128_fold64(acc[0] ^ read64(secret), acc[1] ^ read64(secret + 8));
}

static u64_t merge_accs(const u64_t* acc, const u8_t* secret, u64_t start)
{
    u64_t result64 = start;
    for (size_t i = 0; i < 4; i++)
        result64 += mix2accs(acc + 2 * i, secret + 16 * i);
    return xxh3_avalanche(result64);
}

static void init_acc(u64_t* acc)
{
    acc[0] = XXH_PRIME32_3;
    acc[1] = XXH_PRIME64_1;
    acc[2] = XXH_PRIME64_2;
    acc[3] = XXH_PRIME64_3;
    acc[4] = XXH_PRIME64_4;
    acc[5] = XXH_PRIME32_2;
    acc[6] = XXH_PRIME64_5;
    acc[7] = XXH_PRIME32_1;
}

// Feeds nb_stripes stripes to the accumulators, scrambling whenever a block
// of NB_STRIPES_PER_BLOCK is complete. Returns where it stopped reading
static const u8_t* consume_stripes(u64_t* acc, u64_t* nb_stripes_so_far,
                                   const u8_t* input, size_t nb_stripes)
{
    const u8_t* initial_secret = kSecret + *nb_stripes_so_far * SECRET_CONSUME;

    if (nb_stripes >= (NB_STRIPES_PER_BLOCK - *nb_stripes_so_far)) {
        size_t nb_this_iter = NB_STRIPES_PER_BLOCK - *nb_stripes_so_far;
        do {
            accumulate(acc, input, initial_secret, nb_this_iter);
            scramble_acc(acc, kSecret + SECRET_LIMIT);
            input += nb_this_iter * STRIPE_LEN;
            nb_stripes -= nb_this_iter;
            nb_this_iter   = NB_STRIPES_PER_BLOCK;
            initial_secret = kSecret;
        } while (nb_stripes >= NB_STRIPES_PER_BLOCK);
        *nb_stripes_so_far = 0;
    }
    if (nb_stripes > 0) {
        accumulate(acc, input, initial_secret, nb_stripes);
        input += nb_stripes * STRIPE_LEN;
        *nb_stripes_so_far += nb_stripes;
    }
    return input;
}

/* ===================== the streaming API ===================== */

static void xxh3_init(Xxh3Ctx* ctx, int is_128)
{
    memset(ctx, 0, sizeof(*ctx));
    init_acc(ctx->acc);
    ctx->is_128 = is_128;
}

void xxh3_64_init(Xxh3Ctx* ctx) { xxh3_init(ctx, 0); }

void xxh3_128_init(Xxh3Ctx* ctx) { xxh3_init(ctx, 1); }

void xxh3_update(Xxh3Ctx* ctx, const u8_t* data, size_t len)
{
    const u8_t* input = data;
    const u8_t* bEnd  = data + len;

    ctx->total_len += len;

    // an input this short is only buffered: whether it goes down the short or
    // the long path is not known until the digest is asked for
    if (len <= XXH3_INTERNALBUFFER_LEN - ctx->buffered) {
        memcpy(ctx->buffer + ctx->buffered, input, len);
        ctx->buffered += (u32_t)len;
        return;
    }

    if (ctx->buffered) {
        size_t const load_size = XXH3_INTERNALBUFFER_LEN - ctx->buffered;
        memcpy(ctx->buffer + ctx->buffered, input, load_size);
        input += load_size;
        consume_stripes(ctx->acc, &ctx->nb_stripes_so_far, ctx->buffer,
                        XXH3_INTERNALBUFFER_LEN / STRIPE_LEN);
        ctx->buffered = 0;
    }

    if (bEnd - input > XXH3_INTERNALBUFFER_LEN) {
        size_t nb_stripes = (size_t)(bEnd - 1 - input) / STRIPE_LEN;
        input = consume_stripes(ctx->acc, &ctx->nb_stripes_so_far, input,
                                nb_stripes);
        // the digest needs the last whole stripe, which may not survive in
        // the buffer: keep a copy of it at the end of it
        memcpy(ctx->buffer + XXH3_INTERNALBUFFER_LEN - STRIPE_LEN,
               input - STRIPE_LEN, STRIPE_LEN);
    }

    // whatever is left is shorter than the buffer, so it is buffered
    memcpy(ctx->buffer, input, (size_t)(bEnd - input));
    ctx->buffered = (u32_t)(bEnd - input);
}

// The accumulators as they would be with the whole input fed in. Works on a
// copy, so that the context is still usable afterwards
static void digest_long(u64_t* acc, const Xxh3Ctx* ctx)
{
    u8_t        last_stripe[STRIPE_LEN];
    const u8_t* last_stripe_ptr;

    memcpy(acc, ctx->acc, sizeof(ctx->acc));

    if (ctx->buffered >= STRIPE_LEN) {
        size_t const nb_stripes      = (ctx->buffered - 1) / STRIPE_LEN;
        u64_t        nb_stripes_copy = ctx->nb_stripes_so_far;
        consume_stripes(acc, &nb_stripes_copy, ctx->buffer, nb_stripes);
        last_stripe_ptr = ctx->buffer + ctx->buffered - STRIPE_LEN;
    } else {
        // the last stripe straddles the end of the buffer and its beginning:
        // the head of it is the copy update() left behind
        size_t const catchup = STRIPE_LEN - ctx->buffered;
        memcpy(last_stripe, ctx->buffer + XXH3_INTERNALBUFFER_LEN - catchup,
               catchup);
        memcpy(last_stripe + catchup, ctx->buffer, ctx->buffered);
        last_stripe_ptr = last_stripe;
    }

    accumulate_512(acc, last_stripe_ptr,
                   kSecret + SECRET_LIMIT - SECRET_LASTACC);
}

static u64_t xxh3_64_digest(const Xxh3Ctx* ctx)
{
    if (ctx->total_len > MIDSIZE_MAX) {
        u64_t acc[XXH3_ACC_NB];
        digest_long(acc, ctx);
        return merge_accs(acc, kSecret + SECRET_MERGEACCS,
                          ctx->total_len * XXH_PRIME64_1);
    }
    // everything up to 240 bytes is still whole in the buffer
    {
        size_t      len   = (size_t)ctx->total_len;
        const u8_t* input = ctx->buffer;
        if (len <= 16)
            return len_0to16_64b(input, len, kSecret);
        if (len <= 128)
            return len_17to128_64b(input, len, kSecret);
        return len_129to240_64b(input, len, kSecret);
    }
}

static u128 xxh3_128_digest(const Xxh3Ctx* ctx)
{
    if (ctx->total_len > MIDSIZE_MAX) {
        u64_t acc[XXH3_ACC_NB];
        u128  h128;
        digest_long(acc, ctx);
        h128.low64  = merge_accs(acc, kSecret + SECRET_MERGEACCS,
                                 ctx->total_len * XXH_PRIME64_1);
        h128.high64 = merge_accs(
            acc, kSecret + SECRET_SIZE - STRIPE_LEN - SECRET_MERGEACCS,
            ~(ctx->total_len * XXH_PRIME64_2));
        return h128;
    }
    {
        size_t      len   = (size_t)ctx->total_len;
        const u8_t* input = ctx->buffer;
        if (len <= 16)
            return len_0to16_128b(input, len, kSecret);
        if (len <= 128)
            return len_17to128_128b(input, len, kSecret);
        return len_129to240_128b(input, len, kSecret);
    }
}

static void store64_be(u8_t* out, u64_t v)
{
    for (int i = 0; i < 8; ++i)
        out[i] = (u8_t)(v >> (8 * (7 - i)));
}

void xxh3_final(u8_t* out, Xxh3Ctx* ctx)
{
    if (ctx->is_128) {
        // XXH128_canonicalFromHash writes the high half first
        u128 h = xxh3_128_digest(ctx);
        store64_be(out, h.high64);
        store64_be(out + 8, h.low64);
    } else {
        store64_be(out, xxh3_64_digest(ctx));
    }
}
