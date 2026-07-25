// Copyright (c) 2022-2026, bageyelet

// Regression tests for the incremental (streaming) update paths of the hash
// implementations.
//
// bhex feeds hashes in fb_block_size (4096) chunks, which is a multiple of
// every algorithm's block size, so only the very last update is ever partial.
// That masked two real bugs:
//
//   - jh_Update() copied "block size - buffered" bytes out of the caller's
//     buffer regardless of how many bytes were actually supplied (over-read).
//   - shash_Update() overwrote the buffered remainder instead of appending to
//     it when the new data did not complete a chunk (over-read + wrong digest).
//
// Both only appear with consecutive small updates, so we exercise exactly that
// and compare against the one-shot digest.

#include <string.h>
#include <stdlib.h>
#include <alloc.h>
#include <defs.h>

#include <hash/jh-ref.h>
#include <hash/shash.h>

#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

#define MAX_LEN 300

static void fill(u8_t* buf, u32_t len)
{
    for (u32_t i = 0; i < len; ++i)
        buf[i] = (u8_t)(i * 7 + 3);
}

// Feed `data` in `split`-byte pieces, each copied into its own exact-size heap
// allocation so that ASAN catches any read past the supplied bytes.
#define STREAM_IN_PIECES(update_call, ctx, data, len, split)                   \
    do {                                                                       \
        u32_t off = 0;                                                         \
        while (off < (len)) {                                                  \
            u32_t chunk = ((len) - off < (split)) ? ((len) - off) : (split);   \
            u8_t* piece = bhex_malloc(chunk);                                  \
            memcpy(piece, (data) + off, chunk);                                \
            update_call(&(ctx), piece, chunk);                                 \
            bhex_free(piece);                                                  \
            off += chunk;                                                      \
        }                                                                      \
    } while (0)

int TEST(jh_streaming_matches_oneshot)(void)
{
    u8_t buf[MAX_LEN];
    fill(buf, sizeof(buf));

    for (u32_t len = 0; len <= MAX_LEN; ++len) {
        for (u32_t split = 1; split <= 5; ++split) {
            u8_t         oneshot[64], streamed[64];
            jh_hashState s1, s2;

            jh_256_init(&s1);
            u8_t* whole = bhex_malloc(len ? len : 1);
            memcpy(whole, buf, len);
            jh_update_bytes(&s1, whole, len);
            jh_final_wrap(oneshot, &s1);
            bhex_free(whole);

            jh_256_init(&s2);
            STREAM_IN_PIECES(jh_update_bytes, s2, buf, len, split);
            jh_final_wrap(streamed, &s2);

            if (memcmp(oneshot, streamed, 32) != 0)
                return TEST_FAILED;
        }
    }
    return TEST_SUCCEEDED;
}

int TEST(shash_streaming_matches_oneshot)(void)
{
    u8_t buf[MAX_LEN];
    fill(buf, sizeof(buf));

    for (u32_t len = 0; len <= MAX_LEN; ++len) {
        for (u32_t split = 1; split <= 5; ++split) {
            u8_t            oneshot[64], streamed[64];
            SpectralHashCtx s1, s2;

            shash_256_init(&s1);
            u8_t* whole = bhex_malloc(len ? len : 1);
            memcpy(whole, buf, len);
            shash_update(&s1, whole, len);
            shash_final(oneshot, &s1);
            bhex_free(whole);

            shash_256_init(&s2);
            STREAM_IN_PIECES(shash_update, s2, buf, len, split);
            shash_final(streamed, &s2);

            if (memcmp(oneshot, streamed, 32) != 0)
                return TEST_FAILED;
        }
    }
    return TEST_SUCCEEDED;
}
