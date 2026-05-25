/*
 * BLAKE3 portable C implementation.
 * Provides the compression / XOF / hash_many routines declared in
 * blake3_impl.h so blake3.c can link on platforms without SIMD backends.
 */

#include <string.h>

#include "blake3.h"
#include "blake3_impl.h"

/* ------------------------------------------------------------------ */
/*  helper rotator                                                    */
/* ------------------------------------------------------------------ */
INLINE uint32_t rotr32(uint32_t w, unsigned int c)
{
    return (w >> c) | (w << (32 - c));
}

/* ------------------------------------------------------------------ */
/*  G function – one quarter-round of the BLAKE3 permutation          */
/* ------------------------------------------------------------------ */
static void g(uint32_t* state, size_t a, size_t b, size_t c, size_t d,
              uint32_t mx, uint32_t my)
{
    state[a] = state[a] + state[b] + mx;
    state[d] = rotr32(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + my;
    state[d] = rotr32(state[d] ^ state[a], 8);
    state[c] = state[c] + state[d];
    state[b] = rotr32(state[b] ^ state[c], 7);
}

/* ------------------------------------------------------------------ */
/*  round – one full round (8 G calls)                                */
/* ------------------------------------------------------------------ */
static void round_fn(uint32_t* state, const uint32_t* msg, size_t round)
{
    /* clang-format off */
    /* Column steps */
    g(state,  0,  4,  8, 12, msg[MSG_SCHEDULE[round][ 0]], msg[MSG_SCHEDULE[round][ 1]]);
    g(state,  1,  5,  9, 13, msg[MSG_SCHEDULE[round][ 2]], msg[MSG_SCHEDULE[round][ 3]]);
    g(state,  2,  6, 10, 14, msg[MSG_SCHEDULE[round][ 4]], msg[MSG_SCHEDULE[round][ 5]]);
    g(state,  3,  7, 11, 15, msg[MSG_SCHEDULE[round][ 6]], msg[MSG_SCHEDULE[round][ 7]]);
    /* Diagonal steps */
    g(state,  0,  5, 10, 15, msg[MSG_SCHEDULE[round][ 8]], msg[MSG_SCHEDULE[round][ 9]]);
    g(state,  1,  6, 11, 12, msg[MSG_SCHEDULE[round][10]], msg[MSG_SCHEDULE[round][11]]);
    g(state,  2,  7,  8, 13, msg[MSG_SCHEDULE[round][12]], msg[MSG_SCHEDULE[round][13]]);
    g(state,  3,  4,  9, 14, msg[MSG_SCHEDULE[round][14]], msg[MSG_SCHEDULE[round][15]]);
    /* clang-format on */
}

/* ------------------------------------------------------------------ */
/*  compress  –  single-block compression (7 rounds for BLAKE3)       */
/* ------------------------------------------------------------------ */
static void compress(uint32_t state[16], const uint32_t cv[8],
                     const uint8_t block[BLAKE3_BLOCK_LEN], uint8_t block_len,
                     uint64_t counter, uint8_t flags)
{
    uint32_t msg[16];
    load_block_words(block, msg);

    state[0]  = cv[0];
    state[1]  = cv[1];
    state[2]  = cv[2];
    state[3]  = cv[3];
    state[4]  = cv[4];
    state[5]  = cv[5];
    state[6]  = cv[6];
    state[7]  = cv[7];
    state[8]  = IV[0];
    state[9]  = IV[1];
    state[10] = IV[2];
    state[11] = IV[3];
    state[12] = counter_low(counter);
    state[13] = counter_high(counter);
    state[14] = (uint32_t)block_len;
    state[15] = (uint32_t)flags;

    for (size_t r = 0; r < 7; r++)
        round_fn(state, msg, r);
}

/* ------------------------------------------------------------------ */
/*  public entry points (portable)                                    */
/* ------------------------------------------------------------------ */
void blake3_compress_in_place_portable(uint32_t      cv[8],
                                       const uint8_t block[BLAKE3_BLOCK_LEN],
                                       uint8_t block_len, uint64_t counter,
                                       uint8_t flags)
{
    uint32_t state[16];
    compress(state, cv, block, block_len, counter, flags);
    cv[0] = state[0] ^ state[8];
    cv[1] = state[1] ^ state[9];
    cv[2] = state[2] ^ state[10];
    cv[3] = state[3] ^ state[11];
    cv[4] = state[4] ^ state[12];
    cv[5] = state[5] ^ state[13];
    cv[6] = state[6] ^ state[14];
    cv[7] = state[7] ^ state[15];
}

void blake3_compress_xof_portable(const uint32_t cv[8],
                                  const uint8_t  block[BLAKE3_BLOCK_LEN],
                                  uint8_t block_len, uint64_t counter,
                                  uint8_t flags, uint8_t out[64])
{
    uint32_t state[16];
    compress(state, cv, block, block_len, counter, flags);
    store32(&out[0 * 4], state[0] ^ state[8]);
    store32(&out[1 * 4], state[1] ^ state[9]);
    store32(&out[2 * 4], state[2] ^ state[10]);
    store32(&out[3 * 4], state[3] ^ state[11]);
    store32(&out[4 * 4], state[4] ^ state[12]);
    store32(&out[5 * 4], state[5] ^ state[13]);
    store32(&out[6 * 4], state[6] ^ state[14]);
    store32(&out[7 * 4], state[7] ^ state[15]);
    store32(&out[8 * 4], state[8] ^ cv[0]);
    store32(&out[9 * 4], state[9] ^ cv[1]);
    store32(&out[10 * 4], state[10] ^ cv[2]);
    store32(&out[11 * 4], state[11] ^ cv[3]);
    store32(&out[12 * 4], state[12] ^ cv[4]);
    store32(&out[13 * 4], state[13] ^ cv[5]);
    store32(&out[14 * 4], state[14] ^ cv[6]);
    store32(&out[15 * 4], state[15] ^ cv[7]);
}

void blake3_hash_many_portable(const uint8_t* const* inputs, size_t num_inputs,
                               size_t blocks, const uint32_t key[8],
                               uint64_t counter, bool increment_counter,
                               uint8_t flags, uint8_t flags_start,
                               uint8_t flags_end, uint8_t* out)
{
    while (num_inputs > 0) {
        uint32_t cv[8];
        memcpy(cv, key, 32);

        uint8_t block_flags = flags | flags_start;
        for (size_t b = 0; b < blocks; b++) {
            /* last block of this input? */
            if (b == blocks - 1) {
                block_flags |= flags_end;
            }
            blake3_compress_in_place_portable(
                cv, inputs[0] + b * BLAKE3_BLOCK_LEN, BLAKE3_BLOCK_LEN, counter,
                block_flags);
            block_flags = flags; /* clear start/end for subsequent blocks */
        }

        store_cv_words(&out[0], cv);
        out += BLAKE3_OUT_LEN;
        inputs += 1;
        num_inputs -= 1;
        if (increment_counter) {
            counter += 1;
        }
    }
}

/* ------------------------------------------------------------------ */
/*  dispatch helpers  –  always resolve to portable on this build     */
/* ------------------------------------------------------------------ */

size_t blake3_simd_degree(void) { return 1; }

void blake3_compress_in_place(uint32_t      cv[8],
                              const uint8_t block[BLAKE3_BLOCK_LEN],
                              uint8_t block_len, uint64_t counter,
                              uint8_t flags)
{
    blake3_compress_in_place_portable(cv, block, block_len, counter, flags);
}

void blake3_compress_xof(const uint32_t cv[8],
                         const uint8_t  block[BLAKE3_BLOCK_LEN],
                         uint8_t block_len, uint64_t counter, uint8_t flags,
                         uint8_t out[64])
{
    blake3_compress_xof_portable(cv, block, block_len, counter, flags, out);
}

void blake3_xof_many(const uint32_t cv[8],
                     const uint8_t block[BLAKE3_BLOCK_LEN], uint8_t block_len,
                     uint64_t counter, uint8_t flags, uint8_t* out,
                     size_t outblocks)
{
    for (size_t i = 0; i < outblocks; i++) {
        blake3_compress_xof(cv, block, block_len, counter + (uint64_t)i, flags,
                            &out[i * 64]);
    }
}

void blake3_hash_many(const uint8_t* const* inputs, size_t num_inputs,
                      size_t blocks, const uint32_t key[8], uint64_t counter,
                      bool increment_counter, uint8_t flags,
                      uint8_t flags_start, uint8_t flags_end, uint8_t* out)
{
    blake3_hash_many_portable(inputs, num_inputs, blocks, key, counter,
                              increment_counter, flags, flags_start, flags_end,
                              out);
}
