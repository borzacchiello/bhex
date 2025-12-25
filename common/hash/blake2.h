/*
   BLAKE2 reference source code package - reference C implementations

   Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under the
   terms of the CC0, the OpenSSL Licence, or the Apache Public License 2.0, at
   your option.  The terms of these licenses can be found at:

   - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
   - OpenSSL license   : https://www.openssl.org/source/license.html
   - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0

   More information about the BLAKE2 hash function can be found at
   https://blake2.net.
*/
#ifndef BLAKE2_H
#define BLAKE2_H

#include <stddef.h>
#include <defs.h>
#include <log.h>

#if defined(_MSC_VER)
#define BLAKE2_PACKED(x) __pragma(pack(push, 1)) x __pragma(pack(pop))
#else
#define BLAKE2_PACKED(x) x __attribute__((packed))
#endif

enum blake2s_constant {
    BLAKE2S_BLOCKBYTES    = 64,
    BLAKE2S_OUTBYTES      = 32,
    BLAKE2S_KEYBYTES      = 32,
    BLAKE2S_SALTBYTES     = 8,
    BLAKE2S_PERSONALBYTES = 8
};

enum blake2b_constant {
    BLAKE2B_BLOCKBYTES    = 128,
    BLAKE2B_OUTBYTES      = 64,
    BLAKE2B_KEYBYTES      = 64,
    BLAKE2B_SALTBYTES     = 16,
    BLAKE2B_PERSONALBYTES = 16
};

typedef struct blake2s_state__ {
    u32_t  h[8];
    u32_t  t[2];
    u32_t  f[2];
    u8_t   buf[BLAKE2S_BLOCKBYTES];
    size_t buflen;
    size_t outlen;
    u8_t   last_node;
} blake2s_state;

typedef struct blake2b_state__ {
    u64_t  h[8];
    u64_t  t[2];
    u64_t  f[2];
    u8_t   buf[BLAKE2B_BLOCKBYTES];
    size_t buflen;
    size_t outlen;
    u8_t   last_node;
} blake2b_state;

BLAKE2_PACKED(struct blake2s_param__ {
    u8_t  digest_length; /* 1 */
    u8_t  key_length;    /* 2 */
    u8_t  fanout;        /* 3 */
    u8_t  depth;         /* 4 */
    u32_t leaf_length;   /* 8 */
    u32_t node_offset;   /* 12 */
    u16_t xof_length;    /* 14 */
    u8_t  node_depth;    /* 15 */
    u8_t  inner_length;  /* 16 */
    /* u8_t  reserved[0]; */
    u8_t salt[BLAKE2S_SALTBYTES];         /* 24 */
    u8_t personal[BLAKE2S_PERSONALBYTES]; /* 32 */
});

typedef struct blake2s_param__ blake2s_param;

BLAKE2_PACKED(struct blake2b_param__ {
    u8_t  digest_length;                   /* 1 */
    u8_t  key_length;                      /* 2 */
    u8_t  fanout;                          /* 3 */
    u8_t  depth;                           /* 4 */
    u32_t leaf_length;                     /* 8 */
    u32_t node_offset;                     /* 12 */
    u32_t xof_length;                      /* 16 */
    u8_t  node_depth;                      /* 17 */
    u8_t  inner_length;                    /* 18 */
    u8_t  reserved[14];                    /* 32 */
    u8_t  salt[BLAKE2B_SALTBYTES];         /* 48 */
    u8_t  personal[BLAKE2B_PERSONALBYTES]; /* 64 */
});

typedef struct blake2b_param__ blake2b_param;

/* Padded structs result in a compile-time error */
enum {
    BLAKE2_DUMMY_1 = 1 / (int)(sizeof(blake2s_param) == BLAKE2S_OUTBYTES),
    BLAKE2_DUMMY_2 = 1 / (int)(sizeof(blake2b_param) == BLAKE2B_OUTBYTES)
};

/* Streaming API */
int blake2s_init(blake2s_state* S, size_t outlen);
int blake2s_init_key(blake2s_state* S, size_t outlen, const void* key,
                     size_t keylen);
int blake2s_init_param(blake2s_state* S, const blake2s_param* P);
int blake2s_update(blake2s_state* S, const void* in, size_t inlen);
int blake2s_final(blake2s_state* S, void* out, size_t outlen);

#define simple_blake2s_init(state)                                             \
    if (blake2s_init(state, BLAKE2S_OUTBYTES) < 0) {                           \
        panic("blake2s_init failed");                                          \
    }
#define simple_blake2s_update(state, in, inlen)                                \
    if (blake2s_update(state, in, inlen) < 0) {                                \
        panic("blake2s_update failed");                                        \
    }
#define simple_blake2s_final(out, state)                                       \
    if (blake2s_final(state, out, BLAKE2S_OUTBYTES) < 0) {                     \
        panic("blake2s_final failed");                                         \
    }

int blake2b_init(blake2b_state* S, size_t outlen);
int blake2b_init_key(blake2b_state* S, size_t outlen, const void* key,
                     size_t keylen);
int blake2b_init_param(blake2b_state* S, const blake2b_param* P);
int blake2b_update(blake2b_state* S, const void* in, size_t inlen);
int blake2b_final(blake2b_state* S, void* out, size_t outlen);

#define simple_blake2b_init(state)                                             \
    if (blake2b_init(state, BLAKE2B_OUTBYTES) < 0) {                           \
        panic("blake2b_init failed");                                          \
    }
#define simple_blake2b_update(state, in, inlen)                                \
    if (blake2b_update(state, in, inlen) < 0) {                                \
        panic("blake2b_update failed");                                        \
    }
#define simple_blake2b_final(out, state)                                       \
    if (blake2b_final(state, out, BLAKE2B_OUTBYTES) < 0) {                     \
        panic("blake2b_final failed");                                         \
    }

#endif
