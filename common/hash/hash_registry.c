// Copyright (c) 2022-2026, bageyelet
//
// The registry of the supported hash algorithms. It lives in common/ (rather
// than in the 'hh' command that used to own it) so that the bhengine 'hash'
// builtin can reach the very same handlers.

#include "hash_registry.h"

#include <hash/md2.h>
#include <hash/md4.h>
#include <hash/md5.h>
#include <hash/md6.h>
#include <hash/sm3.h>
#include <hash/sha.h>
#include <hash/sha3.h>
#include <hash/ripemd.h>
#include <hash/blake2.h>
#include <hash/gost.h>
#include <hash/streebog.h>
#include <hash/skein.h>
#include <hash/fnv.h>
#include <hash/murmur3.h>
#include <hash/xxhash.h>
#include <hash/xxh3.h>
#include <hash/blake3.h>
#include <hash/groestl-ref.h>
#include <hash/haval.h>
#include <hash/jh-ref.h>
#include <hash/shash.h>
#include <hash/snefru.h>
#include <hash/tiger.h>
#include <hash/whirlpool.h>

#include <util/byte_to_str.h>
#include <filebuffer.h>
#include <string.h>
#include <alloc.h>
#include <defs.h>
#include <log.h>

#define GEN_HANDLE_FUNC(hash_name, ctx_t, init_func, update_func, final_func,  \
                        digest_size)                                           \
    static void handle_##hash_name(FileBuffer* fb, u64_t off, u64_t size,      \
                                   char** o_hash)                              \
    {                                                                          \
        u64_t original_off = fb->off;                                          \
                                                                               \
        ctx_t ctx;                                                             \
        init_func(&ctx);                                                       \
        u64_t processed = 0;                                                   \
        while (processed < size) {                                             \
            fb_seek(fb, off);                                                  \
            u64_t block_size = fb_block_size;                                  \
            if (block_size > size - processed)                                 \
                block_size = size - processed;                                 \
            const u8_t* data = fb_read(fb, block_size);                        \
            if (!data) {                                                       \
                /* do not silently return a digest computed over partial data: \
                   the caller reports an error when o_hash is NULL */          \
                error("unable to read the file at offset %llu", off);          \
                fb_seek(fb, original_off);                                     \
                *o_hash = NULL;                                                \
                return;                                                        \
            }                                                                  \
            update_func(&ctx, data, block_size);                               \
            processed += block_size;                                           \
            off += block_size;                                                 \
        }                                                                      \
        fb_seek(fb, original_off);                                             \
                                                                               \
        u8_t digest[digest_size];                                              \
        final_func(digest, &ctx);                                              \
        *o_hash = bytes_to_hex(digest, digest_size);                           \
    }

GEN_HANDLE_FUNC(md2, MD2_CTX, MD2Init, MD2Update, MD2Final, 16)
GEN_HANDLE_FUNC(md4, MD4_CTX, MD4Init, MD4Update, MD4Final, 16)
GEN_HANDLE_FUNC(md5, MD5_CTX, MD5Init, MD5Update, MD5Final, 16)
GEN_HANDLE_FUNC(md6_128, md6_state, MD6_128_Init, MD6Update, MD6Final,
                MD6_128_DIGEST_LENGTH)
GEN_HANDLE_FUNC(md6_256, md6_state, MD6_256_Init, MD6Update, MD6Final,
                MD6_256_DIGEST_LENGTH)
GEN_HANDLE_FUNC(md6_384, md6_state, MD6_384_Init, MD6Update, MD6Final,
                MD6_384_DIGEST_LENGTH)
GEN_HANDLE_FUNC(md6_512, md6_state, MD6_512_Init, MD6Update, MD6Final,
                MD6_512_DIGEST_LENGTH)
GEN_HANDLE_FUNC(sm3, sm3_ctx_t, SM3Init, SM3Update, SM3Finalize,
                SM3_DIGEST_LENGTH)
GEN_HANDLE_FUNC(sha1, SHA1Context, SHA1Reset, SHA1Input, SHA1Result,
                SHA1HashSize)
GEN_HANDLE_FUNC(sha256, SHA256Context, SHA256Reset, SHA256Input, SHA256Result,
                SHA256HashSize)
GEN_HANDLE_FUNC(sha224, SHA224Context, SHA224Reset, SHA224Input, SHA224Result,
                SHA224HashSize)
GEN_HANDLE_FUNC(sha384, SHA384Context, SHA384Reset, SHA384Input, SHA384Result,
                SHA384HashSize)
GEN_HANDLE_FUNC(sha512, SHA512Context, SHA512Reset, SHA512Input, SHA512Result,
                SHA512HashSize)
GEN_HANDLE_FUNC(sha512_224, SHA512Context, SHA512_224Reset, SHA512Input,
                SHA512_224Result, SHA512_224HashSize)
GEN_HANDLE_FUNC(sha512_256, SHA512Context, SHA512_256Reset, SHA512Input,
                SHA512_256Result, SHA512_256HashSize)
GEN_HANDLE_FUNC(sha3_128, sha3_context, SHA3_128_Init, SHA3Update, SHA3Finalize,
                SHA3_128_DIGEST_LENGTH)
GEN_HANDLE_FUNC(sha3_224, sha3_context, SHA3_224_Init, SHA3Update, SHA3Finalize,
                SHA3_224_DIGEST_LENGTH)
GEN_HANDLE_FUNC(sha3_256, sha3_context, SHA3_256_Init, SHA3Update, SHA3Finalize,
                SHA3_256_DIGEST_LENGTH)
GEN_HANDLE_FUNC(sha3_384, sha3_context, SHA3_384_Init, SHA3Update, SHA3Finalize,
                SHA3_384_DIGEST_LENGTH)
GEN_HANDLE_FUNC(sha3_512, sha3_context, SHA3_512_Init, SHA3Update, SHA3Finalize,
                SHA3_512_DIGEST_LENGTH)
GEN_HANDLE_FUNC(shake128_256, sha3_context, SHAKE128_Init, SHA3Update,
                SHAKE128_256Final, 32)
GEN_HANDLE_FUNC(shake256_512, sha3_context, SHAKE256_Init, SHA3Update,
                SHAKE256_512Final, 64)
GEN_HANDLE_FUNC(keccak_224, sha3_context, KECCAK_224_Init, SHA3Update,
                SHA3Finalize, SHA3_224_DIGEST_LENGTH)
GEN_HANDLE_FUNC(keccak_256, sha3_context, KECCAK_256_Init, SHA3Update,
                SHA3Finalize, SHA3_256_DIGEST_LENGTH)
GEN_HANDLE_FUNC(keccak_384, sha3_context, KECCAK_384_Init, SHA3Update,
                SHA3Finalize, SHA3_384_DIGEST_LENGTH)
GEN_HANDLE_FUNC(keccak_512, sha3_context, KECCAK_512_Init, SHA3Update,
                SHA3Finalize, SHA3_512_DIGEST_LENGTH)
GEN_HANDLE_FUNC(ripemd128, struct ripemd_ctx, ripemd128_init, ripemd_update,
                ripemd_final, RIPEMD128_DIGESTSIZE)
GEN_HANDLE_FUNC(ripemd160, struct ripemd_ctx, ripemd160_init, ripemd_update,
                ripemd_final, RIPEMD160_DIGESTSIZE)
GEN_HANDLE_FUNC(ripemd256, struct ripemd_ctx, ripemd256_init, ripemd_update,
                ripemd_final, RIPEMD256_DIGESTSIZE)
GEN_HANDLE_FUNC(ripemd320, struct ripemd_ctx, ripemd320_init, ripemd_update,
                ripemd_final, RIPEMD320_DIGESTSIZE)
GEN_HANDLE_FUNC(blake2s, blake2s_state, simple_blake2s_init,
                simple_blake2s_update, simple_blake2s_final, BLAKE2S_OUTBYTES)
GEN_HANDLE_FUNC(blake2b, blake2b_state, simple_blake2b_init,
                simple_blake2b_update, simple_blake2b_final, BLAKE2B_OUTBYTES)
GEN_HANDLE_FUNC(gost, GostHashCtx, GOSTInit, GOSTUpdate, GOSTFinal,
                GOST_DIGEST_LENGTH)
GEN_HANDLE_FUNC(skein_256_256, Skein_256_Ctxt_t, skein_256_256_init,
                Skein_256_Update, skein_256_256_final,
                SKEIN_256_256_DIGEST_LENGTH)
GEN_HANDLE_FUNC(skein_512_256, Skein_512_Ctxt_t, skein_512_256_init,
                Skein_512_Update, skein_512_final, SKEIN_512_256_DIGEST_LENGTH)
GEN_HANDLE_FUNC(skein_512_512, Skein_512_Ctxt_t, skein_512_512_init,
                Skein_512_Update, skein_512_final, SKEIN_512_512_DIGEST_LENGTH)
GEN_HANDLE_FUNC(skein_1024_1024, Skein1024_Ctxt_t, skein_1024_1024_init,
                Skein1024_Update, skein_1024_final,
                SKEIN1024_1024_DIGEST_LENGTH)
GEN_HANDLE_FUNC(streebog_256, StreebogCtx, streebog_256_init, streebog_update,
                streebog_final, STREEBOG_256_DIGEST_LENGTH)
GEN_HANDLE_FUNC(streebog_512, StreebogCtx, streebog_512_init, streebog_update,
                streebog_final, STREEBOG_512_DIGEST_LENGTH)
GEN_HANDLE_FUNC(blake2s_128, blake2s_state, simple_blake2s_128_init,
                simple_blake2s_update, simple_blake2s_128_final, 16)
GEN_HANDLE_FUNC(blake2s_160, blake2s_state, simple_blake2s_160_init,
                simple_blake2s_update, simple_blake2s_160_final, 20)
GEN_HANDLE_FUNC(blake2s_224, blake2s_state, simple_blake2s_224_init,
                simple_blake2s_update, simple_blake2s_224_final, 28)
GEN_HANDLE_FUNC(blake2b_160, blake2b_state, simple_blake2b_160_init,
                simple_blake2b_update, simple_blake2b_160_final, 20)
GEN_HANDLE_FUNC(blake2b_256, blake2b_state, simple_blake2b_256_init,
                simple_blake2b_update, simple_blake2b_256_final, 32)
GEN_HANDLE_FUNC(blake2b_384, blake2b_state, simple_blake2b_384_init,
                simple_blake2b_update, simple_blake2b_384_final, 48)
GEN_HANDLE_FUNC(blake3, blake3_hasher, blake3_hasher_init, blake3_hasher_update,
                blake3_hasher_finalize_std, BLAKE3_OUT_LEN)
GEN_HANDLE_FUNC(groestl_224, GroestlCtx, groestl_224_init, groestl_update,
                groestl_final, GROESTL_224_DIGEST_LENGTH)
GEN_HANDLE_FUNC(groestl_256, GroestlCtx, groestl_256_init, groestl_update,
                groestl_final, GROESTL_256_DIGEST_LENGTH)
GEN_HANDLE_FUNC(groestl_384, GroestlCtx, groestl_384_init, groestl_update,
                groestl_final, GROESTL_384_DIGEST_LENGTH)
GEN_HANDLE_FUNC(groestl_512, GroestlCtx, groestl_512_init, groestl_update,
                groestl_final, GROESTL_512_DIGEST_LENGTH)
GEN_HANDLE_FUNC(jh_224, jh_hashState, jh_224_init, jh_update_bytes,
                jh_final_wrap, JH_224_DIGEST_LENGTH)
GEN_HANDLE_FUNC(jh_256, jh_hashState, jh_256_init, jh_update_bytes,
                jh_final_wrap, JH_256_DIGEST_LENGTH)
GEN_HANDLE_FUNC(jh_384, jh_hashState, jh_384_init, jh_update_bytes,
                jh_final_wrap, JH_384_DIGEST_LENGTH)
GEN_HANDLE_FUNC(jh_512, jh_hashState, jh_512_init, jh_update_bytes,
                jh_final_wrap, JH_512_DIGEST_LENGTH)
GEN_HANDLE_FUNC(snefru_128, SnefruCtx, snefru_128_init, snefru_update,
                snefru_final, SNEFRU_128_DIGEST_LENGTH)
GEN_HANDLE_FUNC(snefru_256, SnefruCtx, snefru_256_init, snefru_update,
                snefru_final, SNEFRU_256_DIGEST_LENGTH)
GEN_HANDLE_FUNC(shash_256, SpectralHashCtx, shash_256_init, shash_update,
                shash_final, SHASH_256_DIGEST_LENGTH)
GEN_HANDLE_FUNC(shash_512, SpectralHashCtx, shash_512_init, shash_update,
                shash_final, SHASH_512_DIGEST_LENGTH)
GEN_HANDLE_FUNC(haval_128_3, HavalCtx, haval_128_3_init, haval_update,
                haval_final, HAVAL_128_DIGEST_LENGTH)
GEN_HANDLE_FUNC(haval_128_4, HavalCtx, haval_128_4_init, haval_update,
                haval_final, HAVAL_128_DIGEST_LENGTH)
GEN_HANDLE_FUNC(haval_128_5, HavalCtx, haval_128_5_init, haval_update,
                haval_final, HAVAL_128_DIGEST_LENGTH)
GEN_HANDLE_FUNC(haval_160_3, HavalCtx, haval_160_3_init, haval_update,
                haval_final, HAVAL_160_DIGEST_LENGTH)
GEN_HANDLE_FUNC(haval_160_4, HavalCtx, haval_160_4_init, haval_update,
                haval_final, HAVAL_160_DIGEST_LENGTH)
GEN_HANDLE_FUNC(haval_160_5, HavalCtx, haval_160_5_init, haval_update,
                haval_final, HAVAL_160_DIGEST_LENGTH)
GEN_HANDLE_FUNC(haval_192_3, HavalCtx, haval_192_3_init, haval_update,
                haval_final, HAVAL_192_DIGEST_LENGTH)
GEN_HANDLE_FUNC(haval_192_4, HavalCtx, haval_192_4_init, haval_update,
                haval_final, HAVAL_192_DIGEST_LENGTH)
GEN_HANDLE_FUNC(haval_192_5, HavalCtx, haval_192_5_init, haval_update,
                haval_final, HAVAL_192_DIGEST_LENGTH)
GEN_HANDLE_FUNC(haval_224_3, HavalCtx, haval_224_3_init, haval_update,
                haval_final, HAVAL_224_DIGEST_LENGTH)
GEN_HANDLE_FUNC(haval_224_4, HavalCtx, haval_224_4_init, haval_update,
                haval_final, HAVAL_224_DIGEST_LENGTH)
GEN_HANDLE_FUNC(haval_224_5, HavalCtx, haval_224_5_init, haval_update,
                haval_final, HAVAL_224_DIGEST_LENGTH)
GEN_HANDLE_FUNC(haval_256_3, HavalCtx, haval_256_3_init, haval_update,
                haval_final, HAVAL_256_DIGEST_LENGTH)
GEN_HANDLE_FUNC(haval_256_4, HavalCtx, haval_256_4_init, haval_update,
                haval_final, HAVAL_256_DIGEST_LENGTH)
GEN_HANDLE_FUNC(haval_256_5, HavalCtx, haval_256_5_init, haval_update,
                haval_final, HAVAL_256_DIGEST_LENGTH)
GEN_HANDLE_FUNC(xxh32, XxhCtx, xxh32_init, xxh_update, xxh_final,
                XXH32_DIGEST_LENGTH)
GEN_HANDLE_FUNC(xxh64, XxhCtx, xxh64_init, xxh_update, xxh_final,
                XXH64_DIGEST_LENGTH)
GEN_HANDLE_FUNC(xxh3_64, Xxh3Ctx, xxh3_64_init, xxh3_update, xxh3_final,
                XXH3_64_DIGEST_LENGTH)
GEN_HANDLE_FUNC(xxh3_128, Xxh3Ctx, xxh3_128_init, xxh3_update, xxh3_final,
                XXH3_128_DIGEST_LENGTH)
GEN_HANDLE_FUNC(murmur3_32, Murmur3Ctx, murmur3_x86_32_init, murmur3_update,
                murmur3_final, MURMUR3_32_DIGEST_LENGTH)
GEN_HANDLE_FUNC(murmur3_128, Murmur3Ctx, murmur3_x64_128_init, murmur3_update,
                murmur3_final, MURMUR3_128_DIGEST_LENGTH)
GEN_HANDLE_FUNC(fnv1_32, FnvCtx, fnv1_32_init, fnv_update, fnv_final,
                FNV_32_DIGEST_LENGTH)
GEN_HANDLE_FUNC(fnv1a_32, FnvCtx, fnv1a_32_init, fnv_update, fnv_final,
                FNV_32_DIGEST_LENGTH)
GEN_HANDLE_FUNC(fnv1_64, FnvCtx, fnv1_64_init, fnv_update, fnv_final,
                FNV_64_DIGEST_LENGTH)
GEN_HANDLE_FUNC(fnv1a_64, FnvCtx, fnv1a_64_init, fnv_update, fnv_final,
                FNV_64_DIGEST_LENGTH)
GEN_HANDLE_FUNC(tiger, TigerCtx, tiger_init, tiger_update, tiger_final,
                TIGER_DIGEST_LENGTH)
GEN_HANDLE_FUNC(tiger2, TigerCtx, tiger2_init, tiger_update, tiger_final,
                TIGER_DIGEST_LENGTH)
GEN_HANDLE_FUNC(whirlpool, WhirlpoolCtx, whirlpool_init, whirlpool_update,
                whirlpool_final, WHIRLPOOL_DIGEST_LENGTH)

static hash_handler_t hash_handlers[] = {
    {"md2", handle_md2},
    {"md4", handle_md4},
    {"md5", handle_md5},
    {"md6-128", handle_md6_128},
    {"md6-256", handle_md6_256},
    {"md6-384", handle_md6_384},
    {"md6-512", handle_md6_512},
    {"sm3", handle_sm3},
    {"sha1", handle_sha1},
    {"sha224", handle_sha224},
    {"sha256", handle_sha256},
    {"sha384", handle_sha384},
    {"sha512", handle_sha512},
    {"sha512-224", handle_sha512_224},
    {"sha512-256", handle_sha512_256},
    {"sha3-128", handle_sha3_128},
    {"sha3-224", handle_sha3_224},
    {"sha3-256", handle_sha3_256},
    {"sha3-384", handle_sha3_384},
    {"sha3-512", handle_sha3_512},
    {"shake128-256", handle_shake128_256},
    {"shake256-512", handle_shake256_512},
    {"keccak-224", handle_keccak_224},
    {"keccak-256", handle_keccak_256},
    {"keccak-384", handle_keccak_384},
    {"keccak-512", handle_keccak_512},
    {"RipeMD-128", handle_ripemd128},
    {"RipeMD-160", handle_ripemd160},
    {"RipeMD-256", handle_ripemd256},
    {"RipeMD-320", handle_ripemd320},
    {"blake2s", handle_blake2s},
    {"blake2b", handle_blake2b},
    {"blake2s-128", handle_blake2s_128},
    {"blake2s-160", handle_blake2s_160},
    {"blake2s-224", handle_blake2s_224},
    {"blake2b-160", handle_blake2b_160},
    {"blake2b-256", handle_blake2b_256},
    {"blake2b-384", handle_blake2b_384},
    {"blake3", handle_blake3},
    {"gost", handle_gost},
    {"skein-256-256", handle_skein_256_256},
    {"skein-512-256", handle_skein_512_256},
    {"skein-512-512", handle_skein_512_512},
    {"skein-1024-1024", handle_skein_1024_1024},
    {"streebog-256", handle_streebog_256},
    {"streebog-512", handle_streebog_512},
    {"groestl-224", handle_groestl_224},
    {"groestl-256", handle_groestl_256},
    {"groestl-384", handle_groestl_384},
    {"groestl-512", handle_groestl_512},
    {"jh-224", handle_jh_224},
    {"jh-256", handle_jh_256},
    {"jh-384", handle_jh_384},
    {"jh-512", handle_jh_512},
    {"snefru-128", handle_snefru_128},
    {"snefru-256", handle_snefru_256},
    {"spectral-256", handle_shash_256},
    {"spectral-512", handle_shash_512},
    {"haval-128-3", handle_haval_128_3},
    {"haval-128-4", handle_haval_128_4},
    {"haval-128-5", handle_haval_128_5},
    {"haval-160-3", handle_haval_160_3},
    {"haval-160-4", handle_haval_160_4},
    {"haval-160-5", handle_haval_160_5},
    {"haval-192-3", handle_haval_192_3},
    {"haval-192-4", handle_haval_192_4},
    {"haval-192-5", handle_haval_192_5},
    {"haval-224-3", handle_haval_224_3},
    {"haval-224-4", handle_haval_224_4},
    {"haval-224-5", handle_haval_224_5},
    {"haval-256-3", handle_haval_256_3},
    {"haval-256-4", handle_haval_256_4},
    {"haval-256-5", handle_haval_256_5},
    {"xxh32", handle_xxh32},
    {"xxh64", handle_xxh64},
    {"xxh3-64", handle_xxh3_64},
    {"xxh3-128", handle_xxh3_128},
    {"murmur3-32", handle_murmur3_32},
    {"murmur3-128", handle_murmur3_128},
    {"fnv1-32", handle_fnv1_32},
    {"fnv1a-32", handle_fnv1a_32},
    {"fnv1-64", handle_fnv1_64},
    {"fnv1a-64", handle_fnv1a_64},
    {"tiger", handle_tiger},
    {"tiger2", handle_tiger2},
    {"whirlpool", handle_whirlpool}};
#define NUM_HASH_HANDLERS (sizeof(hash_handlers) / sizeof(hash_handlers[0]))

const hash_handler_t* get_hash_by_name(const char* name)
{
    for (size_t i = 0; i < NUM_HASH_HANDLERS; ++i)
        if (strcmp(hash_handlers[i].name, name) == 0)
            return &hash_handlers[i];
    return NULL;
}

const hash_handler_t* get_all_hashes(size_t* o_count)
{
    *o_count = NUM_HASH_HANDLERS;
    return hash_handlers;
}
