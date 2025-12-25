#include <hash/md2.h>
#include <hash/md4.h>
#include <hash/md5.h>
#include <hash/md6.h>
#include <hash/sha.h>
#include <hash/sha3.h>
#include <hash/ripemd.h>
#include <hash/whirlpool.h>

#include <util/byte_to_str.h>
#include <util/byte_to_num.h>
#include <display.h>
#include <alloc.h>
#include <log.h>

#include "cmd_arg_handler.h"
#include "defs.h"
#include "cmd_hash.h"

#define LIST_SET 0

#define HINT_STR "/l <algorithm> [<size> <off>]"
#define HELP_STR                                                               \
    "hash: calculate the hash of <size> bytes at current offset + <off>\n"     \
    "\n"                                                                       \
    "  hash " HINT_STR "\n"                                                    \
    "     l:  list the supported hashing algorithms\n"                         \
    "\n"                                                                       \
    "  algorithm: hashing algorithm (or '*' to use all supported "             \
    "algorithms)\n"                                                            \
    "  size:      number of bytes to include in the hash (if omitted or "      \
    "zero, hash the whole file starting from current offset)\n"                \
    "  offset:    starting offset of the hashed file (if omitted, hash "       \
    "from current offset)\n"

typedef struct hash_handler_t {
    const char* name;
    void (*handler)(FileBuffer* fb, u64_t off, u64_t size, char** o_hash);
} hash_handler_t;

static void hashcmd_dispose(void* obj) { return; }

static void hashcmd_help(void* obj) { display_printf(HELP_STR); }

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
            if (!data)                                                         \
                break;                                                         \
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
GEN_HANDLE_FUNC(ripemd128, struct ripemd_ctx, ripemd128_init, ripemd_update,
                ripemd_final, RIPEMD128_DIGESTSIZE)
GEN_HANDLE_FUNC(ripemd160, struct ripemd_ctx, ripemd160_init, ripemd_update,
                ripemd_final, RIPEMD160_DIGESTSIZE)
GEN_HANDLE_FUNC(ripemd256, struct ripemd_ctx, ripemd256_init, ripemd_update,
                ripemd_final, RIPEMD256_DIGESTSIZE)
GEN_HANDLE_FUNC(ripemd320, struct ripemd_ctx, ripemd320_init, ripemd_update,
                ripemd_final, RIPEMD320_DIGESTSIZE)
GEN_HANDLE_FUNC(whirlpool, whirlpool_ctx, rhash_whirlpool_init,
                rhash_whirlpool_update, rhash_whirlpool_final,
                whirlpool_block_size)

static hash_handler_t hash_handlers[] = {{"md2", handle_md2},
                                         {"md4", handle_md4},
                                         {"md5", handle_md5},
                                         {"md6-128", handle_md6_128},
                                         {"md6-256", handle_md6_256},
                                         {"md6-384", handle_md6_384},
                                         {"md6-512", handle_md6_512},
                                         {"sha1", handle_sha1},
                                         {"sha224", handle_sha224},
                                         {"sha256", handle_sha256},
                                         {"sha384", handle_sha384},
                                         {"sha512", handle_sha512},
                                         {"sha3-128", handle_sha3_128},
                                         {"sha3-224", handle_sha3_224},
                                         {"sha3-256", handle_sha3_256},
                                         {"sha3-384", handle_sha3_384},
                                         {"sha3-512", handle_sha3_512},
                                         {"RipeMD-128", handle_ripemd128},
                                         {"RipeMD-160", handle_ripemd160},
                                         {"RipeMD-256", handle_ripemd256},
                                         {"RipeMD-320", handle_ripemd320},
                                         {"whirlpool", handle_whirlpool}};
#define NUM_HASH_HANDLERS (sizeof(hash_handlers) / sizeof(hash_handlers[0]))

static int hashcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    int list = -1;
    if (handle_mods(pc, "l", &list) != 0)
        return COMMAND_INVALID_MOD;

    if (list == LIST_SET) {
        if (handle_args(pc, 0, 0) != 0)
            return COMMAND_INVALID_ARG;

        for (size_t i = 0; i < NUM_HASH_HANDLERS; ++i)
            display_printf("  %s\n", hash_handlers[i].name);

        return COMMAND_OK;
    }

    char* algorithm  = NULL;
    char* size_str   = NULL;
    char* offset_str = NULL;
    if (handle_args(pc, 3, 1, &algorithm, &size_str, &offset_str) != 0)
        return COMMAND_INVALID_ARG;

    u64_t size = fb->size - fb->off;
    u64_t off  = 0;
    if (size_str) {
        if (!str_to_uint64(size_str, &size)) {
            error("invalid number '%s'", size_str);
            return COMMAND_INVALID_ARG;
        }
    }
    if (offset_str) {
        if (!str_to_uint64(offset_str, &off)) {
            error("invalid number '%s'", offset_str);
            return COMMAND_INVALID_ARG;
        }
    }

    if (size > fb->size - fb->off) {
        error("invalid size, exceeding file size");
        return COMMAND_INVALID_ARG;
    }

    if (off > fb->size - fb->off) {
        error("invalid offset, exceeding file size");
        return COMMAND_INVALID_ARG;
    }

    u64_t real_off = fb->off + off;
    if (real_off + size > fb->size) {
        error("calculated offset exceeds file size");
        return COMMAND_INVALID_ARG;
    }

    for (size_t i = 0; i < NUM_HASH_HANDLERS; ++i) {
        if (strcmp(algorithm, "*") == 0 ||
            strstr(hash_handlers[i].name, algorithm) != NULL) {
            char* hash = NULL;
            hash_handlers[i].handler(fb, real_off, size, &hash);
            if (hash) {
                display_printf("  %12s : %s\n", hash_handlers[i].name, hash);
                bhex_free(hash);
            } else {
                error("error calculating %s hash", hash_handlers[i].name);
                return COMMAND_INTERNAL_ERROR;
            }
        }
    }
    return COMMAND_OK;
}

Cmd* hashcmd_create()
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "hash";
    cmd->alias = "hh";
    cmd->hint  = HINT_STR;

    cmd->dispose = hashcmd_dispose;
    cmd->help    = hashcmd_help;
    cmd->exec    = hashcmd_exec;
    return cmd;
}
