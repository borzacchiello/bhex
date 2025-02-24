#include "cmd_search.h"
#include "cmd.h"
#include "cmd_arg_handler.h"

#include <util/str.h>
#include <util/print.h>
#include <string.h>
#include <alloc.h>
#include <log.h>

#define HINT_STR "[/{x, s}/sk/p] <what>"

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))

#define N_BLOCKS 512

#define is_within_block(block_n, block_off, block_size)                        \
    ((((block_n) < N_BLOCKS - 1) && ((block_off) < (block_size))) ||           \
     ((block_n) == N_BLOCKS - 1))

#define DATA_TYPE_UNSET  -1
#define DATA_TYPE_STRING 0
#define DATA_TYPE_HEX    1

#define SEEK_TO_MATCH_UNSET -1
#define SEEK_TO_MATCH_SET   0

#define PRINT_CTX_UNSET -1
#define PRINT_CTX_SET   0

typedef struct {
    u8_t min;
    u8_t max;
} BlockInfo;

typedef struct {
    BlockInfo blocks[N_BLOCKS];
    u64_t     block_size;
    int       has_index;
    u64_t     version;
} SearchCtx;

static inline BlockInfo* get_block_at(SearchCtx* ctx, u64_t addr)
{
    u64_t off = addr / ctx->block_size;
    if (off >= N_BLOCKS)
        panic("invalid address");
    return &ctx->blocks[off];
}

static void searchcmd_dispose(void* obj) { bhex_free(obj); }

static void searchcmd_help(void* obj)
{
    printf("\nsearch: search a string or a sequence of bytes in the file\n"
           "\n"
           "  src" HINT_STR "\n"
           "     x:  data is an hex string\n"
           "     s:  data is a string (default)\n"
           "     sk: seek to first match\n"
           "     c:  print context\n"
           "\n"
           "  data: either a string or an hex string\n"
           "\n");
}

static void populate_index(SearchCtx* ctx, FileBuffer* fb)
{
    if (ctx->has_index && (ctx->version == fb->version))
        return;

    ctx->version = fb->version;
    if (fb->size < N_BLOCKS * 8) {
        // if the file size is not big enough, it makes
        // no sense to keep the index
        ctx->has_index = 0;
        return;
    }
    ctx->has_index = 1;

    u64_t orig_off = fb->off;
    fb_seek(fb, 0);

    u32_t block_n      = 0;
    u32_t block_off    = 0;
    ctx->blocks[0].min = 255;
    ctx->blocks[0].max = 0;
    ctx->block_size    = fb->size / N_BLOCKS + 1;

    u64_t addr = 0;
    while (addr < fb->size) {
        fb_seek(fb, addr);
        const u8_t* block = fb_read(fb, min(fb_block_size, fb->size - fb->off));
        u32_t       i;
        for (i = 0; i < min(fb_block_size, fb->size - fb->off); i++) {
            if (!is_within_block(block_n, block_off, ctx->block_size)) {
                block_n += 1;
                block_off = 0;

                ctx->blocks[block_n].min = 255;
                ctx->blocks[block_n].max = 0;
            }
            if (block[i] < ctx->blocks[block_n].min)
                ctx->blocks[block_n].min = block[i];
            if (block[i] > ctx->blocks[block_n].max)
                ctx->blocks[block_n].max = block[i];
            block_off += 1;
        }
        addr += min(fb_block_size, fb->size - fb->off);
    }
    fb_seek(fb, orig_off);
}

__attribute__((unused)) static void print_block_info(SearchCtx*  ctx,
                                                     FileBuffer* fb)
{
    populate_index(ctx, fb);
    if (!ctx->has_index) {
        warning("file is too short, no blocks info");
        return;
    }

    size_t i;
    for (i = 0; i < N_BLOCKS; ++i) {
        BlockInfo* binfo    = &ctx->blocks[i];
        u64_t      min_addr = i * ctx->block_size;
        u64_t      max_addr = i == N_BLOCKS - 1 ? (fb->size - 1)
                                                : (min_addr + ctx->block_size - 1);
        printf(" 0x%08llx - 0x%08llx : [min %3u, max %3u]\n", min_addr,
               max_addr, binfo->min, binfo->max);
    }
}

static void search(SearchCtx* ctx, FileBuffer* fb, const u8_t* data,
                   size_t size, int print_context, int seek_to_match)
{
    if (size == 0)
        return;
    populate_index(ctx, fb);

    u64_t orig_off = fb->off;
    fb_seek(fb, 0);

    size_t buf_off  = 0;
    size_t buf_size = max(size * 2, fb_block_size * 2);
    u8_t*  buf      = bhex_malloc(buf_size);

    memcpy(buf, fb_read(fb, min(buf_size / 2, fb->size)),
           min(buf_size / 2, fb->size));

    u8_t   data_min = data[0];
    u8_t   data_max = data[0];
    size_t i;
    for (i = 1; i < size; ++i) {
        if (data[i] < data_min)
            data_min = data[i];
        if (data[i] > data_max)
            data_max = data[i];
    }

    u64_t addr = 0;
    while (addr + size <= fb->size) {
        if (ctx->has_index) {
            BlockInfo* binfo = get_block_at(ctx, addr);
            if (!(binfo->min <= data_min && data_max <= binfo->max)) {
                // skip a block
                addr = (addr / ctx->block_size) * ctx->block_size +
                       ctx->block_size;
                buf_off = 0;
                continue;
            }
        }
        u64_t begin_addr = addr;

        int    eq = 1;
        size_t j  = 0;
        for (j = 0; j < size; ++j) {
            size_t curr_off = (buf_off + j) % buf_size;
            if (curr_off == 0 && fb->off != addr + j) {
                fb_seek(fb, addr + j);
                memcpy(buf, fb_read(fb, min(buf_size / 2, fb->size - fb->off)),
                       min(buf_size / 2, fb->size - fb->off));
            } else if (curr_off == buf_size / 2 && fb->off != addr + j) {
                fb_seek(fb, addr + j);
                memcpy(buf + buf_size / 2,
                       fb_read(fb, min(buf_size / 2, fb->size - fb->off)),
                       min(buf_size / 2, fb->size - fb->off));
            }

            eq = data[j] == buf[curr_off];
            if (!eq)
                break;
        }
        if (eq) {
            printf(" >> Match @ 0x%07llX\n", begin_addr);
            if (seek_to_match) {
                seek_to_match = 0;
                orig_off      = begin_addr;
            }
            if (print_context) {
                u64_t print_addr_begin = begin_addr;
                u64_t print_addr_end   = begin_addr + size;

#define PRINT_RANGE 16
                // if we have enough bytes, expand by PRINT_RANGE bytes before
                // and after
                print_addr_begin = print_addr_begin >= PRINT_RANGE
                                       ? print_addr_begin - PRINT_RANGE
                                       : 0;
                print_addr_end   = print_addr_end + PRINT_RANGE >= fb->size
                                       ? fb->size
                                       : print_addr_end + PRINT_RANGE;

                fb_seek(fb, print_addr_begin);
                const u8_t* data_to_print =
                    fb_read(fb, print_addr_end - print_addr_begin);
                print_hex(data_to_print, print_addr_end - print_addr_begin, 0,
                          1, 1, print_addr_begin);
            }
        }

        addr += 1;
        buf_off += 1;
    }

    bhex_free(buf);
    fb_seek(fb, orig_off);
}

static int searchcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    SearchCtx* ctx = (SearchCtx*)obj;

    int data_type     = DATA_TYPE_STRING;
    int seek_to_match = SEEK_TO_MATCH_UNSET;
    int print_context = PRINT_CTX_UNSET;
    if (handle_mods(pc, "x,s|sk|p", &data_type, &seek_to_match,
                    &print_context) == 0)
        return COMMAND_INVALID_MOD;

    char* data_str;
    if (handle_args(pc, 1, 1, &data_str) != 0)
        return COMMAND_INVALID_ARG;

    u8_t*  data      = NULL;
    size_t data_size = 0;
    switch (data_type) {
        case DATA_TYPE_STRING:
            if (!unescape_ascii_string(data_str, &data, &data_size))
                return COMMAND_INVALID_ARG;
            break;
        case DATA_TYPE_HEX:
            if (!hex_to_bytes(data_str, &data, &data_size))
                return COMMAND_INVALID_ARG;
            break;
    }

    search(ctx, fb, data, data_size, print_context == PRINT_CTX_SET,
           seek_to_match == SEEK_TO_MATCH_SET);
    bhex_free(data);
    return COMMAND_OK;
}

Cmd* searchcmd_create(void)
{
    Cmd*       cmd = bhex_malloc(sizeof(Cmd));
    SearchCtx* ctx = bhex_malloc(sizeof(SearchCtx));

    ctx->has_index = 0;
    ctx->version   = 0;

    cmd->obj   = ctx;
    cmd->name  = "search";
    cmd->alias = "src";
    cmd->hint  = HINT_STR;

    cmd->dispose = searchcmd_dispose;
    cmd->help    = searchcmd_help;
    cmd->exec    = searchcmd_exec;

    return cmd;
}
