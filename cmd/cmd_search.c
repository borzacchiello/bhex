#include "cmd_search.h"

#include <string.h>

#include "util/str.h"
#include "../alloc.h"
#include "../log.h"

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))

#define N_BLOCKS 1024

#define is_within_block(block_n, block_off, block_size)                        \
    ((((block_n) < N_BLOCKS - 1) && ((block_off) < (block_size))) ||           \
     ((block_n) == N_BLOCKS - 1))

#define DATA_TYPE_UNSET  0
#define DATA_TYPE_STRING 1
#define DATA_TYPE_HEX    2

#define SEEK_TO_MATCH_UNSET 0
#define SEEK_TO_MATCH_SET   1

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

static void searchcmd_dispose(void* obj) { free(obj); }

static void searchcmd_help(void* obj)
{
    printf("\nsearch: search a string or a sequence of bytes in the file\n"
           "\n"
           "  s[/{x, s}/sk] <data>\n"
           "     x:  data is an hex string\n"
           "     s:  data is a string (default)\n"
           "     sk: seek to first match\n"
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
    ctx->block_size    = fb->size / (N_BLOCKS - 1);

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

static void search(SearchCtx* ctx, FileBuffer* fb, const u8_t* data,
                   size_t size, int seek_to_match)
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
                addr += ctx->block_size;
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
        }

        addr += 1;
        buf_off += 1;
    }

    bhex_free(buf);
    fb_seek(fb, orig_off);
}

static int searchcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    int     data_type     = DATA_TYPE_UNSET;
    int     seek_to_match = SEEK_TO_MATCH_UNSET;
    LLNode* curr          = pc->cmd_modifiers.head;
    while (curr) {
        if (strcmp((char*)curr->data, "s") == 0) {
            if (data_type != DATA_TYPE_UNSET)
                return COMMAND_INVALID_MODE;
            data_type = DATA_TYPE_STRING;
        } else if (strcmp((char*)curr->data, "x") == 0) {
            if (data_type != DATA_TYPE_UNSET)
                return COMMAND_INVALID_MODE;
            data_type = DATA_TYPE_HEX;
        } else if (strcmp((char*)curr->data, "sk") == 0) {
            if (seek_to_match != SEEK_TO_MATCH_UNSET)
                return COMMAND_INVALID_MODE;
            seek_to_match = SEEK_TO_MATCH_SET;
        } else
            return COMMAND_INVALID_MODE;
        curr = curr->next;
    }

    if (data_type == DATA_TYPE_UNSET)
        data_type = DATA_TYPE_STRING;

    if (pc->args.size != 1)
        return COMMAND_INVALID_ARG;

    u8_t*  data      = NULL;
    size_t data_size = 0;
    char*  data_str  = (char*)pc->args.head->data;
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

    SearchCtx* ctx = (SearchCtx*)obj;
    search(ctx, fb, data, data_size, seek_to_match == SEEK_TO_MATCH_SET);
    bhex_free(data);
    return COMMAND_OK;
}

Cmd* searchcmd_create()
{
    Cmd*       cmd = bhex_malloc(sizeof(Cmd));
    SearchCtx* ctx = bhex_malloc(sizeof(SearchCtx));

    ctx->has_index = 0;
    ctx->version   = 0;

    cmd->obj   = ctx;
    cmd->name  = "search";
    cmd->alias = "src";

    cmd->dispose = searchcmd_dispose;
    cmd->help    = searchcmd_help;
    cmd->exec    = searchcmd_exec;

    return cmd;
}
