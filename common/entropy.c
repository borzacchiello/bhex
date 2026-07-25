// Copyright (c) 2022-2026, bageyelet

#include "entropy.h"

#include <util/math.h>
#include <filebuffer.h>
#include <defs.h>
#include <log.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

float calculate_entropy(FileBuffer* fb, u64_t off, u64_t size)
{
    if (size == 0 || off > fb->size || fb->size - off < size)
        return 0.0f;

    u64_t orig_off    = fb->off;
    u32_t counts[256] = {0};

    u64_t curr_off = off;
    u64_t max_addr = off + size;
    while (curr_off < max_addr) {
        fb_seek(fb, curr_off);

        size_t      len = min(fb_block_size, max_addr - curr_off);
        const u8_t* buf = fb_read(fb, len);
        if (buf == NULL) {
            // the file shrank under us: use the bytes gathered so far
            error("unable to read the file at offset %llu", curr_off);
            break;
        }

        size_t i;
        for (i = 0; i < len; ++i)
            counts[buf[i]] += 1;
        curr_off += len;
    }

    float entropy = 0;
    u32_t i;
    for (i = 0; i < 256; ++i) {
        float px = (float)counts[i] / size;
        if (px > 0)
            entropy += -px * _log2(px);
    }
    if (entropy < 0.0f)
        entropy = 0.0f;

    fb_seek(fb, orig_off);
    return entropy;
}
