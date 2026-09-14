// Copyright (c) 2022-2026, bageyelet

#include "histogram.h"

#include <filebuffer.h>
#include <string.h>
#include <defs.h>
#include <log.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

u64_t calculate_histogram_buckets(FileBuffer* fb, u64_t off, u64_t size,
                                  u64_t nbuckets, histogram_bucket_cb cb,
                                  void* user)
{
    if (nbuckets == 0)
        return 0;

    u64_t counts[256];
    // spread the remainder one byte at a time over the first buckets, rather
    // than multiplying an index by the size: the product would overflow on a
    // range this code is otherwise happy to take
    u64_t base = size / nbuckets;
    u64_t rem  = size % nbuckets;

    u64_t curr  = off;
    u64_t total = 0;
    for (u64_t i = 0; i < nbuckets; ++i) {
        u64_t bsize = base + (i < rem ? 1 : 0);
        total += calculate_histogram(fb, curr, bsize, counts);
        cb(curr, bsize, counts, user);
        curr += bsize;
    }
    return total;
}

u64_t calculate_histogram(FileBuffer* fb, u64_t off, u64_t size,
                          u64_t counts[256])
{
    memset(counts, 0, 256 * sizeof(counts[0]));
    if (size == 0 || off > fb->size || fb->size - off < size)
        return 0;

    u64_t orig_off = fb->off;
    u64_t total    = 0;

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

        for (size_t i = 0; i < len; ++i)
            counts[buf[i]] += 1;
        total += len;
        curr_off += len;
    }

    fb_seek(fb, orig_off);
    return total;
}
