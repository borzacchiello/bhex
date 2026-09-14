// Copyright (c) 2022-2026, bageyelet

#include "entropy.h"

#include <util/math.h>
#include <histogram.h>
#include <filebuffer.h>
#include <defs.h>
#include <log.h>

float entropy_from_counts(const u64_t counts[256], u64_t total)
{
    if (total == 0)
        return 0.0f;

    float entropy = 0;
    u32_t i;
    for (i = 0; i < 256; ++i) {
        float px = (float)counts[i] / (float)total;
        if (px > 0)
            entropy += -px * _log2(px);
    }
    if (entropy < 0.0f)
        entropy = 0.0f;

    return entropy;
}

// The Shannon entropy is a summary of the byte histogram, so the counting is
// shared with the 'hist' command and only the summing lives here
float calculate_entropy(FileBuffer* fb, u64_t off, u64_t size)
{
    u64_t counts[256];
    u64_t total = calculate_histogram(fb, off, size, counts);
    return entropy_from_counts(counts, total);
}
