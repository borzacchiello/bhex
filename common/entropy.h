// Copyright (c) 2022-2026, bageyelet

#ifndef COMMON_ENTROPY_H
#define COMMON_ENTROPY_H

#include <filebuffer.h>
#include <defs.h>

// Shannon entropy (0 - 8) of the [off, off + size) region of the file.
// The current offset is left untouched. Returns 0 for an empty region, or for
// a region that extends past the end of the file.
float calculate_entropy(FileBuffer* fb, u64_t off, u64_t size);

// The same measure over a distribution that has already been counted, where
// `total` is how many bytes those counts came from. It is here for the
// callers that are walking the file anyway and would rather not walk it twice
// -- 'info' hashes and counts in the same pass. Returns 0 when total is 0.
//
// The counts are 64 bit on purpose: a byte value can occur more than 2^32
// times in a file bigger than 4 GB, and a counter that wraps there does not
// report an error, it reports a plausible wrong number.
float entropy_from_counts(const u64_t counts[256], u64_t total);

#endif
