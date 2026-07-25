// Copyright (c) 2022-2026, bageyelet

#ifndef COMMON_ENTROPY_H
#define COMMON_ENTROPY_H

#include <filebuffer.h>
#include <defs.h>

// Shannon entropy (0 - 8) of the [off, off + size) region of the file.
// The current offset is left untouched. Returns 0 for an empty region, or for
// a region that extends past the end of the file.
float calculate_entropy(FileBuffer* fb, u64_t off, u64_t size);

#endif
