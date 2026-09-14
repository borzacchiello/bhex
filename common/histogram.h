// Copyright (c) 2022-2026, bageyelet

#ifndef COMMON_HISTOGRAM_H
#define COMMON_HISTOGRAM_H

#include <filebuffer.h>
#include <defs.h>

// Counts how often each byte value occurs in [off, off+size) of `fb`, and
// returns the number of bytes actually counted: that is `size`, unless the
// range falls outside the file (nothing is counted) or the file could not be
// read to the end of it.
u64_t calculate_histogram(FileBuffer* fb, u64_t off, u64_t size,
                          u64_t counts[256]);

#endif
