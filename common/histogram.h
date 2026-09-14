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

// Called once per bucket, with the byte counts of that bucket
typedef void (*histogram_bucket_cb)(u64_t off, u64_t size,
                                    const u64_t counts[256], void* user);

// Splits [off, off + size) into `nbuckets` contiguous slices and counts each
// one, calling `cb` as it goes. The slices are walked in order, so the file
// is read once from front to back, and only one set of counters is ever live:
// the caller decides what to keep, which is what lets a map of a large file
// cost nothing beyond the row it is drawing.
//
// The sizes differ by at most one byte when the range does not divide evenly.
// Returns the number of bytes actually counted.
u64_t calculate_histogram_buckets(FileBuffer* fb, u64_t off, u64_t size,
                                  u64_t nbuckets, histogram_bucket_cb cb,
                                  void* user);

#endif
