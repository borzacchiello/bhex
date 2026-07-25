// Copyright (c) 2022-2026, bageyelet

#ifndef HASH_REGISTRY_H
#define HASH_REGISTRY_H

#include <filebuffer.h>
#include <stddef.h>
#include <defs.h>

// Computes the hash of [off, off + size) and returns it as a hex string
// that the caller owns. *o_hash is NULL if the file cannot be read.
typedef struct hash_handler_t {
    const char* name;
    void (*handler)(FileBuffer* fb, u64_t off, u64_t size, char** o_hash);
} hash_handler_t;

const hash_handler_t* get_hash_by_name(const char* name);

// Returns the whole table, and its size through o_count
const hash_handler_t* get_all_hashes(size_t* o_count);

#endif
