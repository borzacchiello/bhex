// Copyright (c) 2022-2026, bageyelet

#ifndef FILEBUFFER_H
#define FILEBUFFER_H

/*
   It is a wrapper of FILE* that allows to undo modifications.
   It adopts a best-effort approach to handle external modifications,
   tring to minimize the damage if another application is modifing the same
   file.
*/

#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <defs.h>

#include <ll.h>

#define fb_block_size 4096
#define fb_index_size 512

typedef struct Modification {
    s8_t   type;
    u32_t  chain_n;
    u64_t  off;
    u64_t  end;
    u8_t*  data;
    size_t size;
} Modification;

typedef struct {
    u8_t min;
    u8_t max;
} BlockInfo;

typedef struct {
    BlockInfo blocks[fb_index_size];
    u64_t     block_size;
    int       has_index;
    u64_t     version;
} SearchIndex;

typedef struct FileBuffer {
    char*  path;
    FILE*  file;
    time_t mod_time;
    u64_t  off;
    u64_t  base_addr;
    u64_t  size;
    s8_t   readonly;
    u64_t  version;

    ll_t            modifications;
    SearchIndex*    search_index;
    pthread_mutex_t lock;

    u8_t block[fb_block_size];
    u8_t tmp_block[fb_block_size];
    s8_t block_dirty;

    // Cache describing what `block` currently holds, so that consecutive reads
    // that fall within the loaded window can be served without re-reading from
    // disk (and without re-stat()ing the file). `block[0]` corresponds to file
    // offset `cache_off`, and `cache_len` bytes are valid. The cache is only
    // trusted while `cache_version == version` (any modification bumps
    // `version`).
    u64_t cache_off;
    u64_t cache_len;
    u64_t cache_version;
    s8_t  cache_valid;
} FileBuffer;

typedef int (*fb_search_cb_t)(FileBuffer* fb, u64_t match_addr,
                              const u8_t* match, size_t match_size,
                              void* user_data);

FileBuffer* filebuffer_create(const char* path, int readonly);
void        filebuffer_destroy(FileBuffer* fb);

int  fb_seek(FileBuffer* fb, u64_t off);
int  fb_write(FileBuffer* fb, u8_t* data, size_t size);
int  fb_insert(FileBuffer* fb, u8_t* data, size_t size);
int  fb_delete(FileBuffer* fb, size_t size);
int  fb_undo_last(FileBuffer* fb);
void fb_undo_all(FileBuffer* fb);
void fb_commit(FileBuffer* fb);

void fb_search(FileBuffer* fb, const u8_t* data, size_t size, fb_search_cb_t cb,
               void* user_data, int nthreads);

// Calling this APIs two times will invalidate the old buffer
// and the returned pointer must not be shared across threads.
const u8_t* fb_read(FileBuffer* fb, size_t size);
const u8_t* fb_read_ex(FileBuffer* fb, size_t size, u32_t mod_idx);

// Returns a heap-allocated copy owned by the caller.
// Safe to pass to worker threads after the call returns.
u8_t* fb_read_alloc(FileBuffer* fb, u64_t off, size_t size);
u8_t* fb_read_alloc_ex(FileBuffer* fb, u64_t off, size_t size, u32_t mod_idx);

#endif
