#ifndef FILEBUFFER_H
#define FILEBUFFER_H

/*
   It is a wrapper of FILE* that allows to undo modifications.
   It adopts a best-effort approach to handle external modifications,
   tring to minimize the damage if another application is modifing the same
   file.
*/

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
    u64_t  size;
    s8_t   readonly;
    u64_t  version;

    ll_t         modifications;
    SearchIndex* search_index;

    u8_t block[fb_block_size];
    s8_t block_dirty;
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
               void* user_data);

// Calling this APIs two times will invalidate the old buffer
const u8_t* fb_read(FileBuffer* fb, size_t size);
const u8_t* fb_read_ex(FileBuffer* fb, size_t size, u32_t mod_idx);

#endif
