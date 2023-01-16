#ifndef FILEBUFFER_H
#define FILEBUFFER_H

#include <stdio.h>
#include "defs.h"

#include "ll.h"

#define fb_block_size 256

typedef struct Modification {
    u64_t  off;
    u8_t*  data;
    size_t size;
} Modification;

typedef struct FileBuffer {
    char* path;
    FILE* file;
    u64_t off;
    u64_t size;
    int   readonly;

    LL modifications;

    u8_t*  big_read;
    size_t big_read_capacity;

    u8_t block[fb_block_size];
} FileBuffer;

FileBuffer* filebuffer_create(const char* path);
void        filebuffer_destroy(FileBuffer* fb);

int  fb_seek(FileBuffer* fb, u64_t off);
int  fb_add_modification(FileBuffer* fb, u8_t* data, size_t size);
int  fb_remove_last_modification(FileBuffer* fb);
void fb_commit_modifications(FileBuffer* fb);

// Calling this API two times will invalidate the old buffer
const u8_t* fb_read(FileBuffer* fb, size_t size);

#endif
