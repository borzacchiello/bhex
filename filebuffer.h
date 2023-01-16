#ifndef FILEBUFFER_H
#define FILEBUFFER_H

#include <stdio.h>
#include <stdint.h>

#include "ll.h"

#define fb_block_size 256

typedef struct Modification {
    uint64_t off;
    uint8_t* data;
    size_t   size;
} Modification;

typedef struct FileBuffer {
    char*    path;
    FILE*    file;
    uint64_t off;
    uint64_t size;
    int      readonly;

    LL modifications;

    uint8_t* big_read;
    size_t   big_read_capacity;

    uint8_t block[fb_block_size];
} FileBuffer;

FileBuffer* filebuffer_create(const char* path);
void        filebuffer_destroy(FileBuffer* fb);

int  fb_seek(FileBuffer* fb, uint64_t off);
int  fb_add_modification(FileBuffer* fb, uint8_t* data, size_t size);
int  fb_remove_last_modification(FileBuffer* fb);
void fb_commit_modifications(FileBuffer* fb);

// Calling this API two times will invalidate the old buffer
const uint8_t* fb_read(FileBuffer* fb, size_t size);

#endif
