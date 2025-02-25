#ifndef TEST_FILEBUFFER_H
#define TEST_FILEBUFFER_H

#include <defs.h>
#include "../filebuffer.h"

typedef struct DummyFilebuffer {
    FileBuffer* fb;
    char*       fname;
} DummyFilebuffer;

DummyFilebuffer* dummyfilebuffer_create(const u8_t* data, size_t s);
void             dummyfilebuffer_destroy(DummyFilebuffer* tfs);

#endif
