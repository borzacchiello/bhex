#ifndef TEST_FILEBUFFER_H
#define TEST_FILEBUFFER_H

#include <defs.h>
#include "../filebuffer.h"

typedef struct TestFilebuffer {
    FileBuffer* fb;
    char*       fname;
} TestFilebuffer;

TestFilebuffer* testfilebuffer_create(const uint8_t* data, size_t s);
void            testfilebuffer_destroy(TestFilebuffer* tfs);

#endif
