#include "dummy_filebuffer.h"

#include <sys/random.h>
#include <unistd.h>
#include <alloc.h>
#include <defs.h>
#include <log.h>

static void fill_with_random(u8_t* buffer, u32_t size)
{
    if (getentropy(buffer, size) != 0)
        panic("unable to generate random data");
}

DummyFilebuffer* dummyfilebuffer_create(const u8_t* data, size_t s)
{
    u32_t rand_n = 0;
    fill_with_random((u8_t*)&rand_n, 4);

    char* fname = bhex_calloc(22);
    if (snprintf(fname, 21, "/tmp/testfb_%08x", rand_n) < 0)
        panic("dummyfilebuffer_create(): snprintf failed");

    FILE* f = fopen(fname, "wb");
    if (f == NULL)
        panic("dummyfilebuffer_create(): fopen failed");
    if (fwrite(data, 1, s, f) != s)
        panic("dummyfilebuffer_create(): fwrite failed");
    if (fclose(f) != 0)
        panic("dummyfilebuffer_create(): fclose failed");

    FileBuffer* fb = filebuffer_create(fname, 0);
    if (fb == NULL)
        panic("dummyfilebuffer_create(): filebuffer_create failed");

    DummyFilebuffer* tfb = bhex_calloc(sizeof(DummyFilebuffer));
    tfb->fb              = fb;
    tfb->fname           = fname;
    return tfb;
}

void dummyfilebuffer_destroy(DummyFilebuffer* tfs)
{
    filebuffer_destroy(tfs->fb);
    unlink(tfs->fname);

    bhex_free(tfs->fname);
    bhex_free(tfs);
}
