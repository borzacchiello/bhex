// Copyright (c) 2022-2026, bageyelet

#include "dummy_filebuffer.h"
#include "t.h"

#include <alloc.h>
#include <pthread.h>
#include <string.h>

#ifndef TEST
#define TEST(name) test_##name
#endif

typedef struct {
    FileBuffer* fb;
    const u8_t* expected;
    size_t      size;
    u32_t       seed;
    int         ok;
} ReaderTask;

static u32_t next_rand(u32_t* state)
{
    *state = (*state * 1103515245u) + 12345u;
    return *state;
}

static void* reader_thread(void* arg)
{
    ReaderTask* task = (ReaderTask*)arg;
    u32_t       rng  = task->seed;

    for (int i = 0; i < 200; ++i) {
        size_t max_off = task->size - 128;
        size_t off     = max_off == 0 ? 0 : (next_rand(&rng) % max_off);
        size_t len     = (next_rand(&rng) % 128) + 1;

        u8_t* buf = fb_read_alloc(task->fb, off, len);
        if (buf == NULL || memcmp(buf, task->expected + off, len) != 0) {
            task->ok = 0;
            if (buf)
                bhex_free(buf);
            return NULL;
        }

        bhex_free(buf);
    }

    return NULL;
}

int TEST(read_alloc_threaded)(void)
{
    static u8_t blob[16384];
    for (size_t i = 0; i < sizeof(blob); ++i)
        blob[i] = (u8_t)((i * 37u) & 0xFFu);

    DummyFilebuffer* tfb = dummyfilebuffer_create(blob, sizeof(blob));
    if (tfb == NULL)
        return TEST_FAILED;

    int   result = TEST_FAILED;
    u8_t* a      = NULL;
    u8_t* b      = NULL;
    enum { NTHREADS = 4 };
    pthread_t  threads[NTHREADS];
    ReaderTask tasks[NTHREADS];

    a = fb_read_alloc(tfb->fb, 0, 64);
    b = fb_read_alloc(tfb->fb, 32, 64);
    ASSERT(a != NULL);
    ASSERT(b != NULL);
    ASSERT(memcmp(a, blob, 64) == 0);
    ASSERT(memcmp(b, blob + 32, 64) == 0);
    ASSERT(memcmp(a, blob, 64) == 0);

    for (int i = 0; i < NTHREADS; ++i) {
        tasks[i].fb       = tfb->fb;
        tasks[i].expected = blob;
        tasks[i].size     = sizeof(blob);
        tasks[i].seed     = (u32_t)(i + 1);
        tasks[i].ok       = 1;
        ASSERT(pthread_create(&threads[i], NULL, reader_thread, &tasks[i]) ==
               0);
    }

    for (int i = 0; i < NTHREADS; ++i) {
        pthread_join(threads[i], NULL);
        ASSERT(tasks[i].ok);
    }

    result = TEST_SUCCEEDED;

fail:
    if (a)
        bhex_free(a);
    if (b)
        bhex_free(b);
    dummyfilebuffer_destroy(tfb);
    return result;
}
