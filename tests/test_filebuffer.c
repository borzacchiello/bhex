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

/* ------------------------------------------------------------------ */
/* search callback capture helpers                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    u64_t  count;
    u64_t  last_addr;
    u64_t* addrs;
    size_t addrs_cap;
} SearchCapture;

static int capture_cb(FileBuffer* fb, u64_t match_addr, const u8_t* match,
                      size_t match_size, void* user_data)
{
    (void)fb;
    (void)match;
    (void)match_size;
    SearchCapture* cap = (SearchCapture*)user_data;
    if (cap->addrs && cap->count < cap->addrs_cap)
        cap->addrs[cap->count] = match_addr;
    cap->last_addr = match_addr;
    cap->count += 1;
    return 1;
}

static int stop_after_cb(FileBuffer* fb, u64_t match_addr, const u8_t* match,
                         size_t match_size, void* user_data)
{
    (void)fb;
    (void)match;
    (void)match_size;
    SearchCapture* cap = (SearchCapture*)user_data;
    cap->count += 1;
    return 0; /* stop */
}

/* ------------------------------------------------------------------ */
/* search test helpers                                                */
/* ------------------------------------------------------------------ */

static DummyFilebuffer* make_blob(const u8_t* pattern, size_t pattern_len,
                                  u64_t blob_size, u64_t* offsets,
                                  size_t num_offsets)
{
    u8_t* blob = bhex_calloc(blob_size);
    for (size_t i = 0; i < num_offsets; ++i) {
        if (offsets[i] + pattern_len <= blob_size)
            memcpy(blob + offsets[i], pattern, pattern_len);
    }
    DummyFilebuffer* tfb = dummyfilebuffer_create(blob, blob_size);
    bhex_free(blob);
    return tfb;
}

/* ------------------------------------------------------------------ */
/* search tests                                                       */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* search: basic single-threaded                                      */
/* ------------------------------------------------------------------ */

int TEST(search_st_basic)(void)
{
    /* Place "HELLO" at offset 100 in a 1024-byte blob */
    u8_t             pattern[] = "HELLO";
    u64_t            offsets[] = {100};
    DummyFilebuffer* tfb =
        make_blob(pattern, strlen((char*)pattern), 1024, offsets, 1);

    int result = TEST_FAILED;
    ASSERT(tfb != NULL);

    SearchCapture cap = {0};
    fb_search(tfb->fb, pattern, strlen((char*)pattern), capture_cb, &cap, 1);

    ASSERT(cap.count == 1);
    ASSERT(cap.last_addr == 100);

    result = TEST_SUCCEEDED;
fail:
    dummyfilebuffer_destroy(tfb);
    return result;
}

int TEST(search_st_no_match)(void)
{
    u8_t             pattern[] = "NOPE";
    u64_t            offsets[] = {0};
    u8_t             data[]    = "HELLO";
    DummyFilebuffer* tfb = make_blob(data, strlen((char*)data), 64, offsets, 0);

    int result = TEST_FAILED;
    ASSERT(tfb != NULL);

    SearchCapture cap = {0};
    fb_search(tfb->fb, pattern, strlen((char*)pattern), capture_cb, &cap, 1);

    ASSERT(cap.count == 0);

    result = TEST_SUCCEEDED;
fail:
    dummyfilebuffer_destroy(tfb);
    return result;
}

int TEST(search_st_multi_match)(void)
{
    /* Place "AB" at offsets 0, 50, 100, 150 within a 200-byte blob */
    u8_t             pattern[] = "AB";
    u64_t            offsets[] = {0, 50, 100, 150};
    DummyFilebuffer* tfb =
        make_blob(pattern, strlen((char*)pattern), 200, offsets, 4);

    int result = TEST_FAILED;
    ASSERT(tfb != NULL);

    u64_t         addrs[16] = {0};
    SearchCapture cap       = {.addrs = addrs, .addrs_cap = 16};
    fb_search(tfb->fb, pattern, strlen((char*)pattern), capture_cb, &cap, 1);

    ASSERT(cap.count == 4);
    ASSERT(cap.addrs[0] == 0);
    ASSERT(cap.addrs[1] == 50);
    ASSERT(cap.addrs[2] == 100);
    ASSERT(cap.addrs[3] == 150);

    result = TEST_SUCCEEDED;
fail:
    dummyfilebuffer_destroy(tfb);
    return result;
}

int TEST(search_st_empty)(void)
{
    u8_t             data[] = "SOMEDATA";
    DummyFilebuffer* tfb    = make_blob(data, strlen((char*)data), 32, NULL, 0);

    int result = TEST_FAILED;
    ASSERT(tfb != NULL);

    SearchCapture cap = {0};
    /* empty pattern: should return immediately, no callback */
    fb_search(tfb->fb, (u8_t*)"", 0, capture_cb, &cap, 1);
    ASSERT(cap.count == 0);

    result = TEST_SUCCEEDED;
fail:
    dummyfilebuffer_destroy(tfb);
    return result;
}

int TEST(search_st_early_stop)(void)
{
    u8_t             pattern[] = "XY";
    u64_t            offsets[] = {10, 200, 400};
    DummyFilebuffer* tfb =
        make_blob(pattern, strlen((char*)pattern), 1024, offsets, 3);

    int result = TEST_FAILED;
    ASSERT(tfb != NULL);

    SearchCapture cap = {0};
    fb_search(tfb->fb, pattern, strlen((char*)pattern), stop_after_cb, &cap, 1);
    /* Should stop after first match */
    ASSERT(cap.count == 1);

    result = TEST_SUCCEEDED;
fail:
    dummyfilebuffer_destroy(tfb);
    return result;
}

/* ------------------------------------------------------------------ */
/* search: multithreaded vs single-threaded equivalence               */
/* ------------------------------------------------------------------ */

int TEST(search_mt_matches_st)(void)
{
    /* Scatter "TAG" at various offsets in a 64KB blob */
    u8_t pattern[] = "TAG";
    /* Non-overlapping placements */
    u64_t  offsets[] = {0, 100, 1000, 8192, 16384, 32767, 50000, 65533};
    size_t n_offsets = sizeof(offsets) / sizeof(offsets[0]);
    DummyFilebuffer* tfb =
        make_blob(pattern, strlen((char*)pattern), 65536, offsets, n_offsets);

    int result = TEST_FAILED;
    ASSERT(tfb != NULL);

    /* Single-threaded search */
    SearchCapture cap_st = {0};
    fb_search(tfb->fb, pattern, strlen((char*)pattern), capture_cb, &cap_st, 1);

    /* Multi-threaded search (2 threads) */
    SearchCapture cap_mt = {0};
    fb_search(tfb->fb, pattern, strlen((char*)pattern), capture_cb, &cap_mt, 2);

    ASSERT(cap_st.count == n_offsets);
    ASSERT(cap_mt.count == n_offsets);
    ASSERT(cap_mt.count == cap_st.count);

    result = TEST_SUCCEEDED;
fail:
    dummyfilebuffer_destroy(tfb);
    return result;
}

int TEST(search_mt_matches_st_many_threads)(void)
{
    u8_t   pattern[] = "TAG";
    u64_t  offsets[] = {0, 100, 1000, 8192, 16384, 32767, 50000, 65533};
    size_t n_offsets = sizeof(offsets) / sizeof(offsets[0]);
    DummyFilebuffer* tfb =
        make_blob(pattern, strlen((char*)pattern), 65536, offsets, n_offsets);

    int result = TEST_FAILED;
    ASSERT(tfb != NULL);

    SearchCapture cap_st = {0};
    fb_search(tfb->fb, pattern, strlen((char*)pattern), capture_cb, &cap_st, 1);

    /* Test with 4 and 8 threads */
    for (int nt = 2; nt <= 8; nt += 2) {
        SearchCapture cap_mt = {0};
        fb_search(tfb->fb, pattern, strlen((char*)pattern), capture_cb, &cap_mt,
                  nt);
        ASSERT(cap_mt.count == cap_st.count);
        ASSERT(cap_mt.count == n_offsets);
    }

    result = TEST_SUCCEEDED;
fail:
    dummyfilebuffer_destroy(tfb);
    return result;
}

int TEST(search_mt_no_false_positives)(void)
{
    /* Fill blob with 'A's, no pattern present */
    u8_t* blob = bhex_calloc(65536);
    memset(blob, 'A', 65536);
    DummyFilebuffer* tfb = dummyfilebuffer_create(blob, 65536);
    bhex_free(blob);

    int result = TEST_FAILED;
    ASSERT(tfb != NULL);

    u8_t pattern[] = "TAG";

    for (int nt = 1; nt <= 8; nt += (nt == 1 ? 1 : 2)) {
        SearchCapture cap = {0};
        fb_search(tfb->fb, pattern, strlen((char*)pattern), capture_cb, &cap,
                  nt);
        ASSERT(cap.count == 0);
    }

    result = TEST_SUCCEEDED;
fail:
    dummyfilebuffer_destroy(tfb);
    return result;
}

int TEST(search_mt_boundary)(void)
{
    /* Place a pattern at what would be a thread boundary.
     * With 2 threads on a 8192-byte blob, split_work divides at 4096.
     * Offset 4095 straddles the boundary (bytes 4095-4097). */
    u8_t             pattern[] = "TAG";
    u64_t            offsets[] = {0, 100, 4095, 7000, 8189};
    size_t           n_offsets = sizeof(offsets) / sizeof(offsets[0]);
    DummyFilebuffer* tfb =
        make_blob(pattern, strlen((char*)pattern), 8192, offsets, n_offsets);

    int result = TEST_FAILED;
    ASSERT(tfb != NULL);

    SearchCapture cap_st = {0};
    fb_search(tfb->fb, pattern, strlen((char*)pattern), capture_cb, &cap_st, 1);
    ASSERT(cap_st.count == n_offsets);

    SearchCapture cap_mt = {0};
    fb_search(tfb->fb, pattern, strlen((char*)pattern), capture_cb, &cap_mt, 2);
    ASSERT(cap_mt.count == cap_st.count);
    ASSERT(cap_mt.count == n_offsets);

    result = TEST_SUCCEEDED;
fail:
    dummyfilebuffer_destroy(tfb);
    return result;
}

int TEST(search_mt_overlapping_pattern)(void)
{
    /* Pattern "AAA" in a string "AAAAA" should match at 0,1,2.
     * Test that MT finds all 3 overlapping matches. */
    u8_t* blob = bhex_calloc(128);
    memcpy(blob + 10, "AAAAA", 5);
    DummyFilebuffer* tfb = dummyfilebuffer_create(blob, 128);
    bhex_free(blob);

    int result = TEST_FAILED;
    ASSERT(tfb != NULL);

    u8_t pattern[] = "AAA";

    SearchCapture cap_st = {0};
    fb_search(tfb->fb, pattern, strlen((char*)pattern), capture_cb, &cap_st, 1);
    ASSERT(cap_st.count == 3);

    SearchCapture cap_mt = {0};
    fb_search(tfb->fb, pattern, strlen((char*)pattern), capture_cb, &cap_mt, 4);
    ASSERT(cap_mt.count == 3);
    ASSERT(cap_mt.count == cap_st.count);

    result = TEST_SUCCEEDED;
fail:
    dummyfilebuffer_destroy(tfb);
    return result;
}

int TEST(search_mt_early_stop)(void)
{
    /* Pattern scattered widely; early stop should prevent finding all */
    u8_t             pattern[] = "ZZ";
    u64_t            offsets[] = {500, 5000, 50000};
    DummyFilebuffer* tfb =
        make_blob(pattern, strlen((char*)pattern), 65536, offsets, 3);

    int result = TEST_FAILED;
    ASSERT(tfb != NULL);

    /* Verify all 3 are there with ST */
    SearchCapture cap_st = {0};
    fb_search(tfb->fb, pattern, strlen((char*)pattern), capture_cb, &cap_st, 1);
    ASSERT(cap_st.count == 3);

    /* With MT + early stop, should find >= 1 but may be less than 3
     * (depends on which thread finds first match). */
    SearchCapture cap_mt = {0};
    fb_search(tfb->fb, pattern, strlen((char*)pattern), stop_after_cb, &cap_mt,
              4);
    ASSERT(cap_mt.count >= 1);

    result = TEST_SUCCEEDED;
fail:
    dummyfilebuffer_destroy(tfb);
    return result;
}

int TEST(search_mt_small_file)(void)
{
    /* File too small to split meaningfully across threads */
    u8_t             pattern[] = "!";
    u64_t            offsets[] = {5};
    DummyFilebuffer* tfb =
        make_blob(pattern, strlen((char*)pattern), 32, offsets, 1);

    int result = TEST_FAILED;
    ASSERT(tfb != NULL);

    /* Should still work with many threads on a tiny file */
    SearchCapture cap = {0};
    fb_search(tfb->fb, pattern, strlen((char*)pattern), capture_cb, &cap, 8);
    ASSERT(cap.count == 1);

    result = TEST_SUCCEEDED;
fail:
    dummyfilebuffer_destroy(tfb);
    return result;
}

int TEST(search_mt_pattern_at_end)(void)
{
    /* Pattern at the very last bytes of the file */
    u8_t   pattern[] = "END";
    size_t pat_len   = strlen((char*)pattern);
    u8_t*  blob      = bhex_calloc(1024);
    memset(blob, 'X', 1024);
    memcpy(blob + 1024 - pat_len, pattern, pat_len);
    DummyFilebuffer* tfb = dummyfilebuffer_create(blob, 1024);
    bhex_free(blob);

    int result = TEST_FAILED;
    ASSERT(tfb != NULL);

    SearchCapture cap_st = {0};
    fb_search(tfb->fb, pattern, pat_len, capture_cb, &cap_st, 1);
    ASSERT(cap_st.count == 1);
    ASSERT(cap_st.last_addr == 1024 - pat_len);

    SearchCapture cap_mt = {0};
    fb_search(tfb->fb, pattern, pat_len, capture_cb, &cap_mt, 4);
    ASSERT(cap_mt.count == 1);

    result = TEST_SUCCEEDED;
fail:
    dummyfilebuffer_destroy(tfb);
    return result;
}

/* ------------------------------------------------------------------ */
/* search index: parallel index build is equivalent to sequential     */
/* ------------------------------------------------------------------ */

int TEST(search_index_parallel_equiv)(void)
{
    /* The search index is only built for files >= fb_index_size * 8 bytes
     * (4096). Build a large blob whose bytes are mostly a narrow value range,
     * with a distinctive pattern placed only in a few blocks. The block index
     * lets the search skip blocks that cannot contain the pattern bytes, so
     * this exercises the index-skip path. populate_index() runs with the same
     * thread count as the search, so comparing a single-threaded search
     * (sequential index build) against multi-threaded searches (parallel index
     * build) validates that the parallel index build is equivalent. */
    enum { BLOB_SIZE = 256 * 1024 }; /* well above the 4096 index threshold */
    u8_t   pattern[] = "\xfe\xff\xfe";
    size_t pat_len   = sizeof(pattern) - 1;

    u8_t* blob = bhex_malloc(BLOB_SIZE);
    /* Fill with a low, narrow byte range that never contains 0xfe/0xff, so
     * most index blocks get skipped during the search. */
    for (size_t i = 0; i < BLOB_SIZE; ++i)
        blob[i] = (u8_t)(i % 7); /* values 0..6 only */

    /* Place the high-valued pattern at a handful of spread-out offsets. */
    u64_t  offsets[] = {0, 4096, 50000, 131072, 200000, BLOB_SIZE - pat_len};
    size_t n_offsets = sizeof(offsets) / sizeof(offsets[0]);
    for (size_t i = 0; i < n_offsets; ++i)
        memcpy(blob + offsets[i], pattern, pat_len);

    DummyFilebuffer* tfb = dummyfilebuffer_create(blob, BLOB_SIZE);
    bhex_free(blob);

    int result = TEST_FAILED;
    ASSERT(tfb != NULL);

    u64_t         addrs_st[64] = {0};
    SearchCapture cap_st       = {.addrs = addrs_st, .addrs_cap = 64};
    fb_search(tfb->fb, pattern, pat_len, capture_cb, &cap_st, 1);
    ASSERT(cap_st.count == n_offsets);
    for (size_t i = 0; i < n_offsets; ++i)
        ASSERT(cap_st.addrs[i] == offsets[i]);

    for (int nt = 2; nt <= 8; ++nt) {
        SearchCapture cap_mt = {0};
        fb_search(tfb->fb, pattern, pat_len, capture_cb, &cap_mt, nt);
        ASSERT(cap_mt.count == cap_st.count);
        ASSERT(cap_mt.count == n_offsets);
    }

    result = TEST_SUCCEEDED;
fail:
    dummyfilebuffer_destroy(tfb);
    return result;
}

int TEST(search_mt_stress)(void)
{
    /* Larger blob (1MB) with pattern at many random-ish positions.
     * Verify MT and ST find the same count. */
    enum { BLOB_SIZE = 1 << 20 }; /* 1 MB */
    u8_t   pattern[] = "FINDME";
    size_t pat_len   = strlen((char*)pattern);
    u8_t*  blob      = bhex_calloc(BLOB_SIZE);

    /* Scatter pattern at known positions */
    /* All non-overlapping (6 byte pattern, min gap >= 6) */
    u64_t offsets[] = {
        0,
        100,
        1000,
        8192,
        16384,
        65536,
        99999,
        131072,
        262144,
        500000,
        524288,
        999999,
        BLOB_SIZE - pat_len,
    };
    size_t n_offsets = sizeof(offsets) / sizeof(offsets[0]);
    for (size_t i = 0; i < n_offsets; ++i)
        memcpy(blob + offsets[i], pattern, pat_len);

    DummyFilebuffer* tfb = dummyfilebuffer_create(blob, BLOB_SIZE);
    bhex_free(blob);

    int result = TEST_FAILED;
    ASSERT(tfb != NULL);

    SearchCapture cap_st = {0};
    fb_search(tfb->fb, pattern, pat_len, capture_cb, &cap_st, 1);

    for (int nt = 2; nt <= 8; nt += 2) {
        SearchCapture cap_mt = {0};
        fb_search(tfb->fb, pattern, pat_len, capture_cb, &cap_mt, nt);
        ASSERT(cap_mt.count == cap_st.count);
        ASSERT(cap_mt.count == n_offsets);
    }

    result = TEST_SUCCEEDED;
fail:
    dummyfilebuffer_destroy(tfb);
    return result;
}
