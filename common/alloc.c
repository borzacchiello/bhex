// Copyright (c) 2022-2026, bageyelet

#include <defs.h>
#include <alloc.h>
#include <log.h>

#include <sys/types.h>
#include <string.h>
#include <stdio.h>

#define likely(x) __builtin_expect(!!(x), 1)

// Allocation tracker.
//
// A leak-accounting facility for the tests (see tests/test_leaks.c): it counts
// the allocations still live at the end of a scope. No production code uses it
// -- the bhengine parser used to, to drop a half-built AST on a syntax error,
// but that is now handled precisely by the %destructor rules in parser.y.
//
// Scopes nest, and are isolated: an inner track_free_all() frees only what the
// inner scope allocated, never what its caller is still holding.
//
// Pointers are kept in one array in allocation order. `g_track_marks[k]` is
// the index at which scope `k` begins, so scope k owns
// [g_track_marks[k], g_track_marks[k+1]) and the innermost scope owns
// [g_track_marks[depth-1], g_track_size). Removal preserves that order by
// shifting the tail down, and adjusts the marks of the scopes above it.
#define TRACK_MAX_DEPTH 8

static void** g_track_ptr;
static u64_t  g_track_capacity;
static u64_t  g_track_size;
static u64_t  g_track_marks[TRACK_MAX_DEPTH];
static u32_t  g_track_depth;
int           g_bhex_alloc_tracking;

static inline void track_add(void* ptr)
{
    if (likely(!g_bhex_alloc_tracking))
        return;

    if (g_track_capacity == g_track_size) {
        g_track_capacity *= 2;
        g_track_ptr = realloc(g_track_ptr, sizeof(void*) * g_track_capacity);
        if (g_track_ptr == NULL)
            panic("unable to allocate %llu bytes", g_track_capacity);
    }
    g_track_ptr[g_track_size++] = ptr;
}

static inline int track_remove(void* ptr)
{
    if (likely(!g_bhex_alloc_tracking))
        return 0;

    // scan from the newest: short-lived allocations dominate
    for (u64_t i = g_track_size; i-- > 0;) {
        if (g_track_ptr[i] != ptr)
            continue;

        memmove(&g_track_ptr[i], &g_track_ptr[i + 1],
                (size_t)(g_track_size - i - 1) * sizeof(void*));
        g_track_size--;
        for (u32_t k = 0; k < g_track_depth; ++k)
            if (g_track_marks[k] > i)
                g_track_marks[k]--;
        return 1;
    }
    return 0;
}

static inline void track_start()
{
    if (g_track_depth == TRACK_MAX_DEPTH)
        panic("allocation tracker nested too deeply");

    if (!g_bhex_alloc_tracking) {
        g_track_capacity = 16;
        g_track_size     = 0;
        g_track_ptr      = malloc(sizeof(void*) * g_track_capacity);
        if (!g_track_ptr)
            panic("unable to allocate buffer for tracker");
    }

    g_track_marks[g_track_depth++] = g_track_size;
    g_bhex_alloc_tracking          = 1;
}

static inline void track_stop()
{
    if (!g_bhex_alloc_tracking)
        return;

    // anything the inner scope allocated and did not free is still live, and
    // becomes the enclosing scope's responsibility: leave it in the array
    g_track_depth--;
    if (g_track_depth > 0)
        return;

    free(g_track_ptr);
    g_bhex_alloc_tracking = 0;
    g_track_ptr           = NULL;
    g_track_size          = 0;
    g_track_capacity      = 0;
}

static inline void track_free_all()
{
    if (!g_bhex_alloc_tracking)
        return;

    u64_t start = g_track_marks[g_track_depth - 1];
    for (u64_t i = start; i < g_track_size; ++i)
        free(g_track_ptr[i]);
    g_track_size = start;
}

void* bhex_malloc(size_t n)
{
    void* r = malloc(n);
    if (!r)
        panic("unable to allocate %d bytes", n);

    track_add(r);
    return r;
}

void* bhex_calloc(size_t n)
{
    void* r = bhex_malloc(n);
    memset(r, 0, n);
    return r;
}

void* bhex_realloc(void* b, size_t size)
{
    // check for weird usage of the API...
    if (size == 0)
        panic("realloc size is zero");

    int   was_removed = track_remove(b);
    void* r           = realloc(b, size);
    if (r == NULL)
        panic("realloc failed");

    if (was_removed)
        // realloc needs to be tracked only if the previous malloc was tracked
        track_add(r);
    return r;
}

void bhex_free(void* buf)
{
    track_remove(buf);
    free(buf);
}

char* bhex_strdup(const char* s)
{
    char* r = strdup(s);
    if (!r)
        panic("unable to duplicate string");

    track_add(r);
    return r;
}

char* bhex_getline(void)
{
    char*   line      = NULL;
    size_t  line_size = 0;
    ssize_t r         = getline(&line, &line_size, stdin);
    if (r < 0) {
        bhex_free(line);
        return NULL;
    }

    track_add(line);
    return line;
}

void bhex_alloc_track_start() { track_start(); }

void bhex_alloc_track_stop()
{
    if (!g_bhex_alloc_tracking)
        return;

    track_stop();
}

void bhex_alloc_track_free_all()
{
    if (!g_bhex_alloc_tracking)
        return;

    track_free_all();
}

// live allocations of the innermost scope only
size_t bhex_alloc_live_count()
{
    if (!g_bhex_alloc_tracking)
        return 0;
    return (size_t)(g_track_size - g_track_marks[g_track_depth - 1]);
}
