#include <defs.h>
#include <alloc.h>
#include <log.h>

#include <sys/types.h>
#include <string.h>
#include <stdio.h>

#define likely(x) __builtin_expect(!!(x), 1)

static void** g_track_ptr;
static u64_t  g_track_capacity;
static u64_t  g_track_size;
static int    g_tracking;

static inline void track_add(void* ptr)
{
    if (likely(!g_tracking))
        return;

    if (g_track_capacity == g_track_size) {
        g_track_capacity *= 2;
        g_track_ptr = realloc(g_track_ptr, sizeof(void*) * g_track_capacity);
        if (g_track_ptr == NULL)
            panic("unable to allocate %llu bytes", g_track_capacity);
    }
    g_track_ptr[g_track_size++] = ptr;
}

static inline void track_remove(void* ptr)
{
    if (likely(!g_tracking))
        return;

    for (u64_t i = 0; i < g_track_size; ++i) {
        if (g_track_ptr[i] == ptr) {
            if (i != g_track_size - 1)
                g_track_ptr[i] = g_track_ptr[g_track_size - 1];
            g_track_size--;
            break;
        }
    }
}

static inline void track_start()
{
    if (g_tracking)
        return;

    g_tracking       = 1;
    g_track_capacity = 16;
    g_track_size     = 0;
    g_track_ptr      = malloc(sizeof(void*) * g_track_capacity);
    if (!g_track_ptr)
        panic("unable to allocate buffer for tracker");
}

static inline void track_stop()
{
    if (!g_tracking)
        return;

    free(g_track_ptr);
    g_tracking       = 0;
    g_track_ptr      = NULL;
    g_track_size     = 0;
    g_track_capacity = 0;
}

static inline void track_free_all()
{
    if (!g_tracking)
        return;

    for (u64_t i = 0; i < g_track_size; ++i)
        free(g_track_ptr[i]);
    g_track_size = 0;
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

    track_remove(b);
    void* r = realloc(b, size);
    if (r == NULL)
        panic("realloc failed");

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

void bhex_alloc_track_start()
{
    if (g_tracking)
        return;

    track_start();
}

void bhex_alloc_track_stop()
{
    if (!g_tracking)
        return;

    track_stop();
}

void bhex_alloc_track_free_all()
{
    if (!g_tracking)
        return;

    track_free_all();
}
