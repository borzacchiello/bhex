#include "alloc.h"
#include "log.h"

#include <sys/types.h>
#include <string.h>
#include <stdio.h>

void* bhex_malloc(size_t n)
{
    void* r = malloc(n);
    if (!r)
        panic("unable to allocate %d bytes", n);

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

    void* r = realloc(b, size);
    if (r == NULL)
        panic("realloc failed");
    return r;
}

void bhex_free(void* buf) { free(buf); }

char* bhex_strdup(const char* s)
{
    char* r = strdup(s);
    if (!r)
        panic("unable to duplicate string");
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
    return line;
}
