#include "alloc.h"
#include "log.h"

#include <string.h>
#include <stdio.h>

void* bhex_malloc(size_t n)
{
    void* r = malloc(n);
    if (!r)
        panic("unable to allocate %d bytes", n);

    return r;
}

void* bhex_realloc(void* b, size_t size)
{
    // check for weird usage of the API...
    if (b == NULL)
        panic("realloc buffer is NULL");
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

char* bhex_getline()
{
    char*   line      = NULL;
    size_t  line_size = 0;
    ssize_t r         = getline(&line, &line_size, stdin);
    if (r < 0)
        return NULL;
    return line;
}
