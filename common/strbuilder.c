#include "strbuilder.h"

#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <alloc.h>
#include <log.h>

#define INITIAL_CAP 16

StringBuilder* strbuilder_new()
{
    StringBuilder* sb = bhex_calloc(sizeof(StringBuilder));
    sb->size          = 0;
    sb->capacity      = INITIAL_CAP;
    sb->str           = bhex_calloc(sb->capacity);
    return sb;
}

char* strbuilder_finalize(StringBuilder* sb)
{
    char* r = sb->str;
    bhex_free(sb);
    return r;
}

void strbuilder_append(StringBuilder* sb, const char* str)
{
    u64_t l = strlen(str);
    if (sb->size + l + 1 >= sb->capacity) {
        sb->capacity = (sb->size + l + 1) * 3 / 2;
        sb->str      = bhex_realloc(sb->str, sb->capacity);
    }
    memcpy(sb->str + sb->size, str, l);
    sb->size += l;
    sb->str[sb->size] = '\0';
}

void strbuilder_appendf(StringBuilder* sb, const char* fmt, ...)
{
    va_list argp;
    u64_t   cap = strlen(fmt) * 2;
    char*   tmp = bhex_calloc(cap + 1);

    va_start(argp, fmt);
    int n = vsnprintf(tmp, cap, fmt, argp);
    va_end(argp);

    if (n < 0)
        panic("vsnprintf failed");
    if (n >= cap) {
        cap = n + 1;
        tmp = bhex_realloc(tmp, cap);
        va_start(argp, fmt);
        n = vsnprintf(tmp, cap, fmt, argp);
        va_end(argp);
        if (n < 0 || n >= cap)
            panic("vsnprintf failed");
    }
    strbuilder_append(sb, tmp);
    bhex_free(tmp);

    va_end(argp);
}

void strbuilder_append_char(StringBuilder* sb, char c)
{
    if (sb->size + 2 > sb->capacity) {
        sb->capacity = (sb->size + 2) * 3 / 2;
        sb->str      = bhex_realloc(sb->str, sb->capacity);
    }
    sb->str[sb->size]     = c;
    sb->str[sb->size + 1] = '\0';
    sb->size += 1;
}
