#include "strbuilder.h"
#include "defs.h"

#include <string.h>
#include <stdio.h>
#include <alloc.h>
#include <log.h>

#define INITIAL_CAP 16

StringBuilder* strbuilder_new(void)
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

char* strbuilder_reset(StringBuilder* sb)
{
    char* r = sb->str;

    sb->size     = 0;
    sb->capacity = INITIAL_CAP;
    sb->str      = bhex_calloc(sb->capacity);
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

void strbuilder_appendvs(StringBuilder* sb, const char* fmt, va_list argp)
{
    va_list argp_copy;
    va_copy(argp_copy, argp);

    u64_t cap = strlen(fmt) * 2;
    char* tmp = bhex_calloc(cap + 1);

    int n = vsnprintf(tmp, cap, fmt, argp);
    if (n < 0)
        panic("vsnprintf failed");
    if ((u64_t)n >= cap) {
        cap = n + 1;
        tmp = bhex_realloc(tmp, cap);
        n   = vsnprintf(tmp, cap, fmt, argp_copy);
        if (n < 0 || (u64_t)n >= cap)
            panic("vsnprintf failed");
    }
    strbuilder_append(sb, tmp);
    bhex_free(tmp);

    va_end(argp_copy);
}

void strbuilder_appendf(StringBuilder* sb, const char* fmt, ...)
{
    va_list argp;
    va_start(argp, fmt);
    strbuilder_appendvs(sb, fmt, argp);
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
