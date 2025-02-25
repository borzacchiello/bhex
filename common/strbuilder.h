#ifndef STRBUILDER_H
#define STRBUILDER_H

#include <defs.h>
#include <stdarg.h>

typedef struct StringBuilder {
    char* str;
    u64_t size;
    u64_t capacity;
} StringBuilder;

StringBuilder* strbuilder_new();
char*          strbuilder_finalize(StringBuilder* sb);
char*          strbuilder_reset(StringBuilder* sb);

void strbuilder_append(StringBuilder* sb, const char* str);
void strbuilder_appendf(StringBuilder* sb, const char* fmt, ...);
void strbuilder_appendvsf(StringBuilder* sb, const char* fmt, va_list argp);
void strbuilder_append_char(StringBuilder* sb, char c);

#endif
