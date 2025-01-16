#ifndef STRBUILDER_H
#define STRBUILDER_H

#include <defs.h>

typedef struct StringBuilder {
    char* str;
    u64_t size;
    u64_t capacity;
} StringBuilder;

StringBuilder* strbuilder_new();
char*          strbuilder_finalize(StringBuilder* sb);

void strbuilder_append(StringBuilder* sb, const char* str);
void strbuilder_appendf(StringBuilder* sb, const char* fmt, ...);
void strbuilder_append_char(StringBuilder* sb, char c);

#endif
