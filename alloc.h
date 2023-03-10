#ifndef ALLOC_H
#define ALLOC_H

#include <stdlib.h>

void* bhex_malloc(size_t n);
void* bhex_calloc(size_t n);
void* bhex_realloc(void* buf, size_t n);
void  bhex_free(void* buf);

char* bhex_strdup(const char* s);
char* bhex_getline();

#endif
