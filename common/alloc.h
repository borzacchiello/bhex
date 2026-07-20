// Copyright (c) 2022-2026, bageyelet

#ifndef ALLOC_H
#define ALLOC_H

#include <stdlib.h>

void* bhex_malloc(size_t n);
void* bhex_calloc(size_t n);
void* bhex_realloc(void* buf, size_t n);
void  bhex_free(void* buf);

void   bhex_alloc_track_start();
void   bhex_alloc_track_stop();
void   bhex_alloc_track_free_all();
size_t bhex_alloc_live_count();

// The allocation tracker's enabled flag. Exposed (with an inline accessor) so
// hot paths such as the bhengine value pool can test it without a cross-TU
// function call.
extern int g_bhex_alloc_tracking;

static inline int bhex_alloc_is_tracking(void) { return g_bhex_alloc_tracking; }

char* bhex_strdup(const char* s);
char* bhex_getline();

#endif
