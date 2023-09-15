#ifndef TEMPLATE_MACHO_H
#define TEMPLATE_MACHO_H

#ifdef CPARSER
#define __attribute__(x)
#else
#include "../../defs.h"
#endif

typedef struct mach_header {
    u32_t magic;      /* mach magic number identifier */
    s32_t cputype;    /* cpu specifier */
    s32_t cpusubtype; /* machine specifier */
    u32_t filetype;   /* type of file */
    u32_t ncmds;      /* number of load commands */
    u32_t sizeofcmds; /* the size of all the load commands */
    u32_t flags;      /* flags */
} mach_header;

#endif
