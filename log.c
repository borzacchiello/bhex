#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "log.h"

static void common_print(const char* type, const char* format, va_list argp)
{
    fprintf(stderr, "[ %s ] ", type);
    vfprintf(stderr, format, argp);
    fprintf(stderr, "\n");
}

void panic(const char* format, ...)
{
    va_list argp;
    va_start(argp, format);

    common_print("PANIC", format, argp);
    exit(1);
}

void warning(const char* format, ...)
{
    va_list argp;
    va_start(argp, format);

    common_print("WARNING", format, argp);
}
