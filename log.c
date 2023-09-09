#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "log.h"

int disable_warning = 0;

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
    if (disable_warning)
        return;

    va_list argp;
    va_start(argp, format);

    common_print("WARNING", format, argp);
}

void error(const char* format, ...)
{
    va_list argp;
    va_start(argp, format);

    common_print(" ERROR ", format, argp);
}
