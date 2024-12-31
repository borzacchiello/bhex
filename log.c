#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "log.h"

static void (*g_callback)(const char*);
int disable_warning = 0;

static void common_print(const char* type, const char* format, va_list argp)
{
    char buf[2048] = {0};
    char tmp[1024] = {0};

    if (g_callback == NULL) {
        fprintf(stderr, "[ %s ] ", type);
        vfprintf(stderr, format, argp);
        fprintf(stderr, "\n");
    } else {
        snprintf(buf, sizeof(buf) - 1, "[ %s ] ", type);
        vsnprintf(tmp, sizeof(tmp) - 1, format, argp);
        strncat(buf, tmp, sizeof(buf) - 1 - strlen(buf));

        g_callback(buf);
    }
}

void panic(const char* format, ...)
{
    va_list argp;
    va_start(argp, format);

    common_print(" PANIC ", format, argp);
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

void register_log_callback(void (*callback)(const char*))
{
    g_callback = callback;
}

void unregister_log_callback(void) { g_callback = NULL; }
