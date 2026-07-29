// Copyright (c) 2022-2026, bageyelet

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <log.h>
#include <color.h>

static void (*g_callback)(const char*);
int disable_warning = 0;

// The tag is colored only on the direct path: when a callback is registered
// the message is rendered by somebody else (the TUI puts it in its status
// bar), and the escapes would break its layout.
static void common_print(const char* type, Color color, const char* format,
                         va_list argp)
{
    char buf[2048] = {0};
    char tmp[1024] = {0};

    if (g_callback == NULL) {
        fprintf(stderr, "%s[ %s ]%s ", color_str(color), type,
                color_str(COLOR_RESET));
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

    // PANIC always print on stderr
    g_callback = NULL;
    common_print(" PANIC ", COLOR_PANIC, format, argp);
    va_end(argp);

    exit(1);
}

void warning(const char* format, ...)
{
    if (disable_warning)
        return;

    va_list argp;
    va_start(argp, format);

    common_print("WARNING", COLOR_WARNING, format, argp);
    va_end(argp);
}

void info(const char* format, ...)
{
    if (disable_warning)
        return;

    va_list argp;
    va_start(argp, format);

    common_print(" INFO  ", COLOR_INFO, format, argp);
    va_end(argp);
}

void error(const char* format, ...)
{
    va_list argp;
    va_start(argp, format);

    common_print(" ERROR ", COLOR_ERROR, format, argp);
    va_end(argp);
}

void register_log_callback(void (*callback)(const char*))
{
    g_callback = callback;
}

void unregister_log_callback(void) { g_callback = NULL; }
