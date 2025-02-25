#ifndef DISPLAY_H
#define DISPLAY_H

#include <stdio.h>

typedef void (*display_callback_t)(const char*, ...);

extern display_callback_t g_print_callback;
void                      display_set_print_callback(display_callback_t cb);

#define display_printf(...)                                                    \
    do {                                                                       \
        if (g_print_callback)                                                  \
            g_print_callback(__VA_ARGS__);                                     \
        else                                                                   \
            printf(__VA_ARGS__);                                               \
    } while (0)

#define display_puts(str)                                                      \
    do {                                                                       \
        if (g_print_callback)                                                  \
            g_print_callback(str);                                             \
        else                                                                   \
            puts(str);                                                         \
    } while (0)

#endif
