#include "display.h"

display_callback_t g_print_callback;

void display_set_print_callback(display_callback_t cb)
{
    g_print_callback = cb;
}
