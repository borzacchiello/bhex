
#ifndef TEMPLATE_H
#define TEMPLATE_H

typedef struct Template {
    const char* name;
    size_t (*get_size)();
    void (*pretty_print)(const u8_t*, size_t, int);
} Template;

extern Template templates[2];

#endif
