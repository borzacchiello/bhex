#ifndef FORMATTER_H
#define FORMATTER_H

#include "ast.h"
#include "filebuffer.h"
#include "value.h"
#include <defs.h>

typedef void (*fmt_start_t)(void* this);
typedef void (*fmt_end_t)(void* this);
typedef void (*fmt_start_var_t)(void* this, const char* name,
                                const char* tyname, u64_t off);
typedef void (*fmt_start_print_t)(void* this);
typedef void (*fmt_print_t)(void* this, const char* str);
typedef void (*fmt_end_print_t)(void* this);
typedef void (*fmt_end_var_t)(void* this, const char* name);
typedef void (*fmt_process_value_t)(void* this, BHEngineValue* val);
typedef void (*fmt_process_buffer_value_t)(void* this, FileBuffer* buf,
                                           u64_t size);
typedef void (*fmt_start_array_t)(void* this, const Type* ty);
typedef void (*fmt_notify_array_el_t)(void* this, u64_t n);
typedef void (*fmt_end_array_t)(void* this);
typedef void (*fmt_dispose_t)(void* obj);

typedef enum fmt_t {
    FMT_UNK  = 0,
    FMT_TERM = 1,
    FMT_XML  = 2,
} fmt_t;

typedef struct Formatter {
    void* this;
    fmt_dispose_t              fmt_dispose;
    fmt_start_t                fmt_start;
    fmt_end_t                  fmt_end;
    fmt_start_var_t            fmt_start_var;
    fmt_end_var_t              fmt_end_var;
    fmt_process_value_t        fmt_process_value;
    fmt_process_buffer_value_t fmt_process_buffer_value;
    fmt_start_array_t          fmt_start_array;
    fmt_notify_array_el_t      fmt_notify_array_el;
    fmt_end_array_t            fmt_end_array;
    fmt_start_print_t          fmt_start_print;
    fmt_print_t                fmt_print;
    fmt_end_print_t            fmt_end_print;

    int   quiet_mode;
    int   print_in_hex;
    u32_t max_ident_len;
} Formatter;

Formatter* fmt_new(fmt_t type);
void       fmt_dispose(Formatter* fmt);

#define fmt_start(obj)              (obj)->fmt_start(obj->this)
#define fmt_end(obj)                (obj)->fmt_end(obj->this)
#define fmt_start_var(obj, n, t, o) (obj)->fmt_start_var(obj->this, n, t, o)
#define fmt_end_var(obj, n)         (obj)->fmt_end_var(obj->this, n)
#define fmt_process_value(obj, v)   (obj)->fmt_process_value(obj->this, v)
#define fmt_process_buffer_value(obj, f, s)                                    \
    (obj)->fmt_process_buffer_value(obj->this, f, s)
#define fmt_start_array(obj, t)     (obj)->fmt_start_array(obj->this, t)
#define fmt_notify_array_el(obj, n) (obj)->fmt_notify_array_el(obj->this, n)
#define fmt_end_array(obj)          (obj)->fmt_end_array(obj->this)
#define fmt_start_print(obj)        (obj)->fmt_start_print(obj->this)
#define fmt_print(obj, str)         (obj)->fmt_print(obj->this, str)
#define fmt_end_print(obj)          (obj)->fmt_end_print(obj->this)

#endif
