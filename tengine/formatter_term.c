#include "formatter_term.h"
#include "filebuffer.h"
#include "formatter.h"
#include "builtin.h"
#include "value.h"
#include "defs.h"

#include <display.h>
#include <alloc.h>
#include <log.h>
#include <ll.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

#define PRINT_OFF_STEP     4
#define MAX_ARR_PRINT_SIZE 16
#define MAX_BUF_PRINT      16

typedef struct FormatterTerm {
    Formatter* super;

    u32_t print_off;
    int   on_a_new_line;
    // array print context
    int is_first_element;
    int skip_next;
    int last_array_type_was_builtin;
    int prev_array_type_was_builtin;
} FormatterTerm;

static void fmt_term_print_off(FormatterTerm* this)
{
    for (u32_t i = 0; i < this->print_off; ++i)
        display_printf(" ");
}

static void fmt_term_dispose(FormatterTerm* fmt) { bhex_free(fmt); }

static void fmt_term_start_var(FormatterTerm* this, const char* name,
                               const char* tyname, u64_t off)
{
    if (!this->super->quiet_mode) {
        if (!this->on_a_new_line)
            display_printf("\n");
        else
            this->on_a_new_line = 0;
        display_printf("b+%08llx ", off);
        fmt_term_print_off(this);
        display_printf(" %*s: ", this->super->max_ident_len, name);
    }
    this->print_off += PRINT_OFF_STEP;
}

static void fmt_term_end_var(FormatterTerm* this, const char* name)
{
    if (this->print_off < PRINT_OFF_STEP)
        panic("no var to end");

    this->print_off -= PRINT_OFF_STEP;
}

static void fmt_term_process_buffer_value(FormatterTerm* this, FileBuffer* fb,
                                          u64_t size)
{
    if (this->super->quiet_mode)
        return;

    const u8_t* buf = fb_read(fb, min(size, MAX_BUF_PRINT));

    u32_t i = 0;
    for (; i < min(size, MAX_BUF_PRINT); ++i) {
        display_printf("%02x", buf[i]);
    }
    if (i < size)
        display_printf("...");
}

static void fmt_term_process_value(FormatterTerm* this, TEngineValue* val)
{
    if (this->super->quiet_mode || this->skip_next)
        return;
    this->skip_next = 0;

    if (val->t == TENGINE_ARRAY || val->t == TENGINE_OBJ ||
        val->t == TENGINE_BUF)
        panic("process value called with an unexpected type");

    char* value_str = TEngineValue_tostring(val, this->super->print_in_hex);
    display_printf("%s", value_str);
    bhex_free(value_str);
}

static void fmt_term_start_array(FormatterTerm* this, const Type* ty)
{
    if (!this->super->quiet_mode)
        display_printf("[ ");

    this->is_first_element            = 1;
    this->prev_array_type_was_builtin = this->last_array_type_was_builtin;
    this->last_array_type_was_builtin = is_builtin_type(ty->name);
    if (this->last_array_type_was_builtin)
        this->print_off += PRINT_OFF_STEP;
}

static void fmt_term_notify_array_el(FormatterTerm* this, u64_t n)
{
    if (this->last_array_type_was_builtin) {
        if (n >= MAX_ARR_PRINT_SIZE) {
            this->skip_next = 1;
            if (n == MAX_ARR_PRINT_SIZE && !this->super->quiet_mode)
                display_printf(", ...");
            return;
        }
        if (!this->is_first_element && !this->super->quiet_mode)
            display_printf(", ");
        this->is_first_element = 0;
        return;
    }

    if (!this->super->quiet_mode) {
        display_printf("\n           ");
        fmt_term_print_off(this);
        display_printf("[%llu]", n);
    }
}

static void fmt_term_end_array(FormatterTerm* this)
{
    if (!this->super->quiet_mode)
        display_printf(" ]");
    if (this->last_array_type_was_builtin) {
        if (this->print_off < PRINT_OFF_STEP)
            panic("no array to end");
        this->print_off -= PRINT_OFF_STEP;
    }
    this->last_array_type_was_builtin = this->prev_array_type_was_builtin;
}

static void fmt_term_start_print(FormatterTerm* this)
{
    // Print in TERM mode ignores the quiet mode...
    if (!this->on_a_new_line) {
        this->on_a_new_line = 1;
        display_printf("\n");
    }
}

static void fmt_term_print(FormatterTerm* this, const char* str)
{
    // Print in TERM mode ignores the quiet mode...
    display_printf("%s", str);
}

static void do_nothing(FormatterTerm* this) {}

void fmt_term_new(Formatter* obj)
{
    FormatterTerm* this = bhex_calloc(sizeof(FormatterTerm));
    this->super         = obj;
    this->on_a_new_line = 1;

    obj->this              = this;
    obj->fmt_dispose       = (fmt_dispose_t)fmt_term_dispose;
    obj->fmt_start         = (fmt_start_t)do_nothing;
    obj->fmt_end           = (fmt_end_t)do_nothing;
    obj->fmt_start_var     = (fmt_start_var_t)fmt_term_start_var;
    obj->fmt_end_var       = (fmt_end_var_t)fmt_term_end_var;
    obj->fmt_process_value = (fmt_process_value_t)fmt_term_process_value;
    obj->fmt_process_buffer_value =
        (fmt_process_buffer_value_t)fmt_term_process_buffer_value;
    obj->fmt_start_array     = (fmt_start_array_t)fmt_term_start_array;
    obj->fmt_notify_array_el = (fmt_notify_array_el_t)fmt_term_notify_array_el;
    obj->fmt_end_array       = (fmt_end_array_t)fmt_term_end_array;
    obj->fmt_start_print     = (fmt_start_print_t)fmt_term_start_print;
    obj->fmt_print           = (fmt_print_t)fmt_term_print;
    obj->fmt_end_print       = (fmt_end_print_t)do_nothing;
}
