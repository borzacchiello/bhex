// Copyright (c) 2022-2026, bageyelet

#include "formatter_term.h"
#include "formatter.h"
#include "builtin.h"
#include "value.h"

#include <filebuffer.h>
#include <display.h>
#include <color.h>
#include <alloc.h>
#include <defs.h>
#include <log.h>
#include <ll.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

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
    // truncation of arrays of structs: the elements past the limit are still
    // parsed (the offset must advance) but printed in quiet mode. depth is the
    // array nesting level, hidden_at_depth the level of the array that got
    // truncated, or 0 when we are printing everything
    u64_t depth;
    u64_t hidden_at_depth;
    u64_t hidden_saved_quiet_mode;
    u64_t hidden_limit;
    u64_t hidden_num_els;
} FormatterTerm;

// The number of elements to print, 0 meaning "all of them". A template can
// override it with max_array_print(); by default only the arrays of a builtin
// type are truncated, as an array of structs is usually worth printing in full
static u64_t fmt_term_array_limit(FormatterTerm* this)
{
    if (this->super->max_array_print != FMT_MAX_ARRAY_PRINT_UNSET)
        return this->super->max_array_print;
    return this->last_array_type_was_builtin ? MAX_ARR_PRINT_SIZE : 0;
}

// The name of a field is right adjusted on a column that is the same for every
// field of a nesting level, and that moves right by FMT_PRINT_OFF_STEP at each
// level: the indentation is part of the padding, so that a name longer than the
// column of its level eats into it instead of pushing the whole line right
static u32_t fmt_term_name_width(FormatterTerm* this)
{
    return (u32_t)this->super->max_fvar_len + this->print_off;
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
        // the escapes wrap the whole (padded) field, so that they do not
        // eat into the width of the name column
        display_printf("%sb+%08llx%s ", color_str(COLOR_ADDR), off,
                       color_str(COLOR_RESET));
        display_printf("%s", color_str(COLOR_LABEL));
        display_printf(" %*s: ", (int)fmt_term_name_width(this), name);
        display_printf("%s", color_str(COLOR_RESET));
    }
    this->print_off += FMT_PRINT_OFF_STEP;
}

static void fmt_term_end_var(FormatterTerm* this, const char* name)
{
    if (this->print_off < FMT_PRINT_OFF_STEP)
        panic("no var to end");

    this->print_off -= FMT_PRINT_OFF_STEP;
}

static void fmt_term_process_buffer_value(FormatterTerm* this, FileBuffer* fb,
                                          u64_t size)
{
    if (this->super->quiet_mode)
        return;

    const u8_t* buf = fb_read(fb, min(size, MAX_BUF_PRINT));
    if (buf == NULL)
        return;

    u32_t i = 0;
    for (; i < min(size, MAX_BUF_PRINT); ++i) {
        display_printf("%02x", buf[i]);
    }
    if (i < size)
        display_printf("...");
}

static void fmt_term_process_value(FormatterTerm* this, BHEngineValue* val)
{
    // an element past the print limit: consume the flag, print nothing. It has
    // to be cleared here, or every value printed afterwards would be skipped
    if (this->skip_next) {
        this->skip_next = 0;
        return;
    }
    if (this->super->quiet_mode)
        return;

    if (val->t == TENGINE_ARRAY || val->t == TENGINE_OBJ ||
        val->t == TENGINE_BUF)
        panic("process value called with an unexpected type");

    char* value_str = BHEngineValue_tostring(val, this->super->print_in_hex,
                                             (u32_t)this->super->max_fvar_len);
    display_printf("%s", value_str);
    bhex_free(value_str);
}

static void fmt_term_start_array(FormatterTerm* this, const Type* ty)
{
    this->depth += 1;
    if (!this->super->quiet_mode)
        display_printf("[ ");

    this->is_first_element            = 1;
    this->prev_array_type_was_builtin = this->last_array_type_was_builtin;
    this->last_array_type_was_builtin = is_builtin_type(ty->name);
    if (this->last_array_type_was_builtin)
        this->print_off += FMT_PRINT_OFF_STEP;
}

// The '[i]' marker of an array of structs, and the '... N more' line closing a
// truncated one, sit on a line of their own. They are laid out like a field
// name -- the offset column is left blank, and the text is right adjusted on
// the same column -- so that the marker lines up with the element it labels
// instead of floating to the left of it
static void fmt_term_print_el_label(FormatterTerm* this, const char* label)
{
    display_printf("\n           ");
    display_printf(" %*s", (int)fmt_term_name_width(this), label);
}

static void fmt_term_notify_array_el(FormatterTerm* this, u64_t n)
{
    if (this->hidden_at_depth != 0) {
        // an element of a truncated array, or anything nested in it: count it,
        // print nothing
        if (this->depth == this->hidden_at_depth)
            this->hidden_num_els = n + 1;
        return;
    }

    u64_t limit = fmt_term_array_limit(this);

    if (this->last_array_type_was_builtin) {
        if (limit != 0 && n >= limit) {
            this->skip_next = 1;
            if (n == limit && !this->super->quiet_mode)
                display_printf(", ...");
            return;
        }
        if (!this->is_first_element && !this->super->quiet_mode)
            display_printf(", ");
        this->is_first_element = 0;
        return;
    }

    if (limit != 0 && n >= limit) {
        // stop printing, but let the interpreter parse the remaining elements
        this->hidden_at_depth         = this->depth;
        this->hidden_saved_quiet_mode = this->super->quiet_mode;
        this->hidden_limit            = limit;
        this->hidden_num_els          = n + 1;
        this->super->quiet_mode       = 1;
        return;
    }

    if (!this->super->quiet_mode) {
        char idx[32];
        snprintf(idx, sizeof(idx), "[%llu]", n);
        fmt_term_print_el_label(this, idx);
    }
}

static void fmt_term_end_array(FormatterTerm* this)
{
    if (this->hidden_at_depth == this->depth && this->hidden_at_depth != 0) {
        this->super->quiet_mode = this->hidden_saved_quiet_mode;
        if (!this->super->quiet_mode) {
            char  summary[128];
            u64_t hidden = this->hidden_num_els - this->hidden_limit;
            snprintf(summary, sizeof(summary),
                     "... %llu more element%s (%llu in total)", hidden,
                     hidden == 1 ? "" : "s", this->hidden_num_els);
            fmt_term_print_el_label(this, summary);
        }
        this->hidden_at_depth = 0;
    }
    if (this->depth > 0)
        this->depth -= 1;

    if (!this->super->quiet_mode)
        display_printf(" ]");
    if (this->last_array_type_was_builtin) {
        if (this->print_off < FMT_PRINT_OFF_STEP)
            panic("no array to end");
        this->print_off -= FMT_PRINT_OFF_STEP;
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
