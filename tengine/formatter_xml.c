#include "formatter_xml.h"
#include "filebuffer.h"
#include "formatter.h"
#include "util/str.h"
#include "value.h"
#include "defs.h"

#include <util/byte_to_str.h>
#include <util/str.h>
#include <strbuilder.h>
#include <display.h>
#include <alloc.h>
#include <log.h>
#include <ll.h>

#define min(x, y) ((x) < (y) ? (x) : (y))
#define printf_if_not_quiet(this, ...)                                         \
    if (!this->super->quiet_mode) {                                            \
        display_printf(__VA_ARGS__);                                           \
    }

typedef struct FormatterXML {
    Formatter* super;
} FormatterXML;

static void fmt_xml_dispose(FormatterXML* fmt) { bhex_free(fmt); }

static void fmt_xml_start_var(FormatterXML* this, const char* name,
                              const char* tyname, u64_t off)
{
    char* name_dup = bhex_strdup(name);
    strip_chars(name_dup, "\"'");
    char* tyname_dup = bhex_strdup(tyname);
    strip_chars(tyname_dup, "\"'");
    printf_if_not_quiet(this, "<var name=\"%s\" type=\"%s\" off=\"%llu\">",
                        name_dup, tyname_dup, off);
    bhex_free(name_dup);
    bhex_free(tyname_dup);
}

static void fmt_xml_end_var(FormatterXML* this, const char* name)
{
    printf_if_not_quiet(this, "</var>");
}

static void fmt_xml_process_buffer_value(FormatterXML* this, FileBuffer* fb,
                                         u64_t size)
{
    if (this->super->quiet_mode)
        return;

    u64_t off = 0;
    display_printf("<buffer>");
    while (off < size) {
        u64_t       to_read = min(size - off, fb_block_size);
        const u8_t* buf     = fb_read(fb, to_read);
        for (u64_t i = 0; i < to_read; ++i) {
            display_printf("%02x", buf[i]);
        }
        off += to_read;
    }
    display_printf("</buffer>");
}

static void fmt_xml_process_value(FormatterXML* this, TEngineValue* val)
{
    switch (val->t) {
        case TENGINE_UNUM:
            printf_if_not_quiet(this, "<unum size=\"%d\">%llu</unum>",
                                val->unum_size, val->unum);
            break;
        case TENGINE_SNUM:
            printf_if_not_quiet(this, "<snum size=\"%d\">%lld</snum>",
                                val->snum_size, val->snum);
            break;
        case TENGINE_CHAR:
            printf_if_not_quiet(this, "<char>%d</char>", val->c);
            break;
        case TENGINE_STRING:
            printf_if_not_quiet(this, "<buffer>");
            for (u32_t i = 0; i < val->str_size; ++i)
                display_printf("%02x", val->str[i]);
            printf_if_not_quiet(this, "</buffer>");
            break;
        case TENGINE_WSTRING:
            printf_if_not_quiet(this, "<buffer>");
            for (u32_t i = 0; i < val->wstr_size; ++i) {
                u16_t tmp = htons(val->wstr[i]);
                display_printf("%02x%02x", (tmp >> 8) & 0xff, tmp & 0xff);
            }
            printf_if_not_quiet(this, "</buffer>");
            break;
        case TENGINE_ENUM_VALUE: {
            char* enum_mnemonic = bhex_strdup(val->enum_value);
            strip_chars(enum_mnemonic, "\"'");
            printf_if_not_quiet(this,
                                "<enum_value mnemonic=\"%s\">%llu</enum_value>",
                                enum_mnemonic, val->enum_const);
            bhex_free(enum_mnemonic);
            break;
        }
        default:
            panic("process value called with an unexpected type");
            break;
    }
}

static void fmt_xml_start_array(FormatterXML* this, const Type* ty)
{
    char* tyname = bhex_strdup(ty->name);
    strip_chars(tyname, "\"'");
    printf_if_not_quiet(this, "<array type=\"%s\">", tyname);
    bhex_free(tyname);
}

static void fmt_xml_notify_array_el(FormatterXML* this, u64_t n) {}

static void fmt_xml_end_array(FormatterXML* this)
{
    printf_if_not_quiet(this, "</array>");
}

static void fmt_xml_start(FormatterXML* this)
{
    printf_if_not_quiet(this, "<root>");
}

static void fmt_xml_end(FormatterXML* this)
{
    printf_if_not_quiet(this, "</root>");
}

static void fmt_xml_start_print(FormatterXML* this)
{
    printf_if_not_quiet(this, "<!--");
}

static void fmt_xml_end_print(FormatterXML* this)
{
    printf_if_not_quiet(this, "-->");
}

static void fmt_xml_print(FormatterXML* this, const char* str)
{
    char* stripped_str = bhex_strdup(str);
    strip_chars(stripped_str, "<>");
    printf_if_not_quiet(this, "%s", stripped_str);
    bhex_free(stripped_str);
}

void fmt_xml_new(Formatter* obj)
{
    FormatterXML* this = bhex_calloc(sizeof(FormatterXML));
    this->super        = obj;

    obj->this              = this;
    obj->fmt_start         = (fmt_start_t)fmt_xml_start;
    obj->fmt_end           = (fmt_end_t)fmt_xml_end;
    obj->fmt_dispose       = (fmt_dispose_t)fmt_xml_dispose;
    obj->fmt_start_var     = (fmt_start_var_t)fmt_xml_start_var;
    obj->fmt_end_var       = (fmt_end_var_t)fmt_xml_end_var;
    obj->fmt_process_value = (fmt_process_value_t)fmt_xml_process_value;
    obj->fmt_process_buffer_value =
        (fmt_process_buffer_value_t)fmt_xml_process_buffer_value;
    obj->fmt_start_array     = (fmt_start_array_t)fmt_xml_start_array;
    obj->fmt_notify_array_el = (fmt_notify_array_el_t)fmt_xml_notify_array_el;
    obj->fmt_end_array       = (fmt_end_array_t)fmt_xml_end_array;
    obj->fmt_start_print     = (fmt_start_print_t)fmt_xml_start_print;
    obj->fmt_print           = (fmt_print_t)fmt_xml_print;
    obj->fmt_end_print       = (fmt_end_print_t)fmt_xml_end_print;
}
