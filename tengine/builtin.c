#include "builtin.h"
#include "defs.h"
#include "display.h"
#include "filebuffer.h"
#include "strbuilder.h"
#include "interpreter.h"
#include "util/str.h"
#include "value.h"

#include <stddef.h>
#include <stdio.h>
#include <util/byte_to_num.h>
#include <string.h>
#include <alloc.h>
#include <log.h>

/*
    Builtin Types
*/

static TEngineValue* string_process(InterpreterContext* ctx)
{
    u64_t tmp_capacity = 8;
    u64_t tmp_size     = 0;
    u8_t* tmp          = bhex_calloc(tmp_capacity);

#define enlarge_tmp                                                            \
    if (tmp_size == tmp_capacity) {                                            \
        tmp_capacity *= 2;                                                     \
        tmp = bhex_realloc(tmp, tmp_capacity);                                 \
    }

    const u8_t* buf = fb_read(ctx->fb, 1);
    if (buf == NULL)
        return NULL;

    TEngineValue* r = NULL;
    while (*buf) {
        enlarge_tmp;

        tmp[tmp_size++] = (char)*buf;
        if (fb_seek(ctx->fb, ctx->fb->off + 1) != 0)
            goto end;
        buf = fb_read(ctx->fb, 1);
        if (buf == NULL)
            return NULL;
    }
    // seek after the NULL terminator
    if (fb_seek(ctx->fb, ctx->fb->off + 1) != 0)
        goto end;

    enlarge_tmp;
    tmp[tmp_size] = '\0';
    r             = TEngineValue_STRING_new(tmp, tmp_size);

end:
    bhex_free(tmp);
    return r;

#undef enlarge_tmp
}

static TEngineValue* wstring_process(InterpreterContext* ctx)
{
    u64_t  tmp_capacity = 8;
    u64_t  tmp_size     = 0;
    u16_t* tmp          = bhex_calloc(tmp_capacity * 2);

#define enlarge_tmp                                                            \
    if (tmp_size == tmp_capacity) {                                            \
        tmp_capacity *= 2;                                                     \
        tmp = bhex_realloc(tmp, tmp_capacity * 2);                             \
    }

    const u8_t* buf = fb_read(ctx->fb, 2);
    if (buf == NULL)
        return NULL;

    TEngineValue* r = NULL;
    while (*buf) {
        enlarge_tmp;

        tmp[tmp_size++] = ctx->endianess == TE_BIG_ENDIAN
                              ? (((u16_t)buf[0] << 8) | (u16_t)buf[1])
                              : (((u16_t)buf[1] << 8) | (u16_t)buf[0]);
        if (fb_seek(ctx->fb, ctx->fb->off + 2) != 0)
            goto end;
        buf = fb_read(ctx->fb, 2);
        if (buf == NULL)
            return NULL;
    }
    // seek after the NULL terminator
    if (fb_seek(ctx->fb, ctx->fb->off + 2) != 0)
        goto end;

    enlarge_tmp;
    tmp[tmp_size] = 0;
    r             = TEngineValue_WSTRING_new(tmp, tmp_size);

end:
    bhex_free(tmp);
    return r;

#undef enlarge_tmp
}

static TEngineValue* char_process(InterpreterContext* ctx)
{
    const u8_t* buf = fb_read(ctx->fb, 1);
    if (buf == NULL)
        return NULL;
    if (fb_seek(ctx->fb, ctx->fb->off + 1) != 0)
        return NULL;
    return TEngineValue_CHAR_new(*buf);
}

static TEngineValue* wchar_process(InterpreterContext* ctx)
{
    const u8_t* buf = fb_read(ctx->fb, 2);
    if (buf == NULL)
        return NULL;
    if (fb_seek(ctx->fb, ctx->fb->off + 2) != 0)
        return NULL;
    if (ctx->endianess == TE_BIG_ENDIAN)
        return TEngineValue_WCHAR_new(((u16_t)buf[0] << 8) | (u16_t)buf[1]);
    return TEngineValue_WCHAR_new(((u16_t)buf[1] << 8) | (u16_t)buf[0]);
}

static TEngineValue* uint_process(InterpreterContext* e, const u8_t* buf,
                                  u32_t size)
{
    u64_t v = 0;
    for (u32_t i = 0; i < size; ++i) {
        v |= (u64_t)buf[i] << ((e->endianess == TE_BIG_ENDIAN)
                                   ? ((size - i - 1) * 8)
                                   : (i * 8));
    }
    return TEngineValue_UNUM_new(v, size);
}

static TEngineValue* int_process(InterpreterContext* e, const u8_t* buf,
                                 u32_t size)
{
    u64_t v = 0;
    for (u32_t i = 0; i < size; ++i) {
        v |= (u64_t)buf[i] << ((e->endianess == TE_BIG_ENDIAN)
                                   ? ((size - i - 1) * 8)
                                   : (i * 8));
    }

    s64_t sv = 0;
    switch (size) {
        case 1:
            sv = (s64_t)(s8_t)v;
            break;
        case 2:
            sv = (s64_t)(s16_t)v;
            break;
        case 4:
            sv = (s64_t)(s32_t)v;
            break;
        case 8:
            sv = (s64_t)v;
            break;
        default:
            panic("invalid size (%u) in 'int_print'", size);
    }
    return TEngineValue_SNUM_new(sv, size);
}

#define GEN_INT_PROCESS(name, size, signed)                                    \
    static TEngineValue* name##_process(InterpreterContext* ctx)               \
    {                                                                          \
        const u8_t* buf = fb_read(ctx->fb, size);                              \
        fb_seek(ctx->fb, ctx->fb->off + size);                                 \
        if (buf == NULL)                                                       \
            return NULL;                                                       \
        if (!signed)                                                           \
            return uint_process(ctx, buf, size);                               \
        return int_process(ctx, buf, size);                                    \
    }

GEN_INT_PROCESS(u64, 8, 0)
GEN_INT_PROCESS(u32, 4, 0)
GEN_INT_PROCESS(u16, 2, 0)
GEN_INT_PROCESS(u8, 1, 0)
GEN_INT_PROCESS(i64, 8, 1)
GEN_INT_PROCESS(i32, 4, 1)
GEN_INT_PROCESS(i16, 2, 1)
GEN_INT_PROCESS(i8, 1, 1)

static TEngineBuiltinType builtin_types[] = {
    {"u64", u64_process},      {"u32", u32_process},
    {"u16", u16_process},      {"u8", u8_process},
    {"i64", i64_process},      {"i32", i32_process},
    {"i16", i16_process},      {"i8", i8_process},
    {"uint64_t", u64_process}, {"uint32_t", u32_process},
    {"uint16_t", u16_process}, {"uint8_t", u8_process},
    {"int64_t", i64_process},  {"int32_t", i32_process},
    {"int16_t", i16_process},  {"int8_t", i8_process},
    {"char", char_process},    {"string", string_process},
    {"wchar", wchar_process},  {"wstring", wstring_process},
};

const TEngineBuiltinType* get_builtin_type(const char* type)
{
    for (u64_t i = 0; i < sizeof(builtin_types) / sizeof(TEngineBuiltinType);
         ++i) {
        TEngineBuiltinType* t = &builtin_types[i];
        if (strcmp(t->name, type) == 0) {
            return t;
        }
    }
    return NULL;
}

/*
    Builtin Functions
*/

#define GEN_INT_CAST(name, sz, signed)                                         \
    static TEngineValue* builtin_##name(InterpreterContext* ctx,               \
                                        DList*              params)            \
    {                                                                          \
        if (!params || params->size == 0) {                                    \
            tengine_raise_exception(ctx,                                       \
                                    "" #name ": missing required parameter");  \
            return NULL;                                                       \
        }                                                                      \
        if (signed) {                                                          \
            s64_t s;                                                           \
            if (TEngineValue_as_s64(ctx, params->data[0], &s) != 0) {          \
                tengine_raise_exception(ctx,                                   \
                                        "builtin_" #name                       \
                                        " parameter cannot be casted to s64"); \
                return NULL;                                                   \
            }                                                                  \
            return TEngineValue_SNUM_new(s, sz);                               \
        }                                                                      \
        u64_t u;                                                               \
        if (TEngineValue_as_u64(ctx, params->data[0], &u) != 0) {              \
            tengine_raise_exception(                                           \
                ctx, "builtin_" #name " parameter cannot be casted to u64");   \
            return NULL;                                                       \
        }                                                                      \
        return TEngineValue_UNUM_new(u, sz);                                   \
    }

GEN_INT_CAST(u8, 1, 0)
GEN_INT_CAST(u16, 2, 0)
GEN_INT_CAST(u32, 4, 0)
GEN_INT_CAST(u64, 8, 0)
GEN_INT_CAST(i8, 1, 1)
GEN_INT_CAST(i16, 2, 1)
GEN_INT_CAST(i32, 4, 1)
GEN_INT_CAST(i64, 8, 1)

static TEngineValue* builtin_off(InterpreterContext* ctx, DList* params)
{
    if (params && params->size > 0) {
        tengine_raise_exception(ctx, "off: expected no parameter");
        return NULL;
    }

    return TEngineValue_UNUM_new(ctx->fb->off, 8);
}

static TEngineValue* builtin_size(InterpreterContext* ctx, DList* params)
{
    if (params && params->size > 0) {
        tengine_raise_exception(ctx, "size: expected no parameter");
        return NULL;
    }

    return TEngineValue_UNUM_new(ctx->fb->size, 8);
}

static TEngineValue* builtin_remaining_size(InterpreterContext* ctx,
                                            DList*              params)
{
    if (params && params->size > 0) {
        tengine_raise_exception(ctx, "remaining_size: expected no parameter");
        return NULL;
    }

    return TEngineValue_UNUM_new(ctx->fb->size - ctx->fb->off, 8);
}

static TEngineValue* builtin_atoi(InterpreterContext* ctx, DList* params)
{
    if (!params || params->size != 1) {
        tengine_raise_exception(ctx, "atoi: missing required parameter");
        return NULL;
    }

    TEngineValue* param = params->data[0];
    const char*   param_str;
    if (TEngineValue_as_string(ctx, param, &param_str) != 0) {
        tengine_raise_exception(ctx, "atoi: expected a string parameter");
        return NULL;
    }

    s64_t oval;
    if (!str_to_int64(param_str, &oval)) {
        tengine_raise_exception(ctx, "atoi: invalid string %s", param_str);
        return NULL;
    }
    return TEngineValue_SNUM_new(oval, 64);
}

static TEngineValue* builtin_strlen(InterpreterContext* ctx, DList* params)
{
    if (!params || params->size != 1) {
        tengine_raise_exception(ctx, "strlen: missing required parameter");
        return NULL;
    }

    TEngineValue* param = params->data[0];
    const char*   param_str;
    if (TEngineValue_as_string(ctx, param, &param_str) != 0) {
        tengine_raise_exception(ctx, "strlen: expected a string parameter");
        return NULL;
    }

    return TEngineValue_UNUM_new(strlen(param_str), 8);
}

static TEngineValue* builtin_strip(InterpreterContext* ctx, DList* params)
{
    if (!params || params->size != 1) {
        tengine_raise_exception(ctx, "strip: missing required parameter");
        return NULL;
    }

    TEngineValue* param = params->data[0];
    const char*   param_str;
    if (TEngineValue_as_string(ctx, param, &param_str) != 0) {
        tengine_raise_exception(ctx, "strip: expected a string parameter");
        return NULL;
    }
    size_t param_len = strlen(param_str);

    StringBuilder* sb = strbuilder_new();
    for (size_t i = 0; i < param_len; ++i) {
        if (param_str[i] != ' ' && param_str[i] != '\t' &&
            param_str[i] != '\n' && param_str[i] > 0x20 && param_str[i] < 0x7f)
            strbuilder_append_char(sb, param_str[i]);
    }

    char*         str = strbuilder_finalize(sb);
    TEngineValue* r   = TEngineValue_STRING_new((const u8_t*)str, strlen(str));
    bhex_free(str);
    return r;
}

static TEngineValue* builtin_little_endian(InterpreterContext* ctx,
                                           DList*              params)
{
    if (params && params->size > 0) {
        tengine_raise_exception(ctx, "little_endian: expected no parameter");
        return NULL;
    }

    ctx->endianess = TE_LITTLE_ENDIAN;
    return NULL;
}

static TEngineValue* builtin_big_endian(InterpreterContext* ctx, DList* params)
{
    if (params && params->size > 0) {
        tengine_raise_exception(ctx, "big_endian: expected no parameter");
        return NULL;
    }

    ctx->endianess = TE_BIG_ENDIAN;
    return NULL;
}

static TEngineValue* builtin_nums_in_hex(InterpreterContext* ctx, DList* params)
{
    if (params && params->size > 0) {
        tengine_raise_exception(ctx, "nums_in_hex: expected no parameter");
        return NULL;
    }

    ctx->fmt->print_in_hex = 1;
    return NULL;
}

static TEngineValue* builtin_nums_in_dec(InterpreterContext* ctx, DList* params)
{
    if (params && params->size > 0) {
        tengine_raise_exception(ctx, "nums_in_dec: expected no parameter");
        return NULL;
    }

    ctx->fmt->print_in_hex = 0;
    return NULL;
}

static TEngineValue* builtin_disable_print(InterpreterContext* ctx,
                                           DList*              params)
{
    if (params && params->size > 0) {
        tengine_raise_exception(ctx, "disable_print: expected no parameter");
        return NULL;
    }

    ctx->fmt->quiet_mode = 1;
    return NULL;
}

static TEngineValue* builtin_enable_print(InterpreterContext* ctx,
                                          DList*              params)
{
    if (params && params->size > 0) {
        tengine_raise_exception(ctx, "enable_print: expected no parameter");
        return NULL;
    }

    ctx->fmt->quiet_mode = 0;
    return NULL;
}

static TEngineValue* builtin_seek(InterpreterContext* ctx, DList* params)
{
    if (!params || params->size != 1) {
        tengine_raise_exception(ctx, "seek: expected a parameter");
        return NULL;
    }

    TEngineValue* param = params->data[0];
    u64_t         param_u64;
    if (TEngineValue_as_u64(ctx, param, &param_u64) != 0) {
        tengine_raise_exception(ctx, "seek: expected an uint parameter");
        return NULL;
    }

    if (fb_seek(ctx->fb, param_u64) != 0) {
        tengine_raise_exception(ctx, "unable to seek to offset '%lld'",
                                param_u64);
        return NULL;
    }
    return NULL;
}

static TEngineValue* builtin_fwd(InterpreterContext* ctx, DList* params)
{
    if (!params || params->size != 1) {
        tengine_raise_exception(ctx, "fwd: expected a parameter");
        return NULL;
    }

    TEngineValue* param = params->data[0];
    u64_t         param_u64;
    if (TEngineValue_as_u64(ctx, param, &param_u64) != 0) {
        tengine_raise_exception(ctx, "fwd: expected an uint parameter");
        return NULL;
    }

    if (fb_seek(ctx->fb, param_u64 + ctx->fb->off) != 0) {
        tengine_raise_exception(ctx, "unable to fwd to offset '%lld'",
                                param_u64);
        return NULL;
    }
    return NULL;
}

static TEngineValue* builtin_print(InterpreterContext* ctx, DList* params)
{
    if (!params || params->size == 0) {
        tengine_raise_exception(ctx, "print: expected at least a parameter");
        return NULL;
    }

    for (u64_t i = 0; i < params->size; ++i) {
        TEngineValue* p = params->data[i];
        if (p->t == TENGINE_STRING) {
            display_printf("%.*s ", p->str_size, p->str);
        } else {
            char* p_str = TEngineValue_tostring(p, 0);
            display_printf("%s ", p_str);
            bhex_free(p_str);
        }
    }
    display_printf("\n");
    return NULL;
}

static TEngineValue* builtin_error(InterpreterContext* ctx, DList* params)
{
    if (!params || params->size != 1) {
        tengine_raise_exception(ctx, "RUNTIME ERROR");
        return NULL;
    }
    TEngineValue* p = params->data[0];
    tengine_raise_exception(ctx, "RUNTIME ERROR: %.*s", p->str_size, p->str);
    return NULL;
}

static TEngineValue* builtin_exit(InterpreterContext* ctx, DList* params)
{
    tengine_raise_exit_request(ctx);
    return NULL;
}

static TEngineValue* builtin_find(InterpreterContext* ctx, DList* params)
{
    if (!params || params->size == 0) {
        tengine_raise_exception(ctx, "find: at least one parameter required");
        return NULL;
    }

    TEngineValue* what = params->data[0];
    if (what->t != TENGINE_STRING) {
        tengine_raise_exception(ctx,
                                "find: expected a string as first parameter");
        return NULL;
    }

    if (what->str_size == 0) {
        warning("find: empty string");
        return NULL;
    }

    int direction_forward = 1;
    if (params->size > 1) {
        // second parameter: if > 0, backward search
        TEngineValue* param = params->data[1];
        u64_t         param_u64;
        if (TEngineValue_as_u64(ctx, param, &param_u64) != 0) {
            tengine_raise_exception(ctx, "find: expected a bool");
            return NULL;
        }
        direction_forward = !param_u64;
    }

    u8_t*  what_bytes = NULL;
    size_t what_len   = 0;
    char*  what_str   = bhex_calloc(what->str_size + 1);
    memcpy(what_str, what->str, what->str_size);
    if (!unescape_ascii_string(what_str, &what_bytes, &what_len)) {
        tengine_raise_exception(ctx, "find: invalid string");
        bhex_free(what_str);
        return NULL;
    }
    bhex_free(what_str);

    u64_t orig_off = ctx->fb->off;
    if (direction_forward) {
        size_t what_off = 0;
        u64_t  curr_off = orig_off;

        while (curr_off < ctx->fb->size) {
            if (fb_seek(ctx->fb, curr_off) != 0)
                panic("fb_seek failed in an unexpected way");

            size_t to_read = fb_block_size;
            if (to_read > ctx->fb->size - ctx->fb->off)
                to_read = ctx->fb->size - ctx->fb->off;

            const u8_t* data = fb_read(ctx->fb, to_read);
            if (data == NULL) {
                bhex_free(what_bytes);
                return NULL;
            }

            u32_t data_off = 0;
            while (data_off < to_read && what_off < what_len) {
                if (data[data_off] == what_bytes[what_off])
                    what_off++;
                else
                    what_off = 0;
                data_off++;
            }

            if (what_off == what_len) {
                // we have a match
                if (fb_seek(ctx->fb, ctx->fb->off + data_off - what_len) != 0)
                    panic("fb_seek failed in an unexpected way");
                bhex_free(what_bytes);
                return TEngineValue_UNUM_new(1, 1);
            }

            curr_off += to_read;
        }

        // no match
        if (fb_seek(ctx->fb, orig_off) != 0)
            panic("fb_seek failed in an unexpected way");
        bhex_free(what_bytes);
        return TEngineValue_UNUM_new(0, 1);
    }

    // Backward search
    u32_t what_off = what_len - 1;
    u64_t prev_off = orig_off;
    u64_t curr_off =
        (prev_off < fb_block_size) ? 0 : (prev_off - fb_block_size);

    while (1) {
        if (fb_seek(ctx->fb, curr_off) != 0)
            panic("fb_seek failed in an unexpected way");

        size_t to_read = (prev_off - curr_off < fb_block_size)
                             ? prev_off - curr_off
                             : fb_block_size;
        if (to_read == 0)
            break;

        const u8_t* data = fb_read(ctx->fb, to_read);
        if (data == NULL) {
            bhex_free(what_bytes);
            return NULL;
        }

        u32_t data_off = to_read - 1;
        while (1) {
            if (data_off == 0 || what_off == 0)
                break;
            if (data[data_off] == what_bytes[what_off]) {
                what_off--;
            } else {
                what_off = what_len - 1;
            }
            data_off--;
        }

        if (what_off == 0) {
            // we have a match
            if (fb_seek(ctx->fb, ctx->fb->off + data_off) != 0)
                panic("fb_seek failed in an unexpected way");
            bhex_free(what_bytes);
            return TEngineValue_UNUM_new(1, 1);
        }

        if (curr_off == 0)
            break;
        prev_off = curr_off;
        curr_off = prev_off < fb_block_size ? 0 : (prev_off - fb_block_size);
    }

    // no match
    if (fb_seek(ctx->fb, orig_off) != 0)
        panic("fb_seek failed in an unexpected way");
    bhex_free(what_bytes);
    return TEngineValue_UNUM_new(0, 1);
}

static TEngineBuiltinFunc builtin_funcs[] = {
    {"u8", builtin_u8},
    {"u16", builtin_u16},
    {"u32", builtin_u32},
    {"u64", builtin_u64},
    {"i8", builtin_i8},
    {"i16", builtin_i16},
    {"i32", builtin_i32},
    {"i64", builtin_i64},
    {"exit", builtin_exit},
    {"little_endian", builtin_little_endian},
    {"big_endian", builtin_big_endian},
    {"nums_in_hex", builtin_nums_in_hex},
    {"nums_in_dec", builtin_nums_in_dec},
    {"disable_print", builtin_disable_print},
    {"enable_print", builtin_enable_print},
    {"seek", builtin_seek},
    {"fwd", builtin_fwd},
    {"off", builtin_off},
    {"size", builtin_size},
    {"remaining_size", builtin_remaining_size},
    {"print", builtin_print},
    {"error", builtin_error},
    {"atoi", builtin_atoi},
    {"strip", builtin_strip},
    {"strlen", builtin_strlen},
    {"find", builtin_find},
};

const TEngineBuiltinFunc* get_builtin_func(const char* name)
{
    for (u64_t i = 0; i < sizeof(builtin_funcs) / sizeof(TEngineBuiltinFunc);
         ++i) {
        TEngineBuiltinFunc* t = &builtin_funcs[i];
        if (strcmp(t->name, name) == 0) {
            return t;
        }
    }
    return NULL;
}
