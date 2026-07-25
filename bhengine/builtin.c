// Copyright (c) 2022-2026, bageyelet

#include "builtin.h"
#include <defs.h>
#include "filebuffer.h"
#include "formatter.h"
#include "strbuilder.h"
#include "interpreter.h"
#include "util/str.h"
#include "value.h"

#include <hash/hash_registry.h>
#include <checksums.h>
#include <entropy.h>
#include <crc.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <util/byte_to_num.h>
#include <string.h>
#include <alloc.h>
#include <log.h>
#include <map.h>

/*
    Builtin Types
*/

static BHEngineValue* string_process(InterpreterContext* ctx)
{
    u64_t tmp_capacity = 8;
    u64_t tmp_size     = 0;
    u8_t* tmp          = bhex_calloc(tmp_capacity);

#define enlarge_tmp                                                            \
    if (tmp_size == tmp_capacity) {                                            \
        tmp_capacity *= 2;                                                     \
        tmp = bhex_realloc(tmp, tmp_capacity);                                 \
    }

    BHEngineValue* r   = NULL;
    const u8_t*    buf = fb_read(ctx->fb, 1);
    if (buf == NULL)
        goto end;

    while (*buf) {
        enlarge_tmp;

        tmp[tmp_size++] = (char)*buf;
        if (fb_seek(ctx->fb, ctx->fb->off + 1) != 0)
            goto end;
        buf = fb_read(ctx->fb, 1);
        if (buf == NULL)
            goto end;
    }
    // seek after the NULL terminator
    if (fb_seek(ctx->fb, ctx->fb->off + 1) != 0)
        goto end;

    enlarge_tmp;
    tmp[tmp_size] = '\0';
    r             = BHEngineValue_STRING_new(tmp, tmp_size);

end:
    bhex_free(tmp);
    return r;

#undef enlarge_tmp
}

static BHEngineValue* wstring_process(InterpreterContext* ctx)
{
    u64_t  tmp_capacity = 8;
    u64_t  tmp_size     = 0;
    u16_t* tmp          = bhex_calloc(tmp_capacity * 2);

#define enlarge_tmp                                                            \
    if (tmp_size == tmp_capacity) {                                            \
        tmp_capacity *= 2;                                                     \
        tmp = bhex_realloc(tmp, tmp_capacity * 2);                             \
    }

    BHEngineValue* r   = NULL;
    const u8_t*    buf = fb_read(ctx->fb, 2);
    if (buf == NULL)
        goto end;

    while (*buf) {
        enlarge_tmp;

        tmp[tmp_size++] = ctx->endianess == TE_BIG_ENDIAN
                              ? (((u16_t)buf[0] << 8) | (u16_t)buf[1])
                              : (((u16_t)buf[1] << 8) | (u16_t)buf[0]);
        if (fb_seek(ctx->fb, ctx->fb->off + 2) != 0)
            goto end;
        buf = fb_read(ctx->fb, 2);
        if (buf == NULL)
            goto end;
    }
    // seek after the NULL terminator
    if (fb_seek(ctx->fb, ctx->fb->off + 2) != 0)
        goto end;

    enlarge_tmp;
    tmp[tmp_size] = 0;
    r             = BHEngineValue_WSTRING_new(tmp, tmp_size);

end:
    bhex_free(tmp);
    return r;

#undef enlarge_tmp
}

static BHEngineValue* char_process(InterpreterContext* ctx)
{
    const u8_t* buf = fb_read(ctx->fb, 1);
    if (buf == NULL)
        return NULL;
    if (fb_seek(ctx->fb, ctx->fb->off + 1) != 0)
        return NULL;
    return BHEngineValue_CHAR_new(*buf);
}

static BHEngineValue* wchar_process(InterpreterContext* ctx)
{
    const u8_t* buf = fb_read(ctx->fb, 2);
    if (buf == NULL)
        return NULL;
    if (fb_seek(ctx->fb, ctx->fb->off + 2) != 0)
        return NULL;
    if (ctx->endianess == TE_BIG_ENDIAN)
        return BHEngineValue_WCHAR_new(((u16_t)buf[0] << 8) | (u16_t)buf[1]);
    return BHEngineValue_WCHAR_new(((u16_t)buf[1] << 8) | (u16_t)buf[0]);
}

static BHEngineValue* uint_process(InterpreterContext* e, const u8_t* buf,
                                   u32_t size)
{
    u64_t v = 0;
    for (u32_t i = 0; i < size; ++i) {
        v |= (u64_t)buf[i] << ((e->endianess == TE_BIG_ENDIAN)
                                   ? ((size - i - 1) * 8)
                                   : (i * 8));
    }
    return BHEngineValue_UNUM_new(v, size);
}

static BHEngineValue* int_process(InterpreterContext* e, const u8_t* buf,
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
    return BHEngineValue_SNUM_new(sv, size);
}

#define GEN_INT_PROCESS(name, size, signed)                                    \
    static BHEngineValue* name##_process(InterpreterContext* ctx)              \
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

static BHEngineBuiltinType builtin_types[] = {
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

const BHEngineBuiltinType* get_builtin_type(const char* type)
{
    static map* builtin_types_map = NULL;
    if (builtin_types_map == NULL) {
        builtin_types_map = map_create();
        for (u64_t i = 0;
             i < sizeof(builtin_types) / sizeof(BHEngineBuiltinType); ++i)
            map_set(builtin_types_map, builtin_types[i].name,
                    &builtin_types[i]);
    }
    return map_get_or_null(builtin_types_map, type);
}

/*
    Builtin Functions
*/

int check_builtin_arity(InterpreterContext* ctx, const BHEngineBuiltinFunc* f,
                        DList* params)
{
    u64_t n = params ? params->size : 0;
    if ((int)n >= f->min_params &&
        (f->max_params == BUILTIN_VARIADIC || (int)n <= f->max_params))
        return 0;

    const char* plural = f->min_params == 1 ? "" : "s";
    if (f->max_params == BUILTIN_VARIADIC)
        bhengine_raise_exception(
            ctx, "%s: expected at least %d parameter%s, got %llu", f->name,
            f->min_params, plural, n);
    else if (f->min_params == f->max_params)
        bhengine_raise_exception(ctx, "%s: expected %d parameter%s, got %llu",
                                 f->name, f->min_params, plural, n);
    else
        bhengine_raise_exception(
            ctx, "%s: expected between %d and %d parameters, got %llu", f->name,
            f->min_params, f->max_params, n);
    return 1;
}
/*
    Parameter helpers

    The arity is checked by the interpreter before the builtin runs (see
    check_builtin_arity), so the helpers below only have to deal with the
    type of each parameter.
*/

static int param_as_u64(InterpreterContext* ctx, const char* fname,
                        DList* params, u64_t i, u64_t* o)
{
    if (BHEngineValue_as_u64(ctx, params->data[i], o) != 0) {
        bhengine_raise_exception(ctx, "%s: parameter %llu is not a number",
                                 fname, i + 1);
        return 1;
    }
    return 0;
}

static int param_as_s64(InterpreterContext* ctx, const char* fname,
                        DList* params, u64_t i, s64_t* o)
{
    if (BHEngineValue_as_s64(ctx, params->data[i], o) != 0) {
        bhengine_raise_exception(ctx, "%s: parameter %llu is not a number",
                                 fname, i + 1);
        return 1;
    }
    return 0;
}

// The raw bytes of a string parameter, NUL bytes included. Anything that
// slices or searches a value coming from peek()/read() has to use this:
// param_as_string() stops at the first NUL, which binary data is full of.
static int param_as_bytes(InterpreterContext* ctx, const char* fname,
                          DList* params, u64_t i, const u8_t** o, u64_t* o_size)
{
    BHEngineValue* v = params->data[i];
    if (v->t != TENGINE_STRING) {
        bhengine_raise_exception(ctx, "%s: parameter %llu is not a string",
                                 fname, i + 1);
        return 1;
    }
    *o      = v->str;
    *o_size = v->str_size;
    return 0;
}

static int param_as_string(InterpreterContext* ctx, const char* fname,
                           DList* params, u64_t i, const char** o)
{
    if (BHEngineValue_as_string(ctx, params->data[i], o) != 0) {
        bhengine_raise_exception(ctx, "%s: parameter %llu is not a string",
                                 fname, i + 1);
        return 1;
    }
    return 0;
}

/*
    Casts
*/

#define GEN_INT_CAST(name, sz, signed)                                         \
    static BHEngineValue* builtin_##name(InterpreterContext* ctx,              \
                                         DList*              params)           \
    {                                                                          \
        if (signed) {                                                          \
            s64_t s;                                                           \
            if (param_as_s64(ctx, #name, params, 0, &s) != 0)                  \
                return NULL;                                                   \
            return BHEngineValue_SNUM_new(s, sz);                              \
        }                                                                      \
        u64_t u;                                                               \
        if (param_as_u64(ctx, #name, params, 0, &u) != 0)                      \
            return NULL;                                                       \
        return BHEngineValue_UNUM_new(u, sz);                                  \
    }

GEN_INT_CAST(u8, 1, 0)
GEN_INT_CAST(u16, 2, 0)
GEN_INT_CAST(u32, 4, 0)
GEN_INT_CAST(u64, 8, 0)
GEN_INT_CAST(i8, 1, 1)
GEN_INT_CAST(i16, 2, 1)
GEN_INT_CAST(i32, 4, 1)
GEN_INT_CAST(i64, 8, 1)

static BHEngineValue* builtin_wstring(InterpreterContext* ctx, DList* params)
{
    const char* param_str;
    if (param_as_string(ctx, "wstring", params, 0, &param_str) != 0)
        return NULL;

    size_t str_len = strlen(param_str);
    u16_t* tmp     = bhex_calloc(str_len * 2 + 2);
    for (size_t i = 0; i < str_len; ++i) {
        tmp[i] = param_str[i];
    }
    BHEngineValue* res = BHEngineValue_WSTRING_new(tmp, str_len);
    bhex_free(tmp);
    return res;
}

/*
    Cursor
*/

static BHEngineValue* builtin_off(InterpreterContext* ctx, DList* params)
{
    return BHEngineValue_UNUM_new(ctx->fb->off, 8);
}

static BHEngineValue* builtin_size(InterpreterContext* ctx, DList* params)
{
    return BHEngineValue_UNUM_new(ctx->fb->size, 8);
}

static BHEngineValue* builtin_remaining_size(InterpreterContext* ctx,
                                             DList*              params)
{
    return BHEngineValue_UNUM_new(ctx->fb->size - ctx->fb->off, 8);
}

static BHEngineValue* builtin_seek(InterpreterContext* ctx, DList* params)
{
    u64_t param_u64;
    if (param_as_u64(ctx, "seek", params, 0, &param_u64) != 0)
        return NULL;

    if (fb_seek(ctx->fb, param_u64) != 0) {
        bhengine_raise_exception(ctx, "unable to seek to offset '%lld'",
                                 param_u64);
        return NULL;
    }
    return NULL;
}

static BHEngineValue* builtin_fwd(InterpreterContext* ctx, DList* params)
{
    u64_t param_u64;
    if (param_as_u64(ctx, "fwd", params, 0, &param_u64) != 0)
        return NULL;

    // a negative value reaches us as a huge u64: without this check it wraps
    // around and silently seeks *backwards*
    if (param_u64 > UINT64_MAX - ctx->fb->off ||
        fb_seek(ctx->fb, param_u64 + ctx->fb->off) != 0) {
        bhengine_raise_exception(
            ctx, "fwd: unable to go forward by '%llu' bytes", param_u64);
        return NULL;
    }
    return NULL;
}

static BHEngineValue* builtin_bwd(InterpreterContext* ctx, DList* params)
{
    u64_t param_u64;
    if (param_as_u64(ctx, "bwd", params, 0, &param_u64) != 0)
        return NULL;

    if (param_u64 > ctx->fb->off) {
        bhengine_raise_exception(
            ctx, "bwd: '%lld' is greater that current offset", param_u64);
        return NULL;
    }

    if (fb_seek(ctx->fb, ctx->fb->off - param_u64) != 0) {
        bhengine_raise_exception(
            ctx, "bwd: unable to go backwards by '%llu' bytes", param_u64);
        return NULL;
    }
    return NULL;
}

/*
    Reading without declaring a file variable
*/

// Resolves the optional relative offset shared by the peek functions. It may
// be negative, so that a template can look back at what it has just read.
static int peek_offset(InterpreterContext* ctx, const char* fname,
                       DList* params, u64_t idx, u64_t* o_off)
{
    u64_t off = ctx->fb->off;
    if (params && params->size > idx) {
        s64_t rel;
        if (param_as_s64(ctx, fname, params, idx, &rel) != 0)
            return 1;
        if ((rel < 0 && (u64_t)(-rel) > off) ||
            (rel > 0 && (u64_t)rel > ctx->fb->size - off)) {
            bhengine_raise_exception(
                ctx, "%s: offset %lld is outside of the file", fname, rel);
            return 1;
        }
        off = rel < 0 ? off - (u64_t)(-rel) : off + (u64_t)rel;
    }

    *o_off = off;
    return 0;
}

// Reads at most `n` bytes at `off` without moving the current offset. Returns
// fewer bytes (possibly none) when the file ends first.
static BHEngineValue* read_bytes(InterpreterContext* ctx, const char* fname,
                                 u64_t off, u64_t n, int advance)
{
    u64_t remaining = ctx->fb->size - off;
    if (n > remaining)
        n = remaining;
    if (n == 0)
        return BHEngineValue_STRING_new((const u8_t*)"", 0);

    u64_t          orig_off = ctx->fb->off;
    StringBuilder* sb       = strbuilder_new();
    u64_t          done     = 0;
    while (done < n) {
        if (fb_seek(ctx->fb, off + done) != 0)
            goto fail;

        u64_t to_read = n - done;
        if (to_read > fb_block_size)
            to_read = fb_block_size;

        const u8_t* buf = fb_read(ctx->fb, to_read);
        if (buf == NULL)
            goto fail;
        for (u64_t i = 0; i < to_read; ++i)
            strbuilder_append_char(sb, (char)buf[i]);
        done += to_read;
    }

    fb_seek(ctx->fb, advance ? off + n : orig_off);

    char*          str = strbuilder_finalize(sb);
    BHEngineValue* r   = BHEngineValue_STRING_new((const u8_t*)str, n);
    bhex_free(str);
    return r;

fail:
    bhex_free(strbuilder_finalize(sb));
    fb_seek(ctx->fb, orig_off);
    bhengine_raise_exception(ctx, "%s: unable to read %llu bytes", fname, n);
    return NULL;
}

static BHEngineValue* builtin_peek(InterpreterContext* ctx, DList* params)
{
    u64_t n;
    if (param_as_u64(ctx, "peek", params, 0, &n) != 0)
        return NULL;

    u64_t off;
    if (peek_offset(ctx, "peek", params, 1, &off) != 0)
        return NULL;
    return read_bytes(ctx, "peek", off, n, 0);
}

static BHEngineValue* builtin_read(InterpreterContext* ctx, DList* params)
{
    u64_t n;
    if (param_as_u64(ctx, "read", params, 0, &n) != 0)
        return NULL;
    return read_bytes(ctx, "read", ctx->fb->off, n, 1);
}

// The next `size` bytes as a number, honoring the current endianness, without
// consuming them. Returns -1 when there are not enough bytes left, which is
// what makes "peek and dispatch" loops free of bound checks. A u64 whose top
// bit is set cannot be told apart from that sentinel: read it into a file
// variable instead.
static BHEngineValue* peek_num(InterpreterContext* ctx, const char* fname,
                               DList* params, u32_t size)
{
    u64_t off;
    if (peek_offset(ctx, fname, params, 0, &off) != 0)
        return NULL;

    if (off + size > ctx->fb->size)
        return BHEngineValue_SNUM_new(-1, 8);

    u64_t orig_off = ctx->fb->off;
    if (fb_seek(ctx->fb, off) != 0) {
        bhengine_raise_exception(ctx, "%s: unable to seek to %llu", fname, off);
        return NULL;
    }

    const u8_t* buf = fb_read(ctx->fb, size);
    if (buf == NULL) {
        fb_seek(ctx->fb, orig_off);
        bhengine_raise_exception(ctx, "%s: unable to read %u bytes", fname,
                                 size);
        return NULL;
    }

    u64_t v = 0;
    for (u32_t i = 0; i < size; ++i)
        v |= (u64_t)buf[i] << ((ctx->endianess == TE_BIG_ENDIAN)
                                   ? ((size - i - 1) * 8)
                                   : (i * 8));

    fb_seek(ctx->fb, orig_off);
    return BHEngineValue_SNUM_new((s64_t)v, 8);
}

static BHEngineValue* builtin_peek_u8(InterpreterContext* ctx, DList* params)
{
    return peek_num(ctx, "peek_u8", params, 1);
}

static BHEngineValue* builtin_peek_u16(InterpreterContext* ctx, DList* params)
{
    return peek_num(ctx, "peek_u16", params, 2);
}

static BHEngineValue* builtin_peek_u32(InterpreterContext* ctx, DList* params)
{
    return peek_num(ctx, "peek_u32", params, 4);
}

static BHEngineValue* builtin_peek_u64(InterpreterContext* ctx, DList* params)
{
    return peek_num(ctx, "peek_u64", params, 8);
}

/*
    Scanning runs of bytes
*/

static int byte_in_set(u8_t c, const char* set, size_t set_len)
{
    for (size_t i = 0; i < set_len; ++i)
        if ((u8_t)set[i] == c)
            return 1;
    return 0;
}

// Length of the run of bytes at the current offset that are in `set` (when
// `in_set` is true) or not in `set` (when it is false). The offset is moved
// past the run only if `advance` is set.
static BHEngineValue* scan_run(InterpreterContext* ctx, const char* fname,
                               DList* params, int in_set, int advance)
{
    BHEngineValue* set_val = params->data[0];
    if (set_val->t != TENGINE_STRING) {
        bhengine_raise_exception(ctx, "%s: parameter 1 is not a string", fname);
        return NULL;
    }
    if (set_val->str_size == 0) {
        bhengine_raise_exception(ctx, "%s: the byte set is empty", fname);
        return NULL;
    }
    const char* set     = (const char*)set_val->str;
    size_t      set_len = set_val->str_size;

    u64_t orig_off = ctx->fb->off;
    u64_t n        = 0;
    int   done     = 0;
    while (!done && ctx->fb->off < ctx->fb->size) {
        u64_t to_read = ctx->fb->size - ctx->fb->off;
        if (to_read > fb_block_size)
            to_read = fb_block_size;

        const u8_t* buf = fb_read(ctx->fb, to_read);
        if (buf == NULL)
            break;

        u64_t i = 0;
        while (i < to_read && byte_in_set(buf[i], set, set_len) == in_set)
            i += 1;
        n += i;
        done = i != to_read;

        if (fb_seek(ctx->fb, orig_off + n) != 0)
            break;
    }

    if (fb_seek(ctx->fb, advance ? orig_off + n : orig_off) != 0)
        panic("fb_seek failed in an unexpected way");
    return BHEngineValue_UNUM_new(n, 8);
}

static BHEngineValue* builtin_scan_while(InterpreterContext* ctx, DList* params)
{
    return scan_run(ctx, "scan_while", params, 1, 0);
}

static BHEngineValue* builtin_scan_until(InterpreterContext* ctx, DList* params)
{
    return scan_run(ctx, "scan_until", params, 0, 0);
}

static BHEngineValue* builtin_skip_while(InterpreterContext* ctx, DList* params)
{
    return scan_run(ctx, "skip_while", params, 1, 1);
}

static BHEngineValue* builtin_skip_until(InterpreterContext* ctx, DList* params)
{
    return scan_run(ctx, "skip_until", params, 0, 1);
}

/*
    Strings
*/

static BHEngineValue* builtin_to_int(InterpreterContext* ctx, DList* params)
{
    const char* param_str;
    if (param_as_string(ctx, "to_int", params, 0, &param_str) != 0)
        return NULL;

    u64_t base = 10;
    if (params->size > 1 && param_as_u64(ctx, "to_int", params, 1, &base) != 0)
        return NULL;
    if (base != 0 && (base < 2 || base > 36)) {
        bhengine_raise_exception(
            ctx, "to_int: the base must be 0 or between 2 and 36, got %llu",
            base);
        return NULL;
    }

    s64_t oval;
    if (!str_to_int64_base(param_str, (int)base, &oval)) {
        bhengine_raise_exception(ctx, "to_int: invalid string %s in base %llu",
                                 param_str, base);
        return NULL;
    }
    return BHEngineValue_SNUM_new(oval, 8);
}

static BHEngineValue* builtin_strlen(InterpreterContext* ctx, DList* params)
{
    const char* param_str;
    if (param_as_string(ctx, "strlen", params, 0, &param_str) != 0)
        return NULL;

    return BHEngineValue_UNUM_new(strlen(param_str), 8);
}

// Keeps only the printable ASCII characters, wherever they are in the string.
// The name matters: this is a filter, not the "remove the ends" that a strip()
// suggests, which is what trim() below does.
static BHEngineValue* builtin_printable(InterpreterContext* ctx, DList* params)
{
    const u8_t* str;
    u64_t       len;
    if (param_as_bytes(ctx, "printable", params, 0, &str, &len) != 0)
        return NULL;

    StringBuilder* sb = strbuilder_new();
    for (u64_t i = 0; i < len; ++i) {
        if (str[i] > 0x20 && str[i] < 0x7f)
            strbuilder_append_char(sb, (char)str[i]);
    }

    char*          out = strbuilder_finalize(sb);
    BHEngineValue* r = BHEngineValue_STRING_new((const u8_t*)out, strlen(out));
    bhex_free(out);
    return r;
}

static int is_ascii_space(u8_t c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' ||
           c == '\f';
}

static BHEngineValue* builtin_trim(InterpreterContext* ctx, DList* params)
{
    const u8_t* str;
    u64_t       len;
    if (param_as_bytes(ctx, "trim", params, 0, &str, &len) != 0)
        return NULL;

    u64_t begin = 0;
    u64_t end   = len;
    while (begin < end && is_ascii_space(str[begin]))
        begin += 1;
    while (end > begin && is_ascii_space(str[end - 1]))
        end -= 1;

    return BHEngineValue_STRING_new(str + begin, (u32_t)(end - begin));
}

static BHEngineValue* builtin_substr(InterpreterContext* ctx, DList* params)
{
    const u8_t* str;
    u64_t       str_len;
    if (param_as_bytes(ctx, "substr", params, 0, &str, &str_len) != 0)
        return NULL;

    u64_t begin;
    if (param_as_u64(ctx, "substr", params, 1, &begin) != 0)
        return NULL;
    if (begin > str_len) {
        bhengine_raise_exception(
            ctx, "substr: start %llu is past the end of the string (%llu)",
            begin, str_len);
        return NULL;
    }

    u64_t len = str_len - begin;
    if (params->size > 2) {
        u64_t requested;
        if (param_as_u64(ctx, "substr", params, 2, &requested) != 0)
            return NULL;
        if (requested < len)
            len = requested;
    }

    return BHEngineValue_STRING_new(str + begin, (u32_t)len);
}

static BHEngineValue* builtin_starts_with(InterpreterContext* ctx,
                                          DList*              params)
{
    const u8_t *str, *prefix;
    u64_t       str_len, prefix_len;
    if (param_as_bytes(ctx, "starts_with", params, 0, &str, &str_len) != 0 ||
        param_as_bytes(ctx, "starts_with", params, 1, &prefix, &prefix_len) !=
            0)
        return NULL;

    if (str_len < prefix_len)
        return BHEngineValue_UNUM_new(0, 1);
    return BHEngineValue_UNUM_new(memcmp(str, prefix, prefix_len) == 0, 1);
}

// Offset of `needle` in `haystack`, or -1
static BHEngineValue* builtin_index_of(InterpreterContext* ctx, DList* params)
{
    const u8_t *haystack, *needle;
    u64_t       haystack_len, needle_len;
    if (param_as_bytes(ctx, "index_of", params, 0, &haystack, &haystack_len) !=
            0 ||
        param_as_bytes(ctx, "index_of", params, 1, &needle, &needle_len) != 0)
        return NULL;

    if (needle_len == 0) {
        bhengine_raise_exception(ctx, "index_of: the string to find is empty");
        return NULL;
    }
    if (needle_len <= haystack_len) {
        for (u64_t i = 0; i + needle_len <= haystack_len; ++i)
            if (memcmp(haystack + i, needle, needle_len) == 0)
                return BHEngineValue_SNUM_new((s64_t)i, 8);
    }
    return BHEngineValue_SNUM_new(-1, 8);
}

static BHEngineValue* builtin_tostring(InterpreterContext* ctx, DList* params)
{
    BHEngineValue* param = params->data[0];

    int hex = ctx->fmt->print_in_hex;
    if (params->size > 1) {
        u64_t base;
        if (param_as_u64(ctx, "tostring", params, 1, &base) != 0)
            return NULL;
        if (base != 10 && base != 16) {
            bhengine_raise_exception(
                ctx, "tostring: the base must be 10 or 16, got %llu", base);
            return NULL;
        }
        hex = base == 16;
    }

    if (param->t == TENGINE_STRING)
        return BHEngineValue_dup(param);

    char*          str = BHEngineValue_tostring(param, hex, 0);
    BHEngineValue* r = BHEngineValue_STRING_new((const u8_t*)str, strlen(str));
    bhex_free(str);
    return r;
}

/*
    Math
*/

static BHEngineValue* min_or_max(InterpreterContext* ctx, const char* fname,
                                 DList* params, int want_max)
{
    s64_t best;
    if (param_as_s64(ctx, fname, params, 0, &best) != 0)
        return NULL;

    for (u64_t i = 1; i < params->size; ++i) {
        s64_t v;
        if (param_as_s64(ctx, fname, params, i, &v) != 0)
            return NULL;
        if (want_max ? (v > best) : (v < best))
            best = v;
    }
    return BHEngineValue_SNUM_new(best, 8);
}

static BHEngineValue* builtin_min(InterpreterContext* ctx, DList* params)
{
    return min_or_max(ctx, "min", params, 0);
}

static BHEngineValue* builtin_max(InterpreterContext* ctx, DList* params)
{
    return min_or_max(ctx, "max", params, 1);
}

static BHEngineValue* builtin_abs(InterpreterContext* ctx, DList* params)
{
    s64_t v;
    if (param_as_s64(ctx, "abs", params, 0, &v) != 0)
        return NULL;
    if (v == INT64_MIN) {
        bhengine_raise_exception(ctx, "abs: value is out of range");
        return NULL;
    }
    return BHEngineValue_SNUM_new(v < 0 ? -v : v, 8);
}

// Rounds `value` up to the next multiple of `alignment`: the padding math that
// every archive/section format needs
static BHEngineValue* builtin_align_up(InterpreterContext* ctx, DList* params)
{
    u64_t value, alignment;
    if (param_as_u64(ctx, "align_up", params, 0, &value) != 0 ||
        param_as_u64(ctx, "align_up", params, 1, &alignment) != 0)
        return NULL;

    if (alignment == 0) {
        bhengine_raise_exception(ctx, "align_up: the alignment cannot be zero");
        return NULL;
    }

    u64_t rem = value % alignment;
    if (rem == 0)
        return BHEngineValue_UNUM_new(value, 8);
    if (value > UINT64_MAX - (alignment - rem)) {
        bhengine_raise_exception(ctx, "align_up: the result does not fit");
        return NULL;
    }
    return BHEngineValue_UNUM_new(value + (alignment - rem), 8);
}

/*
    Output and control flow
*/

static BHEngineValue* builtin_little_endian(InterpreterContext* ctx,
                                            DList*              params)
{
    ctx->endianess = TE_LITTLE_ENDIAN;
    return NULL;
}

static BHEngineValue* builtin_big_endian(InterpreterContext* ctx, DList* params)
{
    ctx->endianess = TE_BIG_ENDIAN;
    return NULL;
}

static BHEngineValue* builtin_nums_in(InterpreterContext* ctx, DList* params)
{
    u64_t base;
    if (param_as_u64(ctx, "nums_in", params, 0, &base) != 0)
        return NULL;
    if (base != 10 && base != 16) {
        bhengine_raise_exception(
            ctx, "nums_in: the base must be 10 or 16, got %llu", base);
        return NULL;
    }

    ctx->fmt->print_in_hex = base == 16;
    return NULL;
}

// max_array_print(n): print at most n elements of an array, 0 meaning "all of
// them". It lets a template describe a big table (a symbol table, a sample
// table, ...) without flooding the output with one entry per element
static BHEngineValue* builtin_max_array_print(InterpreterContext* ctx,
                                              DList*              params)
{
    u64_t n;
    if (param_as_u64(ctx, "max_array_print", params, 0, &n) != 0)
        return NULL;

    ctx->fmt->max_array_print = n;
    return NULL;
}

static BHEngineValue* builtin_disable_print(InterpreterContext* ctx,
                                            DList*              params)
{
    ctx->fmt->quiet_mode = 1;
    return NULL;
}

static BHEngineValue* builtin_enable_print(InterpreterContext* ctx,
                                           DList*              params)
{
    ctx->fmt->quiet_mode = 0;
    return NULL;
}

static char* join_params(DList* params, u64_t from)
{
    StringBuilder* sb = strbuilder_new();
    for (u64_t i = from; i < params->size; ++i) {
        BHEngineValue* p = params->data[i];
        if (i > from)
            strbuilder_append_char(sb, ' ');
        if (p->t == TENGINE_STRING) {
            strbuilder_appendf(sb, "%.*s", p->str_size, p->str);
        } else {
            char* p_str = BHEngineValue_tostring(p, 0, 0);
            strbuilder_appendf(sb, "%s", p_str);
            bhex_free(p_str);
        }
    }
    return strbuilder_finalize(sb);
}

static BHEngineValue* builtin_print(InterpreterContext* ctx, DList* params)
{
    char* str = join_params(params, 0);

    fmt_start_print(ctx->fmt);
    fmt_print(ctx->fmt, str);
    fmt_print(ctx->fmt, "\n");
    fmt_end_print(ctx->fmt);
    bhex_free(str);
    return NULL;
}

static BHEngineValue* builtin_warning(InterpreterContext* ctx, DList* params)
{
    char* str = join_params(params, 0);
    warning("%s", str);
    bhex_free(str);
    return NULL;
}

static BHEngineValue* builtin_error(InterpreterContext* ctx, DList* params)
{
    char* str = join_params(params, 0);
    bhengine_raise_exception(ctx, "%s", str);
    bhex_free(str);
    return NULL;
}

// assert(condition, message...): the template equivalent of the
// "if (!ok) { error(...) }" pair that every format check needs
static BHEngineValue* builtin_assert(InterpreterContext* ctx, DList* params)
{
    u64_t cond;
    if (param_as_u64(ctx, "assert", params, 0, &cond) != 0)
        return NULL;
    if (cond != 0)
        return NULL;

    if (params->size == 1) {
        bhengine_raise_exception(ctx, "assertion failed");
        return NULL;
    }

    char* str = join_params(params, 1);
    bhengine_raise_exception(ctx, "assertion failed: %s", str);
    bhex_free(str);
    return NULL;
}

static BHEngineValue* builtin_exit(InterpreterContext* ctx, DList* params)
{
    bhengine_raise_exit_request(ctx);
    return NULL;
}

/*
    Searching
*/

// Streaming Knuth-Morris-Pratt: the matcher state survives across block
// boundaries, and a partial match that fails backs off through the failure
// table instead of restarting from scratch. The naive "reset to zero" it
// replaces used to miss any needle whose prefix repeats inside itself
// (find("aab") in "aaab" reported no match).
static size_t* kmp_failure_table(const u8_t* needle, size_t len)
{
    size_t* lps = bhex_calloc(len * sizeof(size_t));
    size_t  k   = 0;
    for (size_t i = 1; i < len; ++i) {
        while (k > 0 && needle[i] != needle[k])
            k = lps[k - 1];
        if (needle[i] == needle[k])
            k += 1;
        lps[i] = k;
    }
    return lps;
}

// Scans [begin, end) forward. Returns 1 and the offset of the first match, 0
// if there is none, -1 if the file cannot be read.
static int search_forward(InterpreterContext* ctx, const u8_t* needle,
                          size_t needle_len, u64_t begin, u64_t end,
                          u64_t* o_off)
{
    if (needle_len > end - begin)
        return 0;

    size_t* lps      = kmp_failure_table(needle, needle_len);
    size_t  matched  = 0;
    u64_t   curr_off = begin;
    int     result   = 0;

    while (curr_off < end) {
        if (fb_seek(ctx->fb, curr_off) != 0) {
            result = -1;
            break;
        }

        u64_t to_read = end - curr_off;
        if (to_read > fb_block_size)
            to_read = fb_block_size;

        const u8_t* data = fb_read(ctx->fb, to_read);
        if (data == NULL) {
            result = -1;
            break;
        }

        for (u64_t i = 0; i < to_read; ++i) {
            while (matched > 0 && data[i] != needle[matched])
                matched = lps[matched - 1];
            if (data[i] == needle[matched])
                matched += 1;
            if (matched == needle_len) {
                *o_off = curr_off + i + 1 - needle_len;
                result = 1;
                goto end_search;
            }
        }
        curr_off += to_read;
    }

end_search:
    bhex_free(lps);
    return result;
}

// Scans [0, end) backward, i.e. finds the last match that ends at or before
// `end`. Implemented as a forward KMP over the reversed needle fed with the
// bytes in decreasing order, so it stops as soon as it finds a match instead
// of scanning the whole prefix of the file.
static int search_backward(InterpreterContext* ctx, const u8_t* needle,
                           size_t needle_len, u64_t end, u64_t* o_off)
{
    if (needle_len > end)
        return 0;

    u8_t* reversed = bhex_malloc(needle_len);
    for (size_t i = 0; i < needle_len; ++i)
        reversed[i] = needle[needle_len - 1 - i];

    size_t* lps      = kmp_failure_table(reversed, needle_len);
    size_t  matched  = 0;
    u64_t   curr_end = end;
    int     result   = 0;

    while (curr_end > 0) {
        u64_t to_read = curr_end < fb_block_size ? curr_end : fb_block_size;
        u64_t block   = curr_end - to_read;

        if (fb_seek(ctx->fb, block) != 0) {
            result = -1;
            break;
        }
        const u8_t* data = fb_read(ctx->fb, to_read);
        if (data == NULL) {
            result = -1;
            break;
        }

        for (u64_t i = to_read; i > 0; --i) {
            u8_t c = data[i - 1];
            while (matched > 0 && c != reversed[matched])
                matched = lps[matched - 1];
            if (c == reversed[matched])
                matched += 1;
            if (matched == needle_len) {
                // the last byte consumed is the first byte of the match
                *o_off = block + i - 1;
                result = 1;
                goto end_search;
            }
        }
        curr_end = block;
    }

end_search:
    bhex_free(lps);
    bhex_free(reversed);
    return result;
}

// The bytes of the needle passed to find()/find_next(). The literal was
// already unescaped by the lexer, so they are used as they are: decoding them
// a second time used to reject any needle holding a backslash, and to turn a
// needle with a NUL byte into an "empty string" error.
static int needle_from_param(InterpreterContext* ctx, const char* fname,
                             DList* params, const u8_t** o_needle,
                             size_t* o_len)
{
    BHEngineValue* what = params->data[0];
    if (what->t != TENGINE_STRING) {
        bhengine_raise_exception(ctx, "%s: parameter 1 is not a string", fname);
        return 1;
    }
    if (what->str_size == 0) {
        bhengine_raise_exception(ctx, "%s: the string to find is empty", fname);
        return 1;
    }

    *o_needle = what->str;
    *o_len    = what->str_size;
    return 0;
}

static int find_direction(InterpreterContext* ctx, const char* fname,
                          DList* params, int* o_backward)
{
    *o_backward = 0;
    if (params->size < 2)
        return 0;

    u64_t backward;
    if (param_as_u64(ctx, fname, params, 1, &backward) != 0)
        return 1;
    *o_backward = backward != 0;
    return 0;
}

// Searches from the current offset and, on a match, moves there and returns 1.
// On failure the offset is left untouched and 0 is returned.
static BHEngineValue* builtin_find(InterpreterContext* ctx, DList* params)
{
    const u8_t* needle     = NULL;
    size_t      needle_len = 0;
    if (needle_from_param(ctx, "find", params, &needle, &needle_len) != 0)
        return NULL;

    int backward;
    if (find_direction(ctx, "find", params, &backward) != 0)
        return NULL;

    u64_t orig_off = ctx->fb->off;
    u64_t match_off;
    int   r = backward
                  ? search_backward(ctx, needle, needle_len, orig_off, &match_off)
                  : search_forward(ctx, needle, needle_len, orig_off,
                                   ctx->fb->size, &match_off);

    if (r < 0) {
        fb_seek(ctx->fb, orig_off);
        bhengine_raise_exception(ctx, "find: unable to read the file");
        return NULL;
    }
    if (fb_seek(ctx->fb, r == 1 ? match_off : orig_off) != 0)
        panic("fb_seek failed in an unexpected way");
    return BHEngineValue_UNUM_new(r == 1, 1);
}

// Same search as find(), but returns the offset (or -1) and never moves the
// current offset
static BHEngineValue* builtin_find_next(InterpreterContext* ctx, DList* params)
{
    const u8_t* needle     = NULL;
    size_t      needle_len = 0;
    if (needle_from_param(ctx, "find_next", params, &needle, &needle_len) != 0)
        return NULL;

    int backward;
    if (find_direction(ctx, "find_next", params, &backward) != 0)
        return NULL;

    u64_t orig_off = ctx->fb->off;
    u64_t match_off;
    int   r = backward
                  ? search_backward(ctx, needle, needle_len, orig_off, &match_off)
                  : search_forward(ctx, needle, needle_len, orig_off,
                                   ctx->fb->size, &match_off);

    if (fb_seek(ctx->fb, orig_off) != 0)
        panic("fb_seek failed in an unexpected way");
    if (r < 0) {
        bhengine_raise_exception(ctx, "find_next: unable to read the file");
        return NULL;
    }
    return BHEngineValue_SNUM_new(r == 1 ? (s64_t)match_off : -1, 8);
}

/*
    Integrity checks: the same engines used by the 'cr', 'cs' and 'hh'
    commands, so that a template can validate what it parses
*/

// Resolves the [size [, off]] optional parameters shared by crc/checksum/hash
// and entropy. `size` 0 (or missing) means "up to the end of the file", `off`
// is relative to the current offset and may be negative, so that a template
// can check the bytes it has just read.
static int checked_region(InterpreterContext* ctx, const char* fname,
                          DList* params, u64_t first, u64_t* o_off,
                          u64_t* o_size)
{
    // entropy() takes no mandatory parameter, so params can be NULL here
    u64_t nparams = params ? params->size : 0;

    u64_t off = ctx->fb->off;
    if (nparams > first + 1) {
        s64_t rel;
        if (param_as_s64(ctx, fname, params, first + 1, &rel) != 0)
            return 1;
        if ((rel < 0 && (u64_t)(-rel) > off) ||
            (rel > 0 && (u64_t)rel > ctx->fb->size - off)) {
            bhengine_raise_exception(
                ctx, "%s: offset %lld is outside of the file", fname, rel);
            return 1;
        }
        off = rel < 0 ? off - (u64_t)(-rel) : off + (u64_t)rel;
    }

    u64_t size = ctx->fb->size - off;
    if (nparams > first) {
        u64_t requested;
        if (param_as_u64(ctx, fname, params, first, &requested) != 0)
            return 1;
        if (requested != 0) {
            if (requested > size) {
                bhengine_raise_exception(
                    ctx, "%s: %llu bytes requested, but only %llu are left",
                    fname, requested, size);
                return 1;
            }
            size = requested;
        }
    }

    *o_off  = off;
    *o_size = size;
    return 0;
}

// Feeds [off, off + size) to `cb` one block at a time, so that a whole-file
// CRC does not need a whole-file buffer. Restores the current offset.
static int stream_region(InterpreterContext* ctx, u64_t off, u64_t size,
                         void (*cb)(void* u, const u8_t* buf, u32_t len),
                         void* u)
{
    u64_t orig_off = ctx->fb->off;
    u64_t done     = 0;
    int   failed   = 0;

    while (done < size) {
        if (fb_seek(ctx->fb, off + done) != 0) {
            failed = 1;
            break;
        }

        u64_t to_read = size - done;
        if (to_read > fb_block_size)
            to_read = fb_block_size;

        const u8_t* data = fb_read(ctx->fb, to_read);
        if (data == NULL) {
            failed = 1;
            break;
        }
        cb(u, data, (u32_t)to_read);
        done += to_read;
    }

    fb_seek(ctx->fb, orig_off);
    return failed;
}

typedef struct crc_stream_t {
    const crc_params_t* params;
    u32_t               crc;
} crc_stream_t;

static void crc_stream_step(void* u, const u8_t* buf, u32_t len)
{
    crc_stream_t* s = u;
    s->crc          = crc_step(s->crc, buf, len, s->params);
}

typedef struct checksum_stream_t {
    const checksum_algo_t* algo;
    checksum_state_t       state;
} checksum_stream_t;

static void checksum_stream_step(void* u, const u8_t* buf, u32_t len)
{
    checksum_stream_t* s = u;
    s->state             = s->algo->step(s->state, buf, len);
}

static BHEngineValue* builtin_crc(InterpreterContext* ctx, DList* params)
{
    const char* name;
    if (param_as_string(ctx, "crc", params, 0, &name) != 0)
        return NULL;

    const crc_params_t* crc_params = get_crc_by_name(name);
    if (crc_params == NULL) {
        bhengine_raise_exception(ctx, "crc: no such CRC '%s'", name);
        return NULL;
    }

    u64_t off, size;
    if (checked_region(ctx, "crc", params, 1, &off, &size) != 0)
        return NULL;

    crc_stream_t stream = {crc_params, crc_initialize(crc_params)};
    if (stream_region(ctx, off, size, crc_stream_step, &stream) != 0) {
        bhengine_raise_exception(ctx, "crc: unable to read the file");
        return NULL;
    }
    return BHEngineValue_UNUM_new(crc_finalize(stream.crc, crc_params), 4);
}

static BHEngineValue* builtin_checksum(InterpreterContext* ctx, DList* params)
{
    const char* name;
    if (param_as_string(ctx, "checksum", params, 0, &name) != 0)
        return NULL;

    const checksum_algo_t* algo = get_checksum_by_name(name);
    if (algo == NULL) {
        bhengine_raise_exception(ctx, "checksum: no such checksum '%s'", name);
        return NULL;
    }

    u64_t off, size;
    if (checked_region(ctx, "checksum", params, 1, &off, &size) != 0)
        return NULL;

    checksum_stream_t stream = {algo, algo->init()};
    if (stream_region(ctx, off, size, checksum_stream_step, &stream) != 0) {
        bhengine_raise_exception(ctx, "checksum: unable to read the file");
        return NULL;
    }
    return BHEngineValue_UNUM_new(algo->finalize(stream.state), 4);
}

// Returns the digest as a lowercase hex string
static BHEngineValue* builtin_hash(InterpreterContext* ctx, DList* params)
{
    const char* name;
    if (param_as_string(ctx, "hash", params, 0, &name) != 0)
        return NULL;

    const hash_handler_t* handler = get_hash_by_name(name);
    if (handler == NULL) {
        bhengine_raise_exception(ctx, "hash: no such hash '%s'", name);
        return NULL;
    }

    u64_t off, size;
    if (checked_region(ctx, "hash", params, 1, &off, &size) != 0)
        return NULL;

    char* digest = NULL;
    handler->handler(ctx->fb, off, size, &digest);
    if (digest == NULL) {
        bhengine_raise_exception(ctx, "hash: unable to hash the file");
        return NULL;
    }

    BHEngineValue* r =
        BHEngineValue_STRING_new((const u8_t*)digest, strlen(digest));
    bhex_free(digest);
    return r;
}

// Shannon entropy of a region, in millesimal units (0 - 8000), so that it can
// be compared without floating point support in the language
static BHEngineValue* builtin_entropy(InterpreterContext* ctx, DList* params)
{
    u64_t off, size;
    if (checked_region(ctx, "entropy", params, 0, &off, &size) != 0)
        return NULL;

    float e = calculate_entropy(ctx->fb, off, size);
    return BHEngineValue_UNUM_new((u64_t)(e * 1000.0f + 0.5f), 4);
}

static BHEngineBuiltinFunc builtin_funcs[] = {
    // casts
    {"u8", 1, 1, builtin_u8},
    {"u16", 1, 1, builtin_u16},
    {"u32", 1, 1, builtin_u32},
    {"u64", 1, 1, builtin_u64},
    {"i8", 1, 1, builtin_i8},
    {"i16", 1, 1, builtin_i16},
    {"i32", 1, 1, builtin_i32},
    {"i64", 1, 1, builtin_i64},
    {"wstring", 1, 1, builtin_wstring},
    // cursor
    {"off", 0, 0, builtin_off},
    {"size", 0, 0, builtin_size},
    {"remaining_size", 0, 0, builtin_remaining_size},
    {"seek", 1, 1, builtin_seek},
    {"fwd", 1, 1, builtin_fwd},
    {"bwd", 1, 1, builtin_bwd},
    // reading without declaring a file variable
    {"peek", 1, 2, builtin_peek},
    {"peek_u8", 0, 1, builtin_peek_u8},
    {"peek_u16", 0, 1, builtin_peek_u16},
    {"peek_u32", 0, 1, builtin_peek_u32},
    {"peek_u64", 0, 1, builtin_peek_u64},
    {"read", 1, 1, builtin_read},
    // scanning runs of bytes
    {"scan_while", 1, 1, builtin_scan_while},
    {"scan_until", 1, 1, builtin_scan_until},
    {"skip_while", 1, 1, builtin_skip_while},
    {"skip_until", 1, 1, builtin_skip_until},
    // searching
    {"find", 1, 2, builtin_find},
    {"find_next", 1, 2, builtin_find_next},
    // strings
    {"to_int", 1, 2, builtin_to_int},
    {"strlen", 1, 1, builtin_strlen},
    {"printable", 1, 1, builtin_printable},
    {"trim", 1, 1, builtin_trim},
    {"substr", 2, 3, builtin_substr},
    {"starts_with", 2, 2, builtin_starts_with},
    {"index_of", 2, 2, builtin_index_of},
    {"tostring", 1, 2, builtin_tostring},
    // math
    {"min", 2, BUILTIN_VARIADIC, builtin_min},
    {"max", 2, BUILTIN_VARIADIC, builtin_max},
    {"abs", 1, 1, builtin_abs},
    {"align_up", 2, 2, builtin_align_up},
    // output and control flow
    {"little_endian", 0, 0, builtin_little_endian},
    {"big_endian", 0, 0, builtin_big_endian},
    {"nums_in", 1, 1, builtin_nums_in},
    {"max_array_print", 1, 1, builtin_max_array_print},
    {"disable_print", 0, 0, builtin_disable_print},
    {"enable_print", 0, 0, builtin_enable_print},
    {"print", 1, BUILTIN_VARIADIC, builtin_print},
    {"warning", 1, BUILTIN_VARIADIC, builtin_warning},
    {"error", 1, BUILTIN_VARIADIC, builtin_error},
    {"assert", 1, BUILTIN_VARIADIC, builtin_assert},
    {"exit", 0, 0, builtin_exit},
    // integrity checks
    {"crc", 1, 3, builtin_crc},
    {"checksum", 1, 3, builtin_checksum},
    {"hash", 1, 3, builtin_hash},
    {"entropy", 0, 2, builtin_entropy},
};

const BHEngineBuiltinFunc* get_builtin_func(const char* name)
{
    static map* builtin_funcs_map = NULL;
    if (builtin_funcs_map == NULL) {
        builtin_funcs_map = map_create();
        for (u64_t i = 0;
             i < sizeof(builtin_funcs) / sizeof(BHEngineBuiltinFunc); ++i)
            map_set(builtin_funcs_map, builtin_funcs[i].name,
                    &builtin_funcs[i]);
    }
    return map_get_or_null(builtin_funcs_map, name);
}
