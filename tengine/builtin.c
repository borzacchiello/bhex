#include "builtin.h"
#include "defs.h"
#include "tengine.h"
#include "value.h"

#include <util/byte_to_num.h>
#include <string.h>
#include <alloc.h>
#include <log.h>

/*
    Builtin Types
*/

static TEngineValue* string_process(TEngine* e, FileBuffer* fb)
{
    u64_t tmp_capacity = 8;
    u64_t tmp_size     = 0;
    u8_t* tmp          = bhex_calloc(tmp_capacity);

#define enlarge_tmp                                                            \
    if (tmp_size == tmp_capacity) {                                            \
        tmp_capacity *= 2;                                                     \
        tmp = bhex_realloc(tmp, tmp_capacity);                                 \
    }

    const u8_t* buf = fb_read(fb, 1);
    if (buf == NULL)
        return NULL;

    TEngineValue* r = NULL;
    while (*buf) {
        enlarge_tmp;

        tmp[tmp_size++] = (char)*buf;
        if (fb_seek(fb, fb->off + 1) != 0)
            goto end;
        buf = fb_read(fb, 1);
    }

    enlarge_tmp;
    tmp[tmp_size] = '\0';
    r             = TEngineValue_STRING_new(tmp, tmp_size);

end:
    bhex_free(tmp);
    return r;
}

static TEngineValue* char_process(TEngine* e, FileBuffer* fb)
{
    const uint8_t* buf = fb_read(fb, 1);
    if (buf == NULL)
        return NULL;
    if (fb_seek(fb, fb->off + 1) != 0)
        return NULL;
    return TEngineValue_CHAR_new(*buf);
}

static TEngineValue* uint_process(TEngine* e, const u8_t* buf, u32_t size)
{
    u64_t v = 0;
    for (u32_t i = 0; i < size; ++i) {
        v |= (u64_t)buf[i] << ((e->endianess == TE_BIG_ENDIAN)
                                   ? ((size - i - 1) * 8)
                                   : (i * 8));
    }
    return TEngineValue_UNUM_new(v, size);
}

static TEngineValue* int_process(TEngine* e, const u8_t* buf, u32_t size)
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

#define GEN_INT_PRINT(name, size, signed)                                      \
    static TEngineValue* name##_process(TEngine* engine, FileBuffer* fb)       \
    {                                                                          \
        const u8_t* buf = fb_read(fb, size);                                   \
        fb_seek(fb, fb->off + size);                                           \
        if (buf == NULL)                                                       \
            return NULL;                                                       \
        if (!signed)                                                           \
            return uint_process(engine, buf, size);                            \
        return int_process(engine, buf, size);                                 \
    }

GEN_INT_PRINT(uint64_t, 8, 0)
GEN_INT_PRINT(uint32_t, 4, 0)
GEN_INT_PRINT(uint16_t, 2, 0)
GEN_INT_PRINT(uint8_t, 1, 0)
GEN_INT_PRINT(int64_t, 8, 1)
GEN_INT_PRINT(int32_t, 4, 1)
GEN_INT_PRINT(int16_t, 2, 1)
GEN_INT_PRINT(int8_t, 1, 1)

static TEngineBuiltinType builtin_types[] = {
    {"uint64_t", uint64_t_process}, {"uint32_t", uint32_t_process},
    {"uint16_t", uint16_t_process}, {"uint8_t", uint8_t_process},
    {"int64_t", int64_t_process},   {"int32_t", int32_t_process},
    {"int16_t", int16_t_process},   {"int8_t", int8_t_process},
    {"char", char_process},         {"string_t", string_process},
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

static TEngineValue* builtin_curroff(TEngine* e, FileBuffer* fb, DList* params)
{
    if (params && params->size > 0)
        panic("[tengine] builtin_curroff invalid parameters");

    return TEngineValue_UNUM_new(fb->off, 8);
}

static TEngineValue* builtin_size(TEngine* e, FileBuffer* fb, DList* params)
{
    if (params && params->size > 0)
        panic("[tengine] builtin_size invalid parameters");

    return TEngineValue_UNUM_new(fb->size, 8);
}

static TEngineValue* builtin_atoi(TEngine* e, FileBuffer* fb, DList* params)
{
    if (!params || params->size != 1)
        panic("[tengine] builtin_atoi invalid parameters");

    TEngineValue* param = params->data[0];
    const char*   param_str;
    if (TEngineValue_as_string(param, &param_str) != 0) {
        error("[tengine] atoi: expected a string parameter");
        return NULL;
    }

    s64_t oval;
    if (!str_to_int64(param_str, &oval)) {
        error("[tengine] atoi: invalid string %s", param_str);
        return NULL;
    }
    return TEngineValue_SNUM_new(oval, 64);
}

static TEngineValue* builtin_strlen(TEngine* e, FileBuffer* fb, DList* params)
{
    if (!params || params->size != 1)
        panic("[tengine] builtin_strlen invalid parameters");

    TEngineValue* param = params->data[0];
    const char*   param_str;
    if (TEngineValue_as_string(param, &param_str) != 0) {
        error("[tengine] strlen: expected a string parameter");
        return NULL;
    }

    return TEngineValue_UNUM_new(strlen(param_str), 8);
}

static TEngineValue* builtin_endianess_le(TEngine* e, FileBuffer* fb,
                                          DList* params)
{
    if (params && params->size > 0)
        panic("[tengine] builtin_endianess_le invalid parameters");

    e->endianess = TE_LITTLE_ENDIAN;
    return NULL;
}

static TEngineValue* builtin_endianess_be(TEngine* e, FileBuffer* fb,
                                          DList* params)
{
    if (params && params->size > 0)
        panic("[tengine] builtin_endianess_be invalid parameters");

    e->endianess = TE_BIG_ENDIAN;
    return NULL;
}

static TEngineValue* builtin_nums_in_hex(TEngine* e, FileBuffer* fb,
                                         DList* params)
{
    if (params && params->size > 0)
        panic("[tengine] nums_in_hex invalid parameters");

    e->print_in_hex = 1;
    return NULL;
}

static TEngineValue* builtin_nums_in_dec(TEngine* e, FileBuffer* fb,
                                         DList* params)
{
    if (params && params->size > 0)
        panic("[tengine] nums_in_dec invalid parameters");

    e->print_in_hex = 0;
    return NULL;
}

static TEngineValue* builtin_disable_print(TEngine* e, FileBuffer* fb,
                                           DList* params)
{
    if (params && params->size > 0)
        panic("[tengine] disable_print invalid parameters");

    e->quiet_mode = 1;
    return NULL;
}

static TEngineValue* builtin_enable_print(TEngine* e, FileBuffer* fb,
                                          DList* params)
{
    if (params && params->size > 0)
        panic("[tengine] enable_print invalid parameters");

    e->quiet_mode = 0;
    return NULL;
}

static TEngineValue* builtin_seek(TEngine* e, FileBuffer* fb, DList* params)
{
    if (!params || params->size != 1)
        panic("[tengine] builtin_seek invalid parameters");

    TEngineValue* param = params->data[0];
    u64_t         param_u64;
    if (TEngineValue_as_u64(param, &param_u64) != 0) {
        error("[tengine] seek: expected an uint parameter");
        return NULL;
    }

    if (fb_seek(fb, param_u64) != 0) {
        error("[tengine] unable to seek to offset '%lld'", param_u64);
        return NULL;
    }
    return NULL;
}

static TEngineValue* builtin_fwd(TEngine* e, FileBuffer* fb, DList* params)
{
    if (!params || params->size != 1)
        panic("[tengine] builtin_fwd invalid parameters");

    TEngineValue* param = params->data[0];
    u64_t         param_u64;
    if (TEngineValue_as_u64(param, &param_u64) != 0) {
        error("[tengine] fwd: expected an uint parameter");
        return NULL;
    }

    if (fb_seek(fb, param_u64 + fb->off) != 0) {
        error("[tengine] unable to fwd to offset '%lld'", param_u64);
        return NULL;
    }
    return NULL;
}

static TEngineBuiltinFunc builtin_funcs[] = {
    {"curroff", 0, builtin_curroff},
    {"size", 0, builtin_size},
    {"atoi", 1, builtin_atoi},
    {"strlen", 1, builtin_strlen},
    {"endianess_le", 0, builtin_endianess_le},
    {"endianess_be", 0, builtin_endianess_be},
    {"nums_in_hex", 0, builtin_nums_in_hex},
    {"nums_in_dec", 0, builtin_nums_in_dec},
    {"disable_print", 0, builtin_disable_print},
    {"enable_print", 0, builtin_enable_print},
    {"seek", 1, builtin_seek},
    {"fwd", 1, builtin_fwd}};

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
