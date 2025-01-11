#include "builtin.h"
#include "tengine.h"
#include "value.h"

#include <string.h>
#include <alloc.h>
#include <log.h>

static TEngineValue* string_process(TEngine* e, FileBuffer* fb)
{
    u64_t tmp_capacity = 8;
    u64_t tmp_size     = 0;
    char* tmp          = bhex_calloc(tmp_capacity);

#define enlarge_tmp                                                            \
    if (tmp_size == tmp_capacity) {                                            \
        tmp_capacity *= 2;                                                     \
        tmp = bhex_realloc(tmp, tmp_capacity);                                 \
    }

    const uint8_t* buf = fb_read(fb, 1);
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
    r             = TEngineValue_STRING_new(tmp);

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
            sv = (s64_t)(s64_t)v;
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

static TEngineBuiltinType embedded_types[] = {
    {"uint64_t", uint64_t_process}, {"uint32_t", uint32_t_process},
    {"uint16_t", uint16_t_process}, {"uint8_t", uint8_t_process},
    {"int64_t", int64_t_process},   {"int32_t", int32_t_process},
    {"int16_t", int16_t_process},   {"int8_t", int8_t_process},
    {"char", char_process},         {"string_t", string_process},
};

const TEngineBuiltinType* get_builtin_type(const char* type)
{
    for (u64_t i = 0; i < sizeof(embedded_types) / sizeof(TEngineBuiltinType);
         ++i) {
        TEngineBuiltinType* t = &embedded_types[i];
        if (strcmp(t->name, type) == 0) {
            return t;
        }
    }
    return NULL;
}
