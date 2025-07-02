#include "value.h"
#include "defs.h"
#include "dlist.h"
#include "util/byte_to_str.h"

#include <filebuffer.h>
#include <strbuilder.h>
#include <util/str.h>
#include <string.h>
#include <alloc.h>
#include <log.h>

#define max(x, y) ((x) > (y) ? (x) : (y))

extern int yymax_ident_len;

static const char* type_to_string(TEngineValueType t)
{
    switch (t) {
        case TENGINE_UNUM:
            return "unum";
        case TENGINE_SNUM:
            return "snum";
        case TENGINE_CHAR:
            return "char";
        case TENGINE_ENUM_VALUE:
            return "enum_value";
        case TENGINE_STRING:
            return "string";
        case TENGINE_OBJ:
            return "custom_type";
        default:
            panic("invalid type in TEngineValue_get_num");
    }
    return NULL;
}

TEngineValue* TEngineValue_SNUM_new(s64_t v, u32_t size)
{
    if (size == 0)
        panic("TEngineValue_SNUM_new() invalid size");
    if (size < 8) {
        u64_t mask = (2ull << ((u64_t)size * 8 - 1ull)) - 1ull;
        u64_t msb  = (1ull << ((u64_t)size * 8 - 1ull));
        u64_t vu   = (u64_t)v & mask;
        if (vu & msb)
            vu |= ~mask;
        v = (s64_t)vu;
    }

    TEngineValue* r = bhex_calloc(sizeof(TEngineValue));
    r->t            = TENGINE_SNUM;
    r->snum         = v;
    r->snum_size    = size;
    return r;
}

TEngineValue* TEngineValue_UNUM_new(u64_t v, u32_t size)
{
    if (size == 0)
        panic("TEngineValue_UNUM_new() invalid size");
    u64_t mask = (2ull << ((u64_t)size * 8 - 1ull)) - 1ull;

    TEngineValue* r = bhex_calloc(sizeof(TEngineValue));
    r->t            = TENGINE_UNUM;
    r->unum         = v & mask;
    r->unum_size    = size;
    return r;
}

TEngineValue* TEngineValue_CHAR_new(char c)
{
    TEngineValue* r = bhex_calloc(sizeof(TEngineValue));
    r->t            = TENGINE_CHAR;
    r->c            = c;
    return r;
}

TEngineValue* TEngineValue_STRING_new(const u8_t* str, u32_t size)
{
    TEngineValue* r = bhex_calloc(sizeof(TEngineValue));
    r->t            = TENGINE_STRING;
    r->str          = bhex_calloc(size + 1);
    r->str_size     = size;
    memcpy(r->str, str, size);
    return r;
}

TEngineValue* TEngineValue_OBJ_new(map* subvals)
{
    TEngineValue* r = bhex_calloc(sizeof(TEngineValue));
    r->t            = TENGINE_OBJ;
    r->subvals      = subvals;
    return r;
}

TEngineValue* TEngineValue_ENUM_VALUE_new(const char* ename, u64_t econst)
{
    TEngineValue* r = bhex_calloc(sizeof(TEngineValue));
    r->t            = TENGINE_ENUM_VALUE;
    r->enum_value   = bhex_strdup(ename);
    r->enum_const   = econst;
    return r;
}

TEngineValue* TEngineValue_BUF_new(u64_t off, u64_t size)
{
    TEngineValue* r = bhex_calloc(sizeof(TEngineValue));
    r->t            = TENGINE_BUF;
    r->buf_off      = off;
    r->buf_size     = size;
    return r;
}

TEngineValue* TEngineValue_ARRAY_new()
{
    TEngineValue* r = bhex_calloc(sizeof(TEngineValue));
    r->t            = TENGINE_ARRAY;
    r->array_data   = DList_new();
    return r;
}

void TEngineValue_ARRAY_append(TEngineValue* arr, TEngineValue* v)
{
    if (arr->t != TENGINE_ARRAY)
        panic("TEngineValue_ARRAY_append: not a TENGINE_ARRAY");

    DList_add(arr->array_data, v);
}

TEngineValue* TEngineValue_array_sub(FileBuffer* fb, const TEngineValue* e,
                                     const TEngineValue* n)
{
    u64_t n_val;
    if (TEngineValue_as_u64(n, &n_val) != 0)
        return NULL;

    switch (e->t) {
        case TENGINE_ARRAY: {
            if (e->array_data->size <= n_val) {
                error("out of bound in array (size %llu, index %llu)",
                      e->array_data->size, n_val);
                return NULL;
            }
            return TEngineValue_dup(e->array_data->data[n_val]);
        }
        case TENGINE_BUF: {
            if (e->buf_size <= n_val) {
                error("out of bound in buf (size %llu, index %llu)",
                      e->buf_size, n_val);
                return NULL;
            }
            u64_t orig_s = fb->off;
            if (fb_seek(fb, e->buf_off + n_val) != 0) {
                error("invalid buffer, it spans outside the file");
                return NULL;
            }
            const u8_t* buf = fb_read(fb, 1);
            if (buf == NULL)
                return NULL;
            TEngineValue* v = TEngineValue_UNUM_new(buf[0], 1);
            fb_seek(fb, orig_s);
            return v;
        }
        case TENGINE_STRING: {
            if (e->str_size <= n_val) {
                error("out of bound in string (size %llu, index %llu)",
                      e->str_size, n_val);
                return NULL;
            }
            return TEngineValue_UNUM_new(e->str[n_val], 1);
        }
        default:
            break;
    }

    error("array_sub undefined for type %s", type_to_string(e->t));
    return NULL;
}

#define binop_num(op)                                                          \
    if (lhs == NULL || rhs == NULL)                                            \
        return NULL;                                                           \
    if (lhs->t == TENGINE_UNUM && rhs->t == TENGINE_UNUM) {                    \
        return TEngineValue_UNUM_new(lhs->unum op rhs->unum,                   \
                                     max(lhs->unum_size, rhs->unum_size));     \
    }                                                                          \
    if (lhs->t == TENGINE_SNUM && rhs->t == TENGINE_UNUM) {                    \
        return TEngineValue_SNUM_new(lhs->snum op(s64_t) rhs->unum,            \
                                     max(lhs->snum_size, rhs->unum_size));     \
    }                                                                          \
    if (lhs->t == TENGINE_UNUM && rhs->t == TENGINE_SNUM) {                    \
        return TEngineValue_SNUM_new((s64_t)lhs->unum op rhs->snum,            \
                                     max(lhs->unum_size, rhs->snum_size));     \
    }                                                                          \
    if (lhs->t == TENGINE_SNUM && rhs->t == TENGINE_SNUM) {                    \
        return TEngineValue_SNUM_new(lhs->snum op rhs->snum,                   \
                                     max(lhs->snum_size, rhs->snum_size));     \
    }

TEngineValue* TEngineValue_add(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_num(+);

    error("add undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_sub(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_num(-);

    error("sub undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_mul(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_num(*);

    error("mul undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_div(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_num(/);

    error("div undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_mod(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_num(%);

    error("mod undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_and(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_num(&);

    error("and undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_or(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_num(|);

    error("or undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_xor(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_num(^);

    error("xor undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_shr(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_num(>>);

    error("shr undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_shl(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_num(<<);

    error("shl undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

#define binop_bool(op)                                                         \
    if (lhs == NULL || rhs == NULL)                                            \
        return NULL;                                                           \
    if (lhs->t == TENGINE_UNUM && rhs->t == TENGINE_UNUM) {                    \
        return TEngineValue_UNUM_new((lhs->unum op rhs->unum) ? 1 : 0, 1);     \
    }                                                                          \
    if (lhs->t == TENGINE_SNUM && rhs->t == TENGINE_UNUM) {                    \
        return TEngineValue_UNUM_new(((u64_t)lhs->snum op rhs->unum) ? 1 : 0,  \
                                     1);                                       \
    }                                                                          \
    if (lhs->t == TENGINE_UNUM && rhs->t == TENGINE_SNUM) {                    \
        return TEngineValue_UNUM_new((lhs->unum op(u64_t) rhs->snum) ? 1 : 0,  \
                                     1);                                       \
    }                                                                          \
    if (lhs->t == TENGINE_SNUM && rhs->t == TENGINE_SNUM) {                    \
        return TEngineValue_UNUM_new((lhs->snum op rhs->snum) ? 1 : 0, 1);     \
    }

TEngineValue* TEngineValue_bgt(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_bool(>);

    error("bgt undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_bge(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_bool(>=);

    error("bge undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_blt(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_bool(<);

    error("blt undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_ble(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_bool(<=);

    error("ble undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_beq(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_bool(==);

    if (lhs->t == TENGINE_STRING && rhs->t == TENGINE_STRING) {
        if (lhs->str_size != rhs->str_size ||
            memcmp(lhs->str, rhs->str, lhs->str_size) != 0)
            return TEngineValue_UNUM_new(0, 8);
        return TEngineValue_UNUM_new(1, 8);
    }
    if (lhs->t == TENGINE_CHAR && rhs->t == TENGINE_CHAR) {
        return TEngineValue_UNUM_new((lhs->c == rhs->c) ? 1 : 0, 1);
    }
    if (lhs->t == TENGINE_ENUM_VALUE && rhs->t == TENGINE_ENUM_VALUE) {
        return TEngineValue_UNUM_new(
            (lhs->enum_const == rhs->enum_const) ? 1 : 0, 1);
    }
    if (lhs->t == TENGINE_ENUM_VALUE && rhs->t == TENGINE_SNUM) {
        return TEngineValue_UNUM_new(
            (lhs->enum_const == (u64_t)rhs->snum) ? 1 : 0, 1);
    }
    if (lhs->t == TENGINE_SNUM && rhs->t == TENGINE_ENUM_VALUE) {
        return TEngineValue_UNUM_new(
            ((u64_t)lhs->snum == rhs->enum_const) ? 1 : 0, 1);
    }
    if (lhs->t == TENGINE_ENUM_VALUE && rhs->t == TENGINE_UNUM) {
        return TEngineValue_UNUM_new((lhs->enum_const == rhs->unum) ? 1 : 0, 1);
    }
    if (lhs->t == TENGINE_UNUM && rhs->t == TENGINE_ENUM_VALUE) {
        return TEngineValue_UNUM_new((lhs->unum == rhs->enum_const) ? 1 : 0, 1);
    }

    error("beq undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_bnot(const TEngineValue* child)
{
    if (child->t == TENGINE_SNUM) {
        return TEngineValue_UNUM_new(child->snum == 0 ? 1 : 0, 1);
    }
    if (child->t == TENGINE_UNUM) {
        return TEngineValue_UNUM_new(child->unum == 0 ? 1 : 0, 1);
    }

    error("beq undefined for type %s", type_to_string(child->t));
    return NULL;
}

TEngineValue* TEngineValue_band(const TEngineValue* lhs,
                                const TEngineValue* rhs)
{
    binop_bool(&&);

    error("band undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_bor(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_bool(||);

    error("bor undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

int TEngineValue_as_u64(const TEngineValue* v, u64_t* o)
{
    switch (v->t) {
        case TENGINE_UNUM:
            if ((v->unum >> 63) != 0) {
                error("TEngineValue_as_u64: the number '%llu' is too big to "
                      "fit a u64_t",
                      v->unum);
                return 1;
            }
            *o = v->unum;
            return 0;
        case TENGINE_SNUM:
            *o = (u64_t)v->snum;
            return 0;
        case TENGINE_CHAR:
            *o = (u64_t)v->c;
            return 0;
        case TENGINE_ENUM_VALUE:
            *o = (u64_t)v->enum_const;
            return 0;
        case TENGINE_STRING:
        case TENGINE_OBJ:
            error("TEngineValue_as_u64: %s not a numeric type",
                  type_to_string(v->t));
            return 1;
        default:
            panic("invalid type in TEngineValue_as_u64");
    }
    return 1;
}

int TEngineValue_as_string(const TEngineValue* v, const char** o)
{
    if (v->t == TENGINE_STRING) {
        *o = (char*)v->str;
        return 0;
    }

    error("TEngineValue_as_string: %s is not a string type",
          type_to_string(v->t));
    return 1;
}

int TEngineValue_as_s64(const TEngineValue* v, s64_t* o)
{
    switch (v->t) {
        case TENGINE_UNUM:
            if ((v->unum >> 63) != 0) {
                error("TEngineValue_as_s64: the number '%llu' is too big to "
                      "fit a s64_t",
                      v->unum);
                return 1;
            }
            *o = (s64_t)v->unum;
            return 0;
        case TENGINE_SNUM:
            *o = v->snum;
            return 0;
        case TENGINE_CHAR:
            *o = (s64_t)v->c;
            return 0;
        case TENGINE_ENUM_VALUE:
            *o = (s64_t)v->enum_const;
            return 0;
        case TENGINE_STRING:
        case TENGINE_OBJ:
            error("TEngineValue_as_s64: %s not a numeric type",
                  type_to_string(v->t));
            return 1;
        default:
            panic("invalid type in TEngineValue_as_s64");
    }
    return 1;
}

void TEngineValue_free(TEngineValue* v)
{
    if (!v)
        return;

    switch (v->t) {
        case TENGINE_UNUM:
        case TENGINE_SNUM:
        case TENGINE_CHAR:
        case TENGINE_BUF:
            break;
        case TENGINE_STRING:
            bhex_free(v->str);
            break;
        case TENGINE_ENUM_VALUE:
            bhex_free(v->enum_value);
            break;
        case TENGINE_OBJ:
            map_destroy(v->subvals);
            break;
        case TENGINE_ARRAY:
            DList_destroy(v->array_data, (void (*)(void*))TEngineValue_free);
            break;
        default:
            panic("invalid type in TEngineValue_free");
    }
    bhex_free(v);
}

TEngineValue* TEngineValue_dup(TEngineValue* v)
{
    if (!v)
        panic("TEngineValue_dup: NULL input");

    switch (v->t) {
        case TENGINE_UNUM:
            return TEngineValue_UNUM_new(v->unum, v->unum_size);
        case TENGINE_SNUM:
            return TEngineValue_SNUM_new(v->snum, v->snum_size);
        case TENGINE_CHAR:
            return TEngineValue_CHAR_new(v->c);
        case TENGINE_STRING:
            return TEngineValue_STRING_new(v->str, v->str_size);
        case TENGINE_ENUM_VALUE:
            return TEngineValue_ENUM_VALUE_new(v->enum_value, v->enum_const);
        case TENGINE_OBJ: {
            map* subvals = map_create();
            map_set_dispose(subvals, (void (*)(void*))TEngineValue_free);
            for (const char* key = map_first(v->subvals); key != NULL;
                 key             = map_next(v->subvals, key)) {
                TEngineValue* n = TEngineValue_dup(map_get(v->subvals, key));
                if (n == NULL)
                    panic("TEngineValue_dup: invalid subvar");
                map_set(subvals, key, n);
            }
            return TEngineValue_OBJ_new(subvals);
        }
        case TENGINE_BUF:
            return TEngineValue_BUF_new(v->buf_off, v->buf_size);
        case TENGINE_ARRAY: {
            TEngineValue* newarr = TEngineValue_ARRAY_new();
            for (u64_t i = 0; i < v->array_data->size; ++i) {
                TEngineValue* dupel = TEngineValue_dup(v->array_data->data[i]);
                if (dupel == NULL)
                    panic("TEngineValue_dup: invalida arr value");
                TEngineValue_ARRAY_append(newarr, dupel);
            }
            return newarr;
        }
        default:
            panic("invalid type in TEngineValue_dup");
    }
    return NULL;
}

static char ascii_or_space(char c)
{
    if (c >= 0x20 && c <= 0x7e)
        return c;
    return ' ';
}

void TEngineValue_pp(const TEngineValue* v, int hex)
{
    char* str = TEngineValue_tostring(v, hex);
    printf("%s\n", str);
    bhex_free(str);
}

char* TEngineValue_tostring(const TEngineValue* v, int hex)
{
    StringBuilder* sb = strbuilder_new();

    switch (v->t) {
        case TENGINE_UNUM:
            if (hex)
                strbuilder_appendf(sb, "%0*llx", v->unum_size * 2, v->unum);
            else
                strbuilder_appendf(sb, "%llu", v->unum);
            break;
        case TENGINE_SNUM:
            if (hex)
                strbuilder_appendf(sb, "%0*llx", v->unum_size * 2, v->unum);
            else
                strbuilder_appendf(sb, "%lld", v->snum);
            break;
        case TENGINE_CHAR:
            strbuilder_appendf(sb, "%c", ascii_or_space(v->c));
            break;
        case TENGINE_STRING: {
            strbuilder_append_char(sb, '\'');
            for (u32_t i = 0; i < v->str_size; ++i) {
                if (!v->str[i])
                    break;
                if (is_printable_ascii(v->str[i]))
                    strbuilder_append_char(sb, v->str[i]);
                else
                    strbuilder_appendf(sb, "\\x%02x", v->str[i]);
            }
            strbuilder_append_char(sb, '\'');
            break;
        }
        case TENGINE_ENUM_VALUE: {
            strbuilder_appendf(sb, "%s", v->enum_value);
            break;
        }
        case TENGINE_OBJ: {
            for (const char* key = map_first(v->subvals); key != NULL;
                 key             = map_next(v->subvals, key)) {
                strbuilder_appendf(sb, ".%.*s: ", yymax_ident_len, key);
                TEngineValue* nv     = map_get(v->subvals, key);
                char*         substr = TEngineValue_tostring(nv, hex);
                strbuilder_append(sb, substr);
                strbuilder_append_char(sb, '\n');
                bhex_free(substr);
            }
            char* content = strbuilder_finalize(sb);
            sb            = strbuilder_new();
            strbuilder_append_char(sb, '\n');
            strbuilder_append(sb, str_indent(content, 4));
            break;
        }
        case TENGINE_BUF:
            strbuilder_appendf(sb, "DATA@%llxh->%llxh", v->buf_off,
                               v->buf_size);
            break;
        case TENGINE_ARRAY: {
            strbuilder_append_char(sb, '\n');
            for (u32_t i = 0; i < v->array_data->size; ++i) {
                strbuilder_appendf(sb, "[%u]\n", i);
                char* subel =
                    TEngineValue_tostring(v->array_data->data[i], hex);
                strbuilder_append(sb, str_indent(subel, 4));
            }
            break;
        }
        default:
            panic("invalid type in TEngineValue_tostring");
    }
    return strbuilder_finalize(sb);
}
