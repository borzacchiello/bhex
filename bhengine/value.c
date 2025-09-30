#include "value.h"
#include "defs.h"
#include "dlist.h"
#include "interpreter.h"
#include "util/byte_to_str.h"

#include <filebuffer.h>
#include <strbuilder.h>
#include <util/str.h>
#include <string.h>
#include <alloc.h>
#include <log.h>

#define max(x, y) ((x) > (y) ? (x) : (y))

extern int yymax_ident_len;

static const char* type_to_string(BHEngineValueType t)
{
    switch (t) {
        case TENGINE_UNUM:
            return "unum";
        case TENGINE_SNUM:
            return "snum";
        case TENGINE_CHAR:
            return "char";
        case TENGINE_WCHAR:
            return "wchar";
        case TENGINE_ENUM_VALUE:
            return "enum_value";
        case TENGINE_STRING:
            return "string";
        case TENGINE_WSTRING:
            return "wstring";
        case TENGINE_OBJ:
            return "custom_type";
        default:
            panic("invalid type in BHEngineValue_get_num");
    }
    return NULL;
}

BHEngineValue* BHEngineValue_SNUM_new(s64_t v, u32_t size)
{
    if (size == 0)
        panic("BHEngineValue_SNUM_new() invalid size");
    if (size < 8) {
        u64_t mask = (2ull << ((u64_t)size * 8 - 1ull)) - 1ull;
        u64_t msb  = (1ull << ((u64_t)size * 8 - 1ull));
        u64_t vu   = (u64_t)v & mask;
        if (vu & msb)
            vu |= ~mask;
        v = (s64_t)vu;
    }

    BHEngineValue* r = bhex_calloc(sizeof(BHEngineValue));
    r->t             = TENGINE_SNUM;
    r->snum          = v;
    r->snum_size     = size;
    return r;
}

BHEngineValue* BHEngineValue_UNUM_new(u64_t v, u32_t size)
{
    if (size == 0)
        panic("BHEngineValue_UNUM_new() invalid size");
    u64_t mask = (2ull << ((u64_t)size * 8 - 1ull)) - 1ull;

    BHEngineValue* r = bhex_calloc(sizeof(BHEngineValue));
    r->t             = TENGINE_UNUM;
    r->unum          = v & mask;
    r->unum_size     = size;
    return r;
}

BHEngineValue* BHEngineValue_CHAR_new(char c)
{
    BHEngineValue* r = bhex_calloc(sizeof(BHEngineValue));
    r->t             = TENGINE_CHAR;
    r->c             = c;
    return r;
}

BHEngineValue* BHEngineValue_WCHAR_new(u16_t c)
{
    BHEngineValue* r = bhex_calloc(sizeof(BHEngineValue));
    r->t             = TENGINE_WCHAR;
    r->wc            = c;
    return r;
}

BHEngineValue* BHEngineValue_STRING_new(const u8_t* str, u32_t size)
{
    BHEngineValue* r = bhex_calloc(sizeof(BHEngineValue));
    r->t             = TENGINE_STRING;
    r->str           = bhex_calloc(size + 1);
    r->str_size      = size;
    memcpy(r->str, str, size);
    return r;
}

BHEngineValue* BHEngineValue_WSTRING_new(const u16_t* str, u32_t size)
{
    BHEngineValue* r = bhex_calloc(sizeof(BHEngineValue));
    r->t             = TENGINE_WSTRING;
    r->wstr          = bhex_calloc(2 * size + 2);
    r->wstr_size     = size;
    memcpy(r->wstr, str, size * 2);
    return r;
}

BHEngineValue* BHEngineValue_OBJ_new(map* subvals)
{
    BHEngineValue* r = bhex_calloc(sizeof(BHEngineValue));
    r->t             = TENGINE_OBJ;
    r->subvals       = subvals;
    return r;
}

BHEngineValue* BHEngineValue_ENUM_VALUE_new(const char* ename, u64_t econst)
{
    BHEngineValue* r = bhex_calloc(sizeof(BHEngineValue));
    r->t             = TENGINE_ENUM_VALUE;
    r->enum_value    = bhex_strdup(ename);
    r->enum_const    = econst;
    return r;
}

BHEngineValue* BHEngineValue_BUF_new(u64_t off, u64_t size)
{
    BHEngineValue* r = bhex_calloc(sizeof(BHEngineValue));
    r->t             = TENGINE_BUF;
    r->buf_off       = off;
    r->buf_size      = size;
    return r;
}

BHEngineValue* BHEngineValue_ARRAY_new(void)
{
    BHEngineValue* r = bhex_calloc(sizeof(BHEngineValue));
    r->t             = TENGINE_ARRAY;
    r->array_data    = DList_new();
    return r;
}

void BHEngineValue_ARRAY_append(BHEngineValue* arr, BHEngineValue* v)
{
    if (arr->t != TENGINE_ARRAY)
        panic("BHEngineValue_ARRAY_append: not a TENGINE_ARRAY");

    DList_add(arr->array_data, v);
}

BHEngineValue* BHEngineValue_array_sub(InterpreterContext*  ctx,
                                       const BHEngineValue* e,
                                       const BHEngineValue* n)
{
    u64_t n_val;
    if (BHEngineValue_as_u64(ctx, n, &n_val) != 0)
        return NULL;

    switch (e->t) {
        case TENGINE_ARRAY: {
            if (e->array_data->size <= n_val) {
                bhengine_raise_exception(
                    ctx, "out of bound in array (size %llu, index %llu)",
                    e->array_data->size, n_val);
                return NULL;
            }
            return BHEngineValue_dup(e->array_data->data[n_val]);
        }
        case TENGINE_BUF: {
            if (e->buf_size <= n_val) {
                bhengine_raise_exception(
                    ctx, "out of bound in buf (size %llu, index %llu)",
                    e->buf_size, n_val);
                return NULL;
            }
            u64_t orig_s = ctx->fb->off;
            if (fb_seek(ctx->fb, e->buf_off + n_val) != 0) {
                bhengine_raise_exception(
                    ctx, "invalid buffer, it spans outside the file");
                return NULL;
            }
            const u8_t* buf = fb_read(ctx->fb, 1);
            if (buf == NULL)
                return NULL;
            BHEngineValue* v = BHEngineValue_UNUM_new(buf[0], 1);
            fb_seek(ctx->fb, orig_s);
            return v;
        }
        case TENGINE_STRING: {
            if (e->str_size <= n_val) {
                bhengine_raise_exception(
                    ctx, "out of bound in string (size %llu, index %llu)",
                    e->str_size, n_val);
                return NULL;
            }
            return BHEngineValue_UNUM_new(e->str[n_val], 1);
        }
        case TENGINE_WSTRING: {
            if (e->wstr_size <= n_val) {
                bhengine_raise_exception(
                    ctx, "out of bound in string (size %llu, index %llu)",
                    e->wstr_size, n_val);
                return NULL;
            }
            return BHEngineValue_UNUM_new(e->wstr[n_val], 2);
        }
        default:
            break;
    }

    bhengine_raise_exception(ctx, "array_sub undefined for type %s",
                             type_to_string(e->t));
    return NULL;
}

#define is_snum(e)       ((e)->t == TENGINE_SNUM)
#define is_unum(e)       ((e)->t == TENGINE_UNUM || (e)->t == TENGINE_ENUM_VALUE)
#define get_unum_size(e) (((e)->t == TENGINE_UNUM) ? (e)->unum_size : 8)
#define get_unum_value(e)                                                      \
    (((e)->t == TENGINE_UNUM) ? (e)->unum : (e)->enum_const)

#define binop_num_ext(ctx, op, check_zero)                                     \
    if (lhs == NULL || rhs == NULL)                                            \
        return NULL;                                                           \
    if (check_zero && ((is_unum(rhs) && get_unum_value(rhs) == 0) ||           \
                       (is_snum(rhs) && rhs->snum == 0))) {                    \
        bhengine_raise_exception(ctx, "div by zero");                          \
        return NULL;                                                           \
    }                                                                          \
    if (is_unum(lhs) && is_unum(rhs)) {                                        \
        return BHEngineValue_UNUM_new(                                         \
            get_unum_value(lhs) op get_unum_value(rhs),                        \
            max(get_unum_size(lhs), get_unum_size(rhs)));                      \
    }                                                                          \
    if (is_snum(lhs) && is_unum(rhs)) {                                        \
        return BHEngineValue_SNUM_new(                                         \
            lhs->snum op(s64_t) get_unum_value(rhs),                           \
            max(lhs->snum_size, get_unum_size(rhs)));                          \
    }                                                                          \
    if (is_unum(lhs) && is_snum(rhs)) {                                        \
        return BHEngineValue_SNUM_new(                                         \
            (s64_t)get_unum_value(lhs) op rhs->snum,                           \
            max(get_unum_size(lhs), rhs->snum_size));                          \
    }                                                                          \
    if (is_snum(lhs) && is_snum(rhs)) {                                        \
        return BHEngineValue_SNUM_new(lhs->snum op rhs->snum,                  \
                                      max(lhs->snum_size, rhs->snum_size));    \
    }

#define binop_num(ctx, op) binop_num_ext(ctx, op, 0)

BHEngineValue* BHEngineValue_add(InterpreterContext*  ctx,
                                 const BHEngineValue* lhs,
                                 const BHEngineValue* rhs)
{
    binop_num(ctx, +);

    bhengine_raise_exception(ctx, "add undefined for types %s and %s",
                             type_to_string(lhs->t), type_to_string(rhs->t));
    return NULL;
}

BHEngineValue* BHEngineValue_sub(InterpreterContext*  ctx,
                                 const BHEngineValue* lhs,
                                 const BHEngineValue* rhs)
{
    binop_num(ctx, -);

    bhengine_raise_exception(ctx, "sub undefined for types %s and %s",
                             type_to_string(lhs->t), type_to_string(rhs->t));
    return NULL;
}

BHEngineValue* BHEngineValue_mul(InterpreterContext*  ctx,
                                 const BHEngineValue* lhs,
                                 const BHEngineValue* rhs)
{
    binop_num(ctx, *);

    bhengine_raise_exception(ctx, "mul undefined for types %s and %s",
                             type_to_string(lhs->t), type_to_string(rhs->t));
    return NULL;
}

BHEngineValue* BHEngineValue_div(InterpreterContext*  ctx,
                                 const BHEngineValue* lhs,
                                 const BHEngineValue* rhs)
{
    binop_num_ext(ctx, /, 1);

    bhengine_raise_exception(ctx, "div undefined for types %s and %s",
                             type_to_string(lhs->t), type_to_string(rhs->t));
    return NULL;
}

BHEngineValue* BHEngineValue_mod(InterpreterContext*  ctx,
                                 const BHEngineValue* lhs,
                                 const BHEngineValue* rhs)
{
    binop_num_ext(ctx, %, 1);

    bhengine_raise_exception(ctx, "mod undefined for types %s and %s",
                             type_to_string(lhs->t), type_to_string(rhs->t));
    return NULL;
}

BHEngineValue* BHEngineValue_and(InterpreterContext*  ctx,
                                 const BHEngineValue* lhs,
                                 const BHEngineValue* rhs)
{
    binop_num(ctx, &);

    bhengine_raise_exception(ctx, "and undefined for types %s and %s",
                             type_to_string(lhs->t), type_to_string(rhs->t));
    return NULL;
}

BHEngineValue* BHEngineValue_or(InterpreterContext*  ctx,
                                const BHEngineValue* lhs,
                                const BHEngineValue* rhs)
{
    binop_num(ctx, |);

    bhengine_raise_exception(ctx, "or undefined for types %s and %s",
                             type_to_string(lhs->t), type_to_string(rhs->t));
    return NULL;
}

BHEngineValue* BHEngineValue_xor(InterpreterContext*  ctx,
                                 const BHEngineValue* lhs,
                                 const BHEngineValue* rhs)
{
    binop_num(ctx, ^);

    bhengine_raise_exception(ctx, "xor undefined for types %s and %s",
                             type_to_string(lhs->t), type_to_string(rhs->t));
    return NULL;
}

BHEngineValue* BHEngineValue_shr(InterpreterContext*  ctx,
                                 const BHEngineValue* lhs,
                                 const BHEngineValue* rhs)
{
    binop_num(ctx, >>);

    bhengine_raise_exception(ctx, "shr undefined for types %s and %s",
                             type_to_string(lhs->t), type_to_string(rhs->t));
    return NULL;
}

BHEngineValue* BHEngineValue_shl(InterpreterContext*  ctx,
                                 const BHEngineValue* lhs,
                                 const BHEngineValue* rhs)
{
    binop_num(ctx, <<);

    bhengine_raise_exception(ctx, "shl undefined for types %s and %s",
                             type_to_string(lhs->t), type_to_string(rhs->t));
    return NULL;
}

#define binop_bool(op)                                                         \
    if (lhs == NULL || rhs == NULL)                                            \
        return NULL;                                                           \
    if (is_unum(lhs) && is_unum(rhs)) {                                        \
        return BHEngineValue_UNUM_new(                                         \
            (get_unum_value(lhs) op get_unum_value(rhs)) ? 1 : 0, 1);          \
    }                                                                          \
    if (is_snum(lhs) && is_unum(rhs)) {                                        \
        return BHEngineValue_UNUM_new(                                         \
            ((u64_t)lhs->snum op get_unum_value(rhs)) ? 1 : 0, 1);             \
    }                                                                          \
    if (is_unum(lhs) && is_snum(rhs)) {                                        \
        return BHEngineValue_UNUM_new(                                         \
            (get_unum_value(lhs) op(u64_t) rhs->snum) ? 1 : 0, 1);             \
    }                                                                          \
    if (is_snum(lhs) && is_snum(rhs)) {                                        \
        return BHEngineValue_UNUM_new((lhs->snum op rhs->snum) ? 1 : 0, 1);    \
    }

BHEngineValue* BHEngineValue_bgt(InterpreterContext*  ctx,
                                 const BHEngineValue* lhs,
                                 const BHEngineValue* rhs)
{
    binop_bool(>);

    bhengine_raise_exception(ctx, "bgt undefined for types %s and %s",
                             type_to_string(lhs->t), type_to_string(rhs->t));
    return NULL;
}

BHEngineValue* BHEngineValue_bge(InterpreterContext*  ctx,
                                 const BHEngineValue* lhs,
                                 const BHEngineValue* rhs)
{
    binop_bool(>=);

    bhengine_raise_exception(ctx, "bge undefined for types %s and %s",
                             type_to_string(lhs->t), type_to_string(rhs->t));
    return NULL;
}

BHEngineValue* BHEngineValue_blt(InterpreterContext*  ctx,
                                 const BHEngineValue* lhs,
                                 const BHEngineValue* rhs)
{
    binop_bool(<);

    bhengine_raise_exception(ctx, "blt undefined for types %s and %s",
                             type_to_string(lhs->t), type_to_string(rhs->t));
    return NULL;
}

BHEngineValue* BHEngineValue_ble(InterpreterContext*  ctx,
                                 const BHEngineValue* lhs,
                                 const BHEngineValue* rhs)
{
    binop_bool(<=);

    bhengine_raise_exception(ctx, "ble undefined for types %s and %s",
                             type_to_string(lhs->t), type_to_string(rhs->t));
    return NULL;
}

BHEngineValue* BHEngineValue_beq(InterpreterContext*  ctx,
                                 const BHEngineValue* lhs,
                                 const BHEngineValue* rhs)
{
    binop_bool(==);

    if (lhs->t == TENGINE_STRING && rhs->t == TENGINE_STRING) {
        if (lhs->str_size != rhs->str_size ||
            memcmp(lhs->str, rhs->str, lhs->str_size) != 0)
            return BHEngineValue_UNUM_new(0, 8);
        return BHEngineValue_UNUM_new(1, 8);
    }
    if (lhs->t == TENGINE_WSTRING && rhs->t == TENGINE_WSTRING) {
        if (lhs->wstr_size != rhs->wstr_size ||
            memcmp(lhs->wstr, rhs->wstr, lhs->wstr_size * 2) != 0)
            return BHEngineValue_UNUM_new(0, 8);
        return BHEngineValue_UNUM_new(1, 8);
    }
    if (lhs->t == TENGINE_CHAR && rhs->t == TENGINE_CHAR) {
        return BHEngineValue_UNUM_new((lhs->c == rhs->c) ? 1 : 0, 1);
    }
    if (lhs->t == TENGINE_WCHAR && rhs->t == TENGINE_WCHAR) {
        return BHEngineValue_UNUM_new((lhs->wc == rhs->wc) ? 1 : 0, 1);
    }
    if (lhs->t == TENGINE_ENUM_VALUE && rhs->t == TENGINE_ENUM_VALUE) {
        return BHEngineValue_UNUM_new(
            (lhs->enum_const == rhs->enum_const) ? 1 : 0, 1);
    }
    if (lhs->t == TENGINE_ENUM_VALUE && rhs->t == TENGINE_SNUM) {
        return BHEngineValue_UNUM_new(
            (lhs->enum_const == (u64_t)rhs->snum) ? 1 : 0, 1);
    }
    if (lhs->t == TENGINE_SNUM && rhs->t == TENGINE_ENUM_VALUE) {
        return BHEngineValue_UNUM_new(
            ((u64_t)lhs->snum == rhs->enum_const) ? 1 : 0, 1);
    }
    if (lhs->t == TENGINE_ENUM_VALUE && rhs->t == TENGINE_UNUM) {
        return BHEngineValue_UNUM_new((lhs->enum_const == rhs->unum) ? 1 : 0,
                                      1);
    }
    if (lhs->t == TENGINE_UNUM && rhs->t == TENGINE_ENUM_VALUE) {
        return BHEngineValue_UNUM_new((lhs->unum == rhs->enum_const) ? 1 : 0,
                                      1);
    }

    // Uncomparable objects, return false
    return BHEngineValue_UNUM_new(0, 8);
}

BHEngineValue* BHEngineValue_bnot(InterpreterContext*  ctx,
                                  const BHEngineValue* child)
{
    if (child->t == TENGINE_SNUM) {
        return BHEngineValue_UNUM_new(child->snum == 0 ? 1 : 0, 1);
    }
    if (child->t == TENGINE_UNUM) {
        return BHEngineValue_UNUM_new(child->unum == 0 ? 1 : 0, 1);
    }

    bhengine_raise_exception(ctx, "beq undefined for type %s",
                             type_to_string(child->t));
    return NULL;
}

BHEngineValue* BHEngineValue_band(InterpreterContext*  ctx,
                                  const BHEngineValue* lhs,
                                  const BHEngineValue* rhs)
{
    binop_bool(&&);

    bhengine_raise_exception(ctx, "band undefined for types %s and %s",
                             type_to_string(lhs->t), type_to_string(rhs->t));
    return NULL;
}

BHEngineValue* BHEngineValue_bor(InterpreterContext*  ctx,
                                 const BHEngineValue* lhs,
                                 const BHEngineValue* rhs)
{
    binop_bool(||);

    bhengine_raise_exception(ctx, "bor undefined for types %s and %s",
                             type_to_string(lhs->t), type_to_string(rhs->t));
    return NULL;
}

int BHEngineValue_as_u64(InterpreterContext* ctx, const BHEngineValue* v,
                         u64_t* o)
{
    switch (v->t) {
        case TENGINE_UNUM:
            if ((v->unum >> 63) != 0) {
                bhengine_raise_exception(ctx,
                                         "the number '%llu' is too big to "
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
        case TENGINE_WCHAR:
            *o = (u64_t)v->wc;
            return 0;
        case TENGINE_ENUM_VALUE:
            *o = (u64_t)v->enum_const;
            return 0;
        case TENGINE_WSTRING:
        case TENGINE_STRING:
        case TENGINE_OBJ:
            bhengine_raise_exception(ctx, "%s not a numeric type",
                                     type_to_string(v->t));
            return 1;
        default:
            panic("invalid type in BHEngineValue_as_u64");
    }
    return 1;
}

int BHEngineValue_as_string(InterpreterContext* ctx, const BHEngineValue* v,
                            const char** o)
{
    if (v->t == TENGINE_STRING) {
        *o = (char*)v->str;
        return 0;
    }
    // TODO: maybe implement something for wstrings? so that we can use string
    // builtins (e.g., strlen) with wstrings

    bhengine_raise_exception(ctx, "%s is not a string", type_to_string(v->t));
    return 1;
}

int BHEngineValue_as_s64(InterpreterContext* ctx, const BHEngineValue* v,
                         s64_t* o)
{
    switch (v->t) {
        case TENGINE_UNUM:
            if ((v->unum >> 63) != 0) {
                bhengine_raise_exception(ctx,
                                         "the number '%llu' is too big to "
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
        case TENGINE_WCHAR:
            *o = (s64_t)v->wc;
            return 0;
        case TENGINE_ENUM_VALUE:
            *o = (s64_t)v->enum_const;
            return 0;
        case TENGINE_STRING:
        case TENGINE_WSTRING:
        case TENGINE_OBJ:
            bhengine_raise_exception(ctx, "%s not a numeric type",
                                     type_to_string(v->t));
            return 1;
        default:
            panic("invalid type in BHEngineValue_as_s64");
    }
    return 1;
}

void BHEngineValue_free(BHEngineValue* v)
{
    if (!v)
        return;

    switch (v->t) {
        case TENGINE_UNUM:
        case TENGINE_SNUM:
        case TENGINE_CHAR:
        case TENGINE_WCHAR:
        case TENGINE_BUF:
            break;
        case TENGINE_STRING:
            bhex_free(v->str);
            break;
        case TENGINE_WSTRING:
            bhex_free(v->wstr);
            break;
        case TENGINE_ENUM_VALUE:
            bhex_free(v->enum_value);
            break;
        case TENGINE_OBJ:
            map_destroy(v->subvals);
            break;
        case TENGINE_ARRAY:
            DList_destroy(v->array_data, (void (*)(void*))BHEngineValue_free);
            break;
        default:
            panic("invalid type in BHEngineValue_free");
    }
    bhex_free(v);
}

BHEngineValue* BHEngineValue_dup(BHEngineValue* v)
{
    if (!v)
        panic("BHEngineValue_dup: NULL input");

    switch (v->t) {
        case TENGINE_UNUM:
            return BHEngineValue_UNUM_new(v->unum, v->unum_size);
        case TENGINE_SNUM:
            return BHEngineValue_SNUM_new(v->snum, v->snum_size);
        case TENGINE_CHAR:
            return BHEngineValue_CHAR_new(v->c);
        case TENGINE_WCHAR:
            return BHEngineValue_WCHAR_new(v->wc);
        case TENGINE_STRING:
            return BHEngineValue_STRING_new(v->str, v->str_size);
        case TENGINE_WSTRING:
            return BHEngineValue_WSTRING_new(v->wstr, v->wstr_size);
        case TENGINE_ENUM_VALUE:
            return BHEngineValue_ENUM_VALUE_new(v->enum_value, v->enum_const);
        case TENGINE_OBJ: {
            map* subvals = map_create();
            map_set_dispose(subvals, (void (*)(void*))BHEngineValue_free);
            for (const char* key = map_first(v->subvals); key != NULL;
                 key             = map_next(v->subvals, key)) {
                BHEngineValue* n = BHEngineValue_dup(map_get(v->subvals, key));
                if (n == NULL)
                    panic("BHEngineValue_dup: invalid subvar");
                map_set(subvals, key, n);
            }
            return BHEngineValue_OBJ_new(subvals);
        }
        case TENGINE_BUF:
            return BHEngineValue_BUF_new(v->buf_off, v->buf_size);
        case TENGINE_ARRAY: {
            BHEngineValue* newarr = BHEngineValue_ARRAY_new();
            for (u64_t i = 0; i < v->array_data->size; ++i) {
                BHEngineValue* dupel =
                    BHEngineValue_dup(v->array_data->data[i]);
                if (dupel == NULL)
                    panic("BHEngineValue_dup: invalida arr value");
                BHEngineValue_ARRAY_append(newarr, dupel);
            }
            return newarr;
        }
        default:
            panic("invalid type in BHEngineValue_dup");
    }
    return NULL;
}

void BHEngineValue_pp(const BHEngineValue* v, int hex)
{
    char* str = BHEngineValue_tostring(v, hex);
    printf("%s\n", str);
    bhex_free(str);
}

char* BHEngineValue_tostring(const BHEngineValue* v, int hex)
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
            if (is_printable_ascii(v->c))
                strbuilder_appendf(sb, "%c", v->c);
            else
                strbuilder_appendf(sb, "'\\x%02X'", v->c);
            break;
        case TENGINE_WCHAR:
            if (v->wc < 128 && is_printable_ascii(v->wc))
                strbuilder_appendf(sb, "%c", (char)v->wc);
            else
                strbuilder_appendf(sb, "'\\u%04x'", v->wc);
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
        case TENGINE_WSTRING: {
            strbuilder_append_char(sb, '\'');
            for (u32_t i = 0; i < v->wstr_size; ++i) {
                if (!v->wstr[i])
                    break;
                if (v->wstr[i] < 128 && is_printable_ascii(v->wstr[i]))
                    strbuilder_append_char(sb, v->wstr[i]);
                else
                    strbuilder_appendf(sb, "\\u%04x", v->wstr[i]);
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
                BHEngineValue* nv     = map_get(v->subvals, key);
                char*          substr = BHEngineValue_tostring(nv, hex);
                strbuilder_append(sb, substr);
                strbuilder_append_char(sb, '\n');
                bhex_free(substr);
            }
            char* content = strbuilder_finalize(sb);
            sb            = strbuilder_new();
            strbuilder_append_char(sb, '\n');
            char* indented = str_indent(content, 4);
            strbuilder_append(sb, indented);
            bhex_free(indented);
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
                    BHEngineValue_tostring(v->array_data->data[i], hex);
                char* indented = str_indent(subel, 4);
                strbuilder_append(sb, indented);
                bhex_free(indented);
            }
            break;
        }
        default:
            panic("invalid type in BHEngineValue_tostring");
    }
    return strbuilder_finalize(sb);
}
