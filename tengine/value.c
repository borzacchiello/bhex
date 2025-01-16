#include "value.h"
#include "defs.h"
#include "tengine.h"
#include "local.h"

#include <strbuilder.h>
#include <util/str.h>
#include <string.h>
#include <alloc.h>
#include <log.h>

#define max(x, y) ((x) > (y) ? (x) : (y))

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
    TEngineValue* r = bhex_calloc(sizeof(TEngineValue));
    r->t            = TENGINE_SNUM;
    r->snum         = v;
    r->snum_size    = size;
    return r;
}

TEngineValue* TEngineValue_UNUM_new(u64_t v, u32_t size)
{
    u64_t mask = (2ul << ((u64_t)size * 8 - 1ul)) - 1ul;

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

TEngineValue* TEngineValue_STRING_new(const char* str)
{
    TEngineValue* r = bhex_calloc(sizeof(TEngineValue));
    r->t            = TENGINE_STRING;
    r->str          = bhex_strdup(str);
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

#define binop_num(op)                                                          \
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

    error("[tengine] add undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_sub(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_num(-);

    error("[tengine] sub undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_mul(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_num(*);

    error("[tengine] mul undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

#define binop_bool(op)                                                         \
    if (lhs->t == TENGINE_UNUM && rhs->t == TENGINE_UNUM) {                    \
        return TEngineValue_UNUM_new((lhs->unum op rhs->unum) ? 1 : 0, 8);     \
    }                                                                          \
    if (lhs->t == TENGINE_SNUM && rhs->t == TENGINE_UNUM) {                    \
        return TEngineValue_UNUM_new(((u64_t)lhs->snum op rhs->unum) ? 1 : 0,  \
                                     8);                                       \
    }                                                                          \
    if (lhs->t == TENGINE_UNUM && rhs->t == TENGINE_SNUM) {                    \
        return TEngineValue_UNUM_new((lhs->unum op(u64_t) rhs->snum) ? 1 : 0,  \
                                     8);                                       \
    }                                                                          \
    if (lhs->t == TENGINE_SNUM && rhs->t == TENGINE_SNUM) {                    \
        return TEngineValue_UNUM_new((lhs->snum op rhs->snum) ? 1 : 0, 8);     \
    }

TEngineValue* TEngineValue_bgt(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_bool(>);

    error("[tengine] bgt undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_bge(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_bool(>=);

    error("[tengine] bge undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_blt(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_bool(<);

    error("[tengine] blt undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_ble(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_bool(<=);

    error("[tengine] ble undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

TEngineValue* TEngineValue_beq(const TEngineValue* lhs, const TEngineValue* rhs)
{
    binop_bool(==);

    if (lhs->t == TENGINE_STRING && rhs->t == TENGINE_STRING) {
        return TEngineValue_UNUM_new((strcmp(lhs->str, rhs->str) == 0) ? 1 : 0,
                                     8);
    }
    if (lhs->t == TENGINE_CHAR && rhs->t == TENGINE_CHAR) {
        return TEngineValue_UNUM_new((lhs->c == rhs->c) ? 1 : 0, 8);
    }
    if (lhs->t == TENGINE_ENUM_VALUE && rhs->t == TENGINE_ENUM_VALUE) {
        return TEngineValue_UNUM_new(
            (lhs->enum_const == rhs->enum_const) ? 1 : 0, 8);
    }
    if (lhs->t == TENGINE_ENUM_VALUE && rhs->t == TENGINE_SNUM) {
        return TEngineValue_UNUM_new(
            (lhs->enum_const == (u64_t)rhs->snum) ? 1 : 0, 8);
    }
    if (lhs->t == TENGINE_SNUM && rhs->t == TENGINE_ENUM_VALUE) {
        return TEngineValue_UNUM_new(
            ((u64_t)lhs->snum == rhs->enum_const) ? 1 : 0, 8);
    }
    if (lhs->t == TENGINE_ENUM_VALUE && rhs->t == TENGINE_UNUM) {
        return TEngineValue_UNUM_new((lhs->enum_const == rhs->unum) ? 1 : 0, 8);
    }
    if (lhs->t == TENGINE_UNUM && rhs->t == TENGINE_ENUM_VALUE) {
        return TEngineValue_UNUM_new((lhs->unum == rhs->enum_const) ? 1 : 0, 8);
    }

    error("[tengine] beq undefined for types %s and %s", type_to_string(lhs->t),
          type_to_string(rhs->t));
    return NULL;
}

int TEngineValue_as_u64(TEngineValue* v, u64_t* o)
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
            error("[tengine] TEngineValue_as_u64: %s not a numeric type",
                  type_to_string(v->t));
            return 1;
        default:
            panic("invalid type in TEngineValue_as_u64");
    }
    return 1;
}

int TEngineValue_as_string(TEngineValue* v, const char** o)
{
    if (v->t == TENGINE_STRING) {
        *o = v->str;
        return 0;
    }

    error("[tengine] TEngineValue_as_string: %s is not a string type",
          type_to_string(v->t));
    return 1;
}

int TEngineValue_as_s64(TEngineValue* v, s64_t* o)
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
            error("[tengine] TEngineValue_as_s64: %s not a numeric type",
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
            return TEngineValue_STRING_new(v->str);
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

char* TEngineValue_tostring(TEngineValue* v, int hex)
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
        case TENGINE_STRING:
            strbuilder_appendf(sb, "'%s'", v->str);
            break;
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
            bhex_free(content);
            break;
        }
        default:
            panic("invalid type in TEngineValue_tostring");
    }
    return strbuilder_finalize(sb);
}
