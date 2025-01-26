#ifndef TENGINE_VALUE_H
#define TENGINE_VALUE_H

#include "dlist.h"
#include <defs.h>
#include <map.h>

struct TEngine;
struct FileBuffer;

typedef enum TEngineValueType {
    TENGINE_UNUM = 500,
    TENGINE_SNUM,
    TENGINE_CHAR,
    TENGINE_STRING,
    TENGINE_ENUM_VALUE,
    TENGINE_BUF,
    TENGINE_ARRAY,
    TENGINE_OBJ,
} TEngineValueType;

typedef struct TEngineValue {
    TEngineValueType t;
    union {
        struct {
            // TENGINE_UNUM
            u64_t unum;
            u32_t unum_size;
        };
        struct {
            // TENGINE_SNUM
            s64_t snum;
            u32_t snum_size;
        };
        struct {
            // TENGINE_CHAR
            char c;
        };
        struct {
            // TENGINE_STRING
            u8_t* str;
            u32_t str_size;
        };
        struct {
            // TENGINE_ENUM_VALUE
            char* enum_value;
            u64_t enum_const;
        };
        struct {
            // TENGINE_BUF
            u64_t buf_off;
            u64_t buf_size;
        };
        struct {
            // TENGINE_ARRAY
            DList* array_data;
        };
        struct {
            // TENGINE_OBJ
            map* subvals;
        };
    };
} TEngineValue;

TEngineValue* TEngineValue_UNUM_new(u64_t v, u32_t size);
TEngineValue* TEngineValue_SNUM_new(s64_t v, u32_t size);
TEngineValue* TEngineValue_CHAR_new(char c);
TEngineValue* TEngineValue_STRING_new(const u8_t* str, u32_t size);
TEngineValue* TEngineValue_ENUM_VALUE_new(const char* ename, u64_t econst);
TEngineValue* TEngineValue_BUF_new(u64_t off, u64_t size);
TEngineValue* TEngineValue_ARRAY_new();
TEngineValue* TEngineValue_OBJ_new(map* subvals);
TEngineValue* TEngineValue_dup(TEngineValue* v);
void          TEngineValue_free(TEngineValue* v);

void TEngineValue_ARRAY_append(TEngineValue* arr, TEngineValue* v);

TEngineValue* TEngineValue_array_sub(struct FileBuffer*  fb,
                                     const TEngineValue* e,
                                     const TEngineValue* n);
TEngineValue* TEngineValue_add(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_sub(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_mul(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_div(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_mod(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_and(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_or(const TEngineValue* lhs, const TEngineValue* rhs);
TEngineValue* TEngineValue_xor(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_bgt(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_bge(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_blt(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_ble(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_beq(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_band(const TEngineValue* lhs,
                                const TEngineValue* rhs);
TEngineValue* TEngineValue_bor(const TEngineValue* lhs,
                               const TEngineValue* rhs);
TEngineValue* TEngineValue_bnot(const TEngineValue* child);

int TEngineValue_as_u64(const TEngineValue* v, u64_t* o);
int TEngineValue_as_s64(const TEngineValue* v, s64_t* o);
int TEngineValue_as_string(const TEngineValue* v, const char** o);

void  TEngineValue_pp(const TEngineValue* v, int hex);
char* TEngineValue_tostring(const TEngineValue* v, int hex);

#endif
