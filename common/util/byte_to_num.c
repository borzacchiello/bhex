#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "byte_to_num.h"

int str_to_uint64(const char* str, u64_t* o_num)
{
    errno = 0;

    char* endptr = NULL;
    u64_t r      = strtoull(str, &endptr, 0);
    *o_num       = 0;

    if (str == endptr)
        // No digits found
        return 0;
    else if (errno == ERANGE)
        // Overflow
        return 0;
    else if (errno == EINVAL)
        // Wrong base
        return 0;
    else if (errno != 0 && r == 0)
        // Unknown error
        return 0;
    else if (errno == 0 && str && *endptr != 0)
        // Data at the end
        return 0;

    *o_num = r;
    return 1;
}

int str_to_uint32(const char* str, u32_t* o_num)
{
    u64_t num;
    if (!str_to_uint64(str, &num))
        return 0;

    if (num > UINT32_MAX)
        return 0;
    *o_num = (u32_t)num;
    return 1;
}

int str_to_uint16(const char* str, u16_t* o_num)
{
    u64_t num;
    if (!str_to_uint64(str, &num))
        return 0;

    if (num > UINT16_MAX)
        return 0;
    *o_num = (u16_t)num;
    return 1;
}

int str_to_uint8(const char* str, u8_t* o_num)
{
    u64_t num;
    if (!str_to_uint64(str, &num))
        return 0;

    if (num > UINT8_MAX)
        return 0;
    *o_num = (u8_t)num;
    return 1;
}

int str_to_int64(const char* str, s64_t* o_num)
{
    errno = 0;

    char* endptr = NULL;
    s64_t r      = strtoll(str, &endptr, 0);
    *o_num       = 0;

    if (str == endptr)
        // No digits found
        return 0;
    else if (errno == ERANGE)
        // Overflow
        return 0;
    else if (errno == EINVAL)
        // Wrong base
        return 0;
    else if (errno != 0 && r == 0)
        // Unknown error
        return 0;
    else if (errno == 0 && str && *endptr != 0)
        // Data at the end
        return 0;

    *o_num = r;
    return 1;
}

int str_to_int32(const char* str, s32_t* o_num)
{
    s64_t num;
    if (!str_to_int64(str, &num))
        return 0;

    if (num > INT32_MAX || num < INT32_MIN)
        return 0;
    *o_num = (s32_t)num;
    return 1;
}

int str_to_int16(const char* str, s16_t* o_num)
{
    s64_t num;
    if (!str_to_int64(str, &num))
        return 0;

    if (num > INT16_MAX || num < INT16_MIN)
        return 0;
    *o_num = (s16_t)num;
    return 1;
}

int str_to_int8(const char* str, s8_t* o_num)
{
    s64_t num;
    if (!str_to_int64(str, &num))
        return 0;

    if (num > INT8_MAX || num < INT8_MIN)
        return 0;
    *o_num = (s8_t)num;
    return 1;
}
