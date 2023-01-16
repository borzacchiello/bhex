#ifndef BYTE_TO_NUM_H
#define BYTE_TO_NUM_H

#include "../../defs.h"

int str_to_uint64(const char* str, u64_t* o_num);
int str_to_uint32(const char* str, u32_t* o_num);
int str_to_uint16(const char* str, u16_t* o_num);
int str_to_uint8(const char* str, u8_t* o_num);

int str_to_int64(const char* str, s64_t* o_num);
int str_to_int32(const char* str, s32_t* o_num);
int str_to_int16(const char* str, s16_t* o_num);
int str_to_int8(const char* str, s8_t* o_num);

#endif
