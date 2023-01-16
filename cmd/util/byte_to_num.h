#ifndef BYTE_TO_NUM_H
#define BYTE_TO_NUM_H

#include <stdint.h>

int str_to_uint64(const char* str, uint64_t* o_num);
int str_to_uint32(const char* str, uint32_t* o_num);
int str_to_uint16(const char* str, uint16_t* o_num);
int str_to_uint8(const char* str, uint8_t* o_num);

int str_to_int64(const char* str, int64_t* o_num);
int str_to_int32(const char* str, int32_t* o_num);
int str_to_int16(const char* str, int16_t* o_num);
int str_to_int8(const char* str, int8_t* o_num);

#endif
