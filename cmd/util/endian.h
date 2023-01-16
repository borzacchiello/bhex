// Based on Rizin https://github.com/rizinorg/rizin

#ifndef ENDIAN_H
#define ENDIAN_H

#include <stdint.h>
#include <stdlib.h>

uint8_t read8(const void* src);
uint8_t read_at_8(const void* src, size_t offset);
void    write8(void* dest, uint8_t val);
void    write_at_8(void* dest, uint8_t val, size_t offset);

uint16_t read_le16(const void* src);
uint16_t read_at_le16(const void* src, size_t offset);
void     write_le16(void* dest, uint16_t val);
void     write_at_le16(void* dest, uint16_t val, size_t offset);
uint32_t read_le32(const void* src);
uint32_t read_at_le32(const void* src, size_t offset);
void     write_le32(void* dest, uint32_t val);
void     write_at_le32(void* dest, uint32_t val, size_t offset);
uint64_t read_le64(const void* src);
uint64_t read_at_le64(const void* src, size_t offset);
void     write_le64(void* dest, uint64_t val);
void     write_at_le64(void* dest, uint64_t val, size_t offset);

uint16_t read_be16(const void* src);
uint16_t read_at_be16(const void* src, size_t offset);
void     write_be16(void* dest, uint16_t val);
void     write_at_be16(void* dest, uint16_t val, size_t offset);
uint32_t read_be32(const void* src);
uint32_t read_at_be32(const void* src, size_t offset);
void     write_be32(void* dest, uint32_t val);
void     write_at_be32(void* dest, uint32_t val, size_t offset);
uint64_t read_be64(const void* src);
uint64_t read_at_be64(const void* src, size_t offset);
void     write_be64(void* dest, uint64_t val);
void     write_at_be64(void* dest, uint64_t val, size_t offset);

#endif
