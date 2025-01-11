// Based on Rizin https://github.com/rizinorg/rizin

#ifndef ENDIAN_H
#define ENDIAN_H

#include <defs.h>
#include <stdlib.h>

u8_t read8(const void* src);
u8_t read_at_8(const void* src, size_t offset);
void    write8(void* dest, u8_t val);
void    write_at_8(void* dest, u8_t val, size_t offset);

u16_t read_le16(const void* src);
u16_t read_at_le16(const void* src, size_t offset);
void     write_le16(void* dest, u16_t val);
void     write_at_le16(void* dest, u16_t val, size_t offset);
u32_t read_le32(const void* src);
u32_t read_at_le32(const void* src, size_t offset);
void     write_le32(void* dest, u32_t val);
void     write_at_le32(void* dest, u32_t val, size_t offset);
u64_t read_le64(const void* src);
u64_t read_at_le64(const void* src, size_t offset);
void     write_le64(void* dest, u64_t val);
void     write_at_le64(void* dest, u64_t val, size_t offset);

u16_t read_be16(const void* src);
u16_t read_at_be16(const void* src, size_t offset);
void     write_be16(void* dest, u16_t val);
void     write_at_be16(void* dest, u16_t val, size_t offset);
u32_t read_be32(const void* src);
u32_t read_at_be32(const void* src, size_t offset);
void     write_be32(void* dest, u32_t val);
void     write_at_be32(void* dest, u32_t val, size_t offset);
u64_t read_be64(const void* src);
u64_t read_at_be64(const void* src, size_t offset);
void     write_be64(void* dest, u64_t val);
void     write_at_be64(void* dest, u64_t val, size_t offset);

#endif
