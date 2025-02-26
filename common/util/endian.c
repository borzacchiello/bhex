// Based on Rizin https://github.com/rizinorg/rizin

#include "endian.h"
#include "display.h"

u8_t read8(const void* src) { return *(const u8_t*)src; }

u8_t read_at_8(const void* src, size_t offset)
{
    return read8((const u8_t*)src + offset);
}

void write8(void* dest, u8_t val) { *(u8_t*)dest = val; }

void write_at_8(void* dest, u8_t val, size_t offset)
{
    write8((u8_t*)dest + offset, val);
}

u16_t read_le16(const void* src)
{
    const u8_t* s = (const u8_t*)src;
    return (((u16_t)s[1]) << 8) | (((u16_t)s[0]) << 0);
}

u16_t read_at_le16(const void* src, size_t offset)
{
    if (!src) {
        return 0;
    }
    const u8_t* s = (const u8_t*)src + offset;
    return read_le16(s);
}

void write_le16(void* dest, u16_t val)
{
    write8(dest, (u8_t)val);
    write_at_8(dest, val >> 8, sizeof(u8_t));
}

void write_at_le16(void* dest, u16_t val, size_t offset)
{
    u8_t* d = (u8_t*)dest + offset;
    write_le16(d, val);
}

u32_t read_le32(const void* src)
{
    if (!src) {
        return 0;
    }
    const u8_t* s = (const u8_t*)src;
    return (((u32_t)s[3]) << 24) | (((u32_t)s[2]) << 16) |
           (((u32_t)s[1]) << 8) | (((u32_t)s[0]) << 0);
}

u32_t read_at_le32(const void* src, size_t offset)
{
    if (!src) {
        return 0;
    }
    const u8_t* s = (const u8_t*)src + offset;
    return read_le32(s);
}

void write_le32(void* dest, u32_t val)
{
    write_le16(dest, val);
    write_at_le16(dest, val >> 16, sizeof(u16_t));
}

void write_at_le32(void* dest, u32_t val, size_t offset)
{
    u8_t* d = ((u8_t*)dest) + offset;
    write_le32(d, val);
}

u64_t read_le64(const void* src)
{
    u64_t val = ((u64_t)(read_at_le32(src, sizeof(u32_t)))) << 32;
    val |= read_le32(src);
    return val;
}

u64_t read_at_le64(const void* src, size_t offset)
{
    const u8_t* s = ((const u8_t*)src) + offset;
    return read_le64(s);
}

void write_le64(void* dest, u64_t val)
{
    write_le32(dest, (u32_t)val);
    write_at_le32(dest, val >> 32, sizeof(u32_t));
}

void write_at_le64(void* dest, u64_t val, size_t offset)
{
    u8_t* d = (u8_t*)dest + offset;
    write_le64(d, val);
}

u16_t read_be16(const void* src)
{
    const u8_t* s = (const u8_t*)src;
    return (((u16_t)s[0]) << 8) | (((u16_t)s[1]) << 0);
}

u16_t read_at_be16(const void* src, size_t offset)
{
    const u8_t* s = (const u8_t*)src + offset;
    return read_be16(s);
}

void write_be16(void* dest, u16_t val)
{
    write8(dest, val >> 8);
    write_at_8(dest, (u8_t)val, sizeof(u8_t));
}

void write_at_be16(void* dest, u16_t val, size_t offset)
{
    u8_t* d = (u8_t*)dest + offset;
    write_be16(d, val);
}

u32_t read_be32(const void* src)
{
    const u8_t* s = (const u8_t*)src;
    return (((u32_t)s[0]) << 24) | (((u32_t)s[1]) << 16) |
           (((u32_t)s[2]) << 8) | (((u32_t)s[3]) << 0);
}

u32_t read_at_be32(const void* src, size_t offset)
{
    const u8_t* s = (const u8_t*)src + offset;
    return read_be32(s);
}

void write_be32(void* dest, u32_t val)
{
    write_be16(dest, val >> 16);
    write_at_be16(dest, val, sizeof(u16_t));
}

void write_at_be32(void* dest, u32_t val, size_t offset)
{
    u8_t* d = (u8_t*)dest + offset;
    write_be32(d, val);
}

u64_t read_be64(const void* src)
{
    u64_t val = ((u64_t)(read_be32(src))) << 32;
    val |= read_at_be32(src, sizeof(u32_t));
    return val;
}

u64_t read_at_be64(const void* src, size_t offset)
{
    const u8_t* s = (const u8_t*)src + offset;
    return read_be64(s);
}

void write_be64(void* dest, u64_t val)
{
    write_be32(dest, val >> 32);
    write_at_be32(dest, (u32_t)val, sizeof(u32_t));
}

void write_at_be64(void* dest, u64_t val, size_t offset)
{
    u8_t* d = (u8_t*)dest + offset;
    write_be64(d, val);
}
