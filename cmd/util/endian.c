// Based on Rizin https://github.com/rizinorg/rizin

#include "endian.h"

uint8_t read8(const void* src) { return *(const uint8_t*)src; }

uint8_t read_at_8(const void* src, size_t offset)
{
    return read8((const uint8_t*)src + offset);
}

void write8(void* dest, uint8_t val) { *(uint8_t*)dest = val; }

void write_at_8(void* dest, uint8_t val, size_t offset)
{
    write8((uint8_t*)dest + offset, val);
}

uint16_t read_le16(const void* src)
{
    const uint8_t* s = (const uint8_t*)src;
    return (((uint16_t)s[1]) << 8) | (((uint16_t)s[0]) << 0);
}

uint16_t read_at_le16(const void* src, size_t offset)
{
    if (!src) {
        return 0;
    }
    const uint8_t* s = (const uint8_t*)src + offset;
    return read_le16(s);
}

void write_le16(void* dest, uint16_t val)
{
    write8(dest, (uint8_t)val);
    write_at_8(dest, val >> 8, sizeof(uint8_t));
}

void write_at_le16(void* dest, uint16_t val, size_t offset)
{
    uint8_t* d = (uint8_t*)dest + offset;
    write_le16(d, val);
}

uint32_t read_le32(const void* src)
{
    if (!src) {
        return 0;
    }
    const uint8_t* s = (const uint8_t*)src;
    return (((uint32_t)s[3]) << 24) | (((uint32_t)s[2]) << 16) |
           (((uint32_t)s[1]) << 8) | (((uint32_t)s[0]) << 0);
}

uint32_t read_at_le32(const void* src, size_t offset)
{
    if (!src) {
        return 0;
    }
    const uint8_t* s = (const uint8_t*)src + offset;
    return read_le32(s);
}

void write_le32(void* dest, uint32_t val)
{
    write_le16(dest, val);
    write_at_le16(dest, val >> 16, sizeof(uint16_t));
}

void write_at_le32(void* dest, uint32_t val, size_t offset)
{
    uint8_t* d = ((uint8_t*)dest) + offset;
    write_le32(d, val);
}

uint64_t read_le64(const void* src)
{
    uint64_t val = ((uint64_t)(read_at_le32(src, sizeof(uint32_t)))) << 32;
    val |= read_le32(src);
    return val;
}

uint64_t read_at_le64(const void* src, size_t offset)
{
    const uint8_t* s = ((const uint8_t*)src) + offset;
    return read_le64(s);
}

void write_le64(void* dest, uint64_t val)
{
    write_le32(dest, (uint32_t)val);
    write_at_le32(dest, val >> 32, sizeof(uint32_t));
}

void write_at_le64(void* dest, uint64_t val, size_t offset)
{
    uint8_t* d = (uint8_t*)dest + offset;
    write_le64(d, val);
}

uint16_t read_be16(const void* src)
{
    const uint8_t* s = (const uint8_t*)src;
    return (((uint16_t)s[0]) << 8) | (((uint16_t)s[1]) << 0);
}

uint16_t read_at_be16(const void* src, size_t offset)
{
    const uint8_t* s = (const uint8_t*)src + offset;
    return read_be16(s);
}

void write_be16(void* dest, uint16_t val)
{
    write8(dest, val >> 8);
    write_at_8(dest, (uint8_t)val, sizeof(uint8_t));
}

void write_at_be16(void* dest, uint16_t val, size_t offset)
{
    uint8_t* d = (uint8_t*)dest + offset;
    write_be16(d, val);
}

uint32_t read_be32(const void* src)
{
    const uint8_t* s = (const uint8_t*)src;
    return (((uint32_t)s[0]) << 24) | (((uint32_t)s[1]) << 16) |
           (((uint32_t)s[2]) << 8) | (((uint32_t)s[3]) << 0);
}

uint32_t read_at_be32(const void* src, size_t offset)
{
    const uint8_t* s = (const uint8_t*)src + offset;
    return read_be32(s);
}

void write_be32(void* dest, uint32_t val)
{
    write_be16(dest, val >> 16);
    write_at_be16(dest, val, sizeof(uint16_t));
}

void write_at_be32(void* dest, uint32_t val, size_t offset)
{
    uint8_t* d = (uint8_t*)dest + offset;
    write_be32(d, val);
}

uint64_t read_be64(const void* src)
{
    uint64_t val = ((uint64_t)(read_be32(src))) << 32;
    val |= read_at_be32(src, sizeof(uint32_t));
    return val;
}

uint64_t read_at_be64(const void* src, size_t offset)
{
    const uint8_t* s = (const uint8_t*)src + offset;
    return read_be64(s);
}

void write_be64(void* dest, uint64_t val)
{
    write_be32(dest, val >> 32);
    write_at_be32(dest, (uint32_t)val, sizeof(uint32_t));
}

void write_at_be64(void* dest, uint64_t val, size_t offset)
{
    uint8_t* d = (uint8_t*)dest + offset;
    write_be64(d, val);
}
