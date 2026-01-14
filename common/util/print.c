#include "defs.h"
#include "print.h"
#include "endian.h"
#include "byte_to_str.h"

#include <display.h>
#include <log.h>

static u32_t get_addr_string_size(u64_t addr)
{
    u32_t size = 0;
    do {
        size += 1;
        addr /= 16;
    } while (addr != 0);
    return size;
}

void print_ascii(const u8_t* bytes, size_t size, int print_footer)
{
    u64_t off = 0;
    while (off < size) {
        if (bytes[off] == 0)
            break;
        if (is_printable_ascii(bytes[off]) || bytes[off] == '\t' ||
            bytes[off] == '\n') {
            display_printf("%c", bytes[off]);
        } else {
            display_printf(".");
        }
        off += 1;
    }
    if (print_footer)
        display_printf("\n");
}

void print_c_buffer(const u8_t* bytes, size_t size, int print_header,
                    int print_footer)
{
    if (size == 0)
        return;

    size_t i = 0;
    if (print_header) {
        display_printf("{ 0x%02x", bytes[0]);
        i = 1;
    }
    for (; i < size; ++i)
        display_printf(", 0x%02x", bytes[i]);
    if (print_footer)
        display_printf(" }\n");
}

void print_hex(const u8_t* bytes, size_t size, int raw_mode, int print_header,
               int print_footer, int row_width, u64_t addr)
{
    int block_size = row_width;
    if (row_width > 256 || row_width < 16)
        panic("print_hex(): row_width must be in [16,256]");

    u32_t addr_off = get_addr_string_size(addr + size);
    if (addr_off < 4)
        addr_off = 4;

    if (!raw_mode && print_header) {
        display_printf(" %*s ", addr_off + 1, " ");
        for (int i = 0; i < block_size; i += 1) {
            display_printf("%02X ", i);
        }
        display_printf("\n %*s ", addr_off + 1, " ");
        for (int i = 0; i < block_size - 1; i += 1) {
            display_printf("---");
        }
        display_printf("--\n");
    }

    size_t off = 0;
    while (off < size) {
        if (!raw_mode)
            display_printf(" %.*llx: ", addr_off, (u64_t)off + addr);
        int i;
        for (i = 0; i < block_size; ++i) {
            if (!raw_mode) {
                if (off + i >= size) {
                    for (; i < block_size; ++i)
                        display_printf("   ");
                    break;
                }
                display_printf("%02X ", bytes[off + i]);
            } else {
                if (off + i >= size)
                    break;
                display_printf("%02X", bytes[off + i]);
            }
        }
        if (!raw_mode) {
            display_printf("  ");
            for (i = 0; i < block_size; ++i) {
                if (off + i >= size)
                    break;
                display_printf(
                    "%c", get_printable_ascii_or_dot((u8_t)bytes[off + i]));
            }
            display_printf("\n");
        }
        off += block_size;
    }
    if (print_footer && raw_mode)
        display_printf("\n");
}

void print_words(const u8_t* bytes, size_t size, int little_endian,
                 int raw_mode, int print_header, int print_footer,
                 int row_width, u64_t addr)
{
    int block_size = row_width;
    if (row_width > 256 || row_width < 16 || row_width % 2 != 0)
        panic("print_words(): row_width must be in [16,256] and must be a "
              "multiple of 2 [%d]",
              row_width);

    u32_t addr_off = get_addr_string_size(addr + size);
    if (addr_off < 4)
        addr_off = 4;

    if (!raw_mode && print_header) {
        display_printf(" %*s ", addr_off + 1, " ");
        for (int i = 0; i < block_size; i += 2) {
            display_printf("%02X    ", i);
        }
        display_printf("\n %*s ", addr_off + 1, " ");
        for (int i = 0; i < block_size - 2; i += 2) {
            display_printf("------");
        }
        display_printf("-----\n");
    }

    size_t off = 0;
    while (off < size) {
        if (!raw_mode)
            display_printf(" %.*llx: ", addr_off, (u64_t)off + addr);
        int i;
        for (i = 0; i < block_size; i += 2) {
            if (off + i + 1 >= size)
                break;
            u16_t w = little_endian ? read_at_le16(bytes + off, i)
                                    : read_at_be16(bytes + off, i);
            if (!raw_mode)
                display_printf("%04Xh ", w);
            else
                display_printf("0x%04X ", w);
        }
        if (!raw_mode)
            display_printf("\n");
        off += block_size;
    }
    if (print_footer && raw_mode)
        display_printf("\n");
}

void print_dwords(const u8_t* bytes, size_t size, int little_endian,
                  int raw_mode, int print_header, int print_footer,
                  int row_width, u64_t addr)
{
    int block_size = row_width;
    if (row_width > 256 || row_width < 16 || row_width % 4 != 0)
        panic("print_dwords(): width must be in [16,256] and must be a "
              "multiple of 4");

    u32_t addr_off = get_addr_string_size(addr + size);
    if (addr_off < 4)
        addr_off = 4;

    if (!raw_mode && print_header) {
        display_printf(" %*s ", addr_off + 1, " ");
        for (int i = 0; i < block_size; i += 4) {
            display_printf("%02X        ", i);
        }
        display_printf("\n %*s ", addr_off + 1, " ");
        for (int i = 0; i < block_size - 4; i += 4) {
            display_printf("----------");
        }
        display_printf("---------\n");
    }

    size_t off = 0;
    while (off < size) {
        if (!raw_mode)
            display_printf(" %.*llx: ", addr_off, (u64_t)off + addr);
        int i;
        for (i = 0; i < block_size; i += 4) {
            if (off + i + 3 >= size)
                break;
            u32_t dw = little_endian ? read_at_le32(bytes + off, i)
                                     : read_at_be32(bytes + off, i);
            if (!raw_mode)
                display_printf("%08Xh ", dw);
            else
                display_printf("0x%08X ", dw);
        }
        if (!raw_mode)
            display_printf("\n");
        off += block_size;
    }
    if (print_footer && raw_mode)
        display_printf("\n");
}

void print_qwords(const u8_t* bytes, size_t size, int little_endian,
                  int raw_mode, int print_header, int print_footer,
                  int row_width, u64_t addr)
{
    int block_size = row_width;
    if (row_width > 256 || row_width < 16 || row_width % 8 != 0)
        panic("print_qwords(): row_width must be in [16,256] and must be a "
              "multiple of 8");

    u32_t addr_off = get_addr_string_size(addr + size);
    if (addr_off < 4)
        addr_off = 4;

    if (!raw_mode && print_header) {
        display_printf(" %*s ", addr_off + 1, " ");
        for (int i = 0; i < block_size; i += 8) {
            display_printf("%02X                ", i);
        }
        display_printf("\n %*s ", addr_off + 1, " ");
        for (int i = 0; i < block_size - 8; i += 8) {
            display_printf("------------------");
        }
        display_printf("-----------------\n");
    }

    size_t off = 0;
    while (off < size) {
        if (!raw_mode)
            display_printf(" %.*llx: ", addr_off, (u64_t)off + addr);
        int i;
        for (i = 0; i < block_size; i += 8) {
            if (off + i + 7 >= size)
                break;
            u64_t qw = little_endian ? read_at_le64(bytes + off, i)
                                     : read_at_be64(bytes + off, i);
            if (!raw_mode)
                display_printf("%016llXh ", qw);
            else
                display_printf("0x%016llX ", qw);
        }
        if (!raw_mode)
            display_printf("\n");
        off += block_size;
    }
    if (print_footer && raw_mode)
        display_printf("\n");
}
