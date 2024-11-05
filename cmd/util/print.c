#include "print.h"
#include "endian.h"
#include "byte_to_str.h"

#include <stdio.h>

void print_ascii(const u8_t* bytes, size_t size, int print_header,
                        int print_footer)
{
    size_t last_newline_off = 0, off = 0, linenum = 0;
    for (off = 0; off < size; off++) {
        if (bytes[off] == '\n')
            last_newline_off = off;
    }

    if (print_header)
        puts("");
    printf("%03lu: ", ++linenum);
    off = 0;
    while (off < last_newline_off) {
        if (is_printable_ascii(bytes[off]) || bytes[off] == '\t' ||
            bytes[off] == '\n')
            printf("%c", bytes[off]);
        else
            printf(".");
        if (bytes[off] == '\n') {
            printf("%03lu: ", ++linenum);
        }
        off += 1;
    }
    if (print_footer)
        printf("\n\n");
}

void print_c_buffer(const u8_t* bytes, size_t size, int print_header,
                           int print_footer)
{
    if (size == 0)
        return;

    size_t i = 0;
    if (print_header) {
        printf("{ 0x%02x", bytes[0]);
        i = 1;
    }
    for (; i < size; ++i)
        printf(", 0x%02x", bytes[i]);
    if (print_footer)
        printf(" }\n");
}

void print_hex(const u8_t* bytes, size_t size, int raw_mode,
                      int print_header, int print_footer, u64_t addr)
{
    int block_size = 16;
    size_t     off        = 0;

    if (!raw_mode && print_header)
        printf("\n"
               "       00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
               "       -----------------------------------------------\n");
    while (off < size) {
        if (!raw_mode)
            printf(" %04llx: ", (u64_t)off + addr);
        int i;
        for (i = 0; i < block_size; ++i) {
            if (!raw_mode) {
                if (off + i >= size) {
                    for (; i < block_size; ++i)
                        printf("   ");
                    break;
                }
                printf("%02X ", bytes[off + i]);
            } else {
                printf("%02X", bytes[off + i]);
            }
        }
        if (!raw_mode) {
            printf("  ");
            for (i = 0; i < block_size; ++i) {
                if (off + i >= size)
                    break;
                printf("%c", get_printable_ascii_or_dot((u8_t)bytes[off + i]));
            }
            printf("\n");
        }
        off += block_size;
    }
    if (print_footer)
        printf("\n");
}

void print_words(const u8_t* bytes, size_t size, int little_endian,
                        int raw_mode, int print_header, int print_footer,
                        u64_t addr)
{
    int block_size = 16;
    size_t     off        = 0;

    if (!raw_mode && print_header)
        printf("\n"
               "       00    02    04    06    08    0A    0C    0E   \n"
               "       -----------------------------------------------\n");
    while (off < size) {
        if (!raw_mode)
            printf(" %04llx: ", (u64_t)off + addr);
        int i;
        for (i = 0; i < block_size; i += 2) {
            if (off + i + 1 >= size)
                break;
            u16_t w = little_endian ? read_at_le16(bytes + off, i)
                                    : read_at_be16(bytes + off, i);
            if (!raw_mode)
                printf("%04Xh ", w);
            else
                printf("0x%04X ", w);
        }
        if (!raw_mode)
            printf("\n");
        off += block_size;
    }
    if (print_footer)
        printf("\n");
}

void print_dwords(const u8_t* bytes, size_t size, int little_endian,
                         int raw_mode, int print_header, int print_footer,
                         u64_t addr)
{
    int block_size = 16;
    size_t     off        = 0;

    if (!raw_mode && print_header)
        printf("\n"
               "       00        04        08        0C       \n"
               "       ---------------------------------------\n");
    while (off < size) {
        if (!raw_mode)
            printf(" %04llx: ", (u64_t)off + addr);
        int i;
        for (i = 0; i < block_size; i += 4) {
            if (off + i + 3 >= size)
                break;
            u32_t dw = little_endian ? read_at_le32(bytes + off, i)
                                     : read_at_be32(bytes + off, i);
            if (!raw_mode)
                printf("%08Xh ", dw);
            else
                printf("0x%08X ", dw);
        }
        if (!raw_mode)
            printf("\n");
        off += block_size;
    }
    if (print_footer)
        printf("\n");
}

void print_qwords(const u8_t* bytes, size_t size, int little_endian,
                         int raw_mode, int print_header, int print_footer,
                         u64_t addr)
{
    int block_size = 16;
    size_t     off        = 0;

    if (!raw_mode && print_header)
        printf("\n"
               "       00                08               \n"
               "       -----------------------------------\n");
    while (off < size) {
        if (!raw_mode)
            printf(" %04llx: ", (u64_t)off + addr);
        int i;
        for (i = 0; i < block_size; i += 8) {
            if (off + i + 7 >= size)
                break;
            u64_t dw = little_endian ? read_at_le64(bytes + off, i)
                                     : read_at_be64(bytes + off, i);
            if (!raw_mode)
                printf("%016llXh ", dw);
            else
                printf("0x%016llX ", dw);
        }
        if (!raw_mode)
            printf("\n");
        off += block_size;
    }
    if (print_footer)
        printf("\n");
}
