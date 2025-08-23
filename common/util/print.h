#include <stdlib.h>

#include <defs.h>

void print_ascii(const u8_t* bytes, size_t size, int print_footer);
void print_c_buffer(const u8_t* bytes, size_t size, int print_header,
                    int print_footer);
void print_hex(const u8_t* bytes, size_t size, int raw_mode, int print_header,
               int print_footer, u64_t addr);
void print_words(const u8_t* bytes, size_t size, int little_endian,
                 int raw_mode, int print_header, int print_footer, u64_t addr);
void print_dwords(const u8_t* bytes, size_t size, int little_endian,
                  int raw_mode, int print_header, int print_footer, u64_t addr);
void print_qwords(const u8_t* bytes, size_t size, int little_endian,
                  int raw_mode, int print_header, int print_footer, u64_t addr);
