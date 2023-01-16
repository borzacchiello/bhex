#ifndef TEMPLATE_ELF32_H
#define TEMPLATE_ELF32_H

#include "../../defs.h"

#define EI_NIDENT 16

typedef u16_t Elf32_Half;
typedef s16_t Elf32_SHalf;
typedef u32_t Elf32_Word;
typedef s32_t Elf32_Sword;
typedef u64_t Elf32_Xword;
typedef s64_t Elf32_Sxword;
typedef u32_t Elf32_Off;
typedef u32_t Elf32_Addr;
typedef u16_t Elf32_Section;

typedef struct Elf32_Ehdr {
    unsigned char e_ident[EI_NIDENT];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
} Elf32_Ehdr;

#endif
