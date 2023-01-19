#ifndef TEMPLATE_ELF64_H
#define TEMPLATE_ELF64_H

#ifdef CPARSER
#define __attribute__(x)
#else
#include "../../defs.h"
#endif

#define EI_NIDENT 16

typedef u64_t Elf64_Addr;
typedef u16_t Elf64_Half;
typedef u64_t Elf64_Off;
typedef s32_t Elf64_Sword;
typedef s64_t Elf64_Sxword;
typedef u32_t Elf64_Word;
typedef u64_t Elf64_Lword;
typedef u64_t Elf64_Xword;

typedef struct Elf64_Ehdr {
    unsigned char e_ident[EI_NIDENT]; /* File identification. */
    Elf64_Half    e_type;             /* File type. */
    Elf64_Half    e_machine;          /* Machine architecture. */
    Elf64_Word    e_version;          /* ELF format version. */
    Elf64_Addr    e_entry;            /* Entry point. */
    Elf64_Off     e_phoff;            /* Program header file offset. */
    Elf64_Off     e_shoff;            /* Section header file offset. */
    Elf64_Word    e_flags;            /* Architecture-specific flags. */
    Elf64_Half    e_ehsize;           /* Size of ELF header in bytes. */
    Elf64_Half    e_phentsize;        /* Size of program header entry. */
    Elf64_Half    e_phnum;            /* Number of program header entries. */
    Elf64_Half    e_shentsize;        /* Size of section header entry. */
    Elf64_Half    e_shnum;            /* Number of section header entries. */
    Elf64_Half    e_shstrndx;         /* Section name strings section. */
} Elf64_Ehdr;

#endif
