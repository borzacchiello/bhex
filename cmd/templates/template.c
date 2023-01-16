
#include <stdio.h>
#include <stddef.h>
#include "../../defs.h"

#include "template.h"
#include "../util/byte_to_str.h"

#include "template_elf32.h"

static size_t sizeof_Elf32_Ehdr() { return sizeof(Elf32_Ehdr); }

static void prettyprint_Elf32_Ehdr(const u8_t* data, size_t size)
{
    if (size < sizeof_Elf32_Ehdr())
        return;

    char*             hexstr;
    const Elf32_Ehdr* s = (const Elf32_Ehdr*)data;
    printf("Elf32_Ehdr:\n");

    hexstr = bytes_to_hex(s->e_ident, sizeof(s->e_ident));
    printf("  %16s: %s\n", "e_ident", hexstr);
    free(hexstr);
    printf("  %16s: %-8u [0x%x]\n", "e_type", s->e_type, s->e_type);
    printf("  %16s: %-8u [0x%x]\n", "e_machine", s->e_machine, s->e_machine);
    printf("  %16s: %-8u [0x%x]\n", "e_version", s->e_version, s->e_version);
    printf("  %16s: %-8u [0x%x]\n", "e_entry", s->e_entry, s->e_entry);
    printf("  %16s: %-8u [0x%x]\n", "e_phoff", s->e_phoff, s->e_phoff);
    printf("  %16s: %-8u [0x%x]\n", "e_shoff", s->e_shoff, s->e_shoff);
    printf("  %16s: %-8u [0x%x]\n", "e_flags", s->e_flags, s->e_flags);
    printf("  %16s: %-8u [0x%x]\n", "e_ehsize", s->e_ehsize, s->e_ehsize);
    printf("  %16s: %-8u [0x%x]\n", "e_phentsize", s->e_phentsize,
           s->e_phentsize);
    printf("  %16s: %-8u [0x%x]\n", "e_phnum", s->e_phnum, s->e_phnum);
    printf("  %16s: %-8u [0x%x]\n", "e_shentsize", s->e_shentsize,
           s->e_shentsize);
    printf("  %16s: %-8u [0x%x]\n", "e_shnum", s->e_shnum, s->e_shnum);
    printf("  %16s: %-8u [0x%x]\n", "e_shstrndx", s->e_shstrndx, s->e_shstrndx);
}

#include "template_elf64.h"

static size_t sizeof_Elf64_Ehdr() { return sizeof(Elf64_Ehdr); }

static void prettyprint_Elf64_Ehdr(const u8_t* data, size_t size)
{
    if (size < sizeof_Elf64_Ehdr())
        return;

    char*             hexstr;
    const Elf64_Ehdr* s = (const Elf64_Ehdr*)data;
    printf("Elf64_Ehdr:\n");

    hexstr = bytes_to_hex(s->e_ident, sizeof(s->e_ident));
    printf("  %16s: %s\n", "e_ident", hexstr);
    free(hexstr);
    printf("  %16s: %-8u [0x%x]\n", "e_type", s->e_type, s->e_type);
    printf("  %16s: %-8u [0x%x]\n", "e_machine", s->e_machine, s->e_machine);
    printf("  %16s: %-8u [0x%x]\n", "e_version", s->e_version, s->e_version);
    printf("  %16s: %-8llu [0x%llx]\n", "e_entry", s->e_entry, s->e_entry);
    printf("  %16s: %-8llu [0x%llx]\n", "e_phoff", s->e_phoff, s->e_phoff);
    printf("  %16s: %-8llu [0x%llx]\n", "e_shoff", s->e_shoff, s->e_shoff);
    printf("  %16s: %-8u [0x%x]\n", "e_flags", s->e_flags, s->e_flags);
    printf("  %16s: %-8u [0x%x]\n", "e_ehsize", s->e_ehsize, s->e_ehsize);
    printf("  %16s: %-8u [0x%x]\n", "e_phentsize", s->e_phentsize,
           s->e_phentsize);
    printf("  %16s: %-8u [0x%x]\n", "e_phnum", s->e_phnum, s->e_phnum);
    printf("  %16s: %-8u [0x%x]\n", "e_shentsize", s->e_shentsize,
           s->e_shentsize);
    printf("  %16s: %-8u [0x%x]\n", "e_shnum", s->e_shnum, s->e_shnum);
    printf("  %16s: %-8u [0x%x]\n", "e_shstrndx", s->e_shstrndx, s->e_shstrndx);
}

Template templates[] = {
    {.name         = "Elf32_Ehdr",
     .get_size     = sizeof_Elf32_Ehdr,
     .pretty_print = prettyprint_Elf32_Ehdr},

    {.name         = "Elf64_Ehdr",
     .get_size     = sizeof_Elf64_Ehdr,
     .pretty_print = prettyprint_Elf64_Ehdr},

};
