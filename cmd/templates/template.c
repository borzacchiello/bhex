
#include <stdio.h>
#include <stddef.h>
#include "../../defs.h"

#include "template.h"
#include "../util/byte_to_str.h"
#include "../util/endian.h"

#include "template_elf32.h"

static size_t sizeof_Elf32_Ehdr() { return sizeof(Elf32_Ehdr); }

static void prettyprint_Elf32_Ehdr(const u8_t* data, size_t size, int le)
{
    if (size < sizeof_Elf32_Ehdr())
        return;

    char*             hexstr;
    const Elf32_Ehdr* s = (const Elf32_Ehdr*)data;
    printf("Elf32_Ehdr:\n");

    hexstr = bytes_to_hex(s->e_ident, sizeof(s->e_ident));
    printf("  %16s: %s\n", "e_ident", hexstr);
    free(hexstr);
    {
        unsigned short v = le ? read_le16(&s->e_type) : read_be16(&s->e_type);
        printf("  %16s: %-12u [0x%x]\n", "e_type", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_machine) : read_be16(&s->e_machine);
        printf("  %16s: %-12u [0x%x]\n", "e_machine", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->e_version) : read_be32(&s->e_version);
        printf("  %16s: %-12u [0x%x]\n", "e_version", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_entry) : read_be32(&s->e_entry);
        printf("  %16s: %-12u [0x%x]\n", "e_entry", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_phoff) : read_be32(&s->e_phoff);
        printf("  %16s: %-12u [0x%x]\n", "e_phoff", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_shoff) : read_be32(&s->e_shoff);
        printf("  %16s: %-12u [0x%x]\n", "e_shoff", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_flags) : read_be32(&s->e_flags);
        printf("  %16s: %-12u [0x%x]\n", "e_flags", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_ehsize) : read_be16(&s->e_ehsize);
        printf("  %16s: %-12u [0x%x]\n", "e_ehsize", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_phentsize) : read_be16(&s->e_phentsize);
        printf("  %16s: %-12u [0x%x]\n", "e_phentsize", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_phnum) : read_be16(&s->e_phnum);
        printf("  %16s: %-12u [0x%x]\n", "e_phnum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_shentsize) : read_be16(&s->e_shentsize);
        printf("  %16s: %-12u [0x%x]\n", "e_shentsize", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_shnum) : read_be16(&s->e_shnum);
        printf("  %16s: %-12u [0x%x]\n", "e_shnum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_shstrndx) : read_be16(&s->e_shstrndx);
        printf("  %16s: %-12u [0x%x]\n", "e_shstrndx", v, v);
    }
}

#include "template_elf64.h"

static size_t sizeof_Elf64_Ehdr() { return sizeof(Elf64_Ehdr); }

static void prettyprint_Elf64_Ehdr(const u8_t* data, size_t size, int le)
{
    if (size < sizeof_Elf64_Ehdr())
        return;

    char*             hexstr;
    const Elf64_Ehdr* s = (const Elf64_Ehdr*)data;
    printf("Elf64_Ehdr:\n");

    hexstr = bytes_to_hex(s->e_ident, sizeof(s->e_ident));
    printf("  %16s: %s\n", "e_ident", hexstr);
    free(hexstr);
    {
        unsigned short v = le ? read_le16(&s->e_type) : read_be16(&s->e_type);
        printf("  %16s: %-12u [0x%x]\n", "e_type", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_machine) : read_be16(&s->e_machine);
        printf("  %16s: %-12u [0x%x]\n", "e_machine", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->e_version) : read_be32(&s->e_version);
        printf("  %16s: %-12u [0x%x]\n", "e_version", v, v);
    }
    {
        unsigned long long v =
            le ? read_le64(&s->e_entry) : read_be64(&s->e_entry);
        printf("  %16s: %-12llu [0x%llx]\n", "e_entry", v, v);
    }
    {
        unsigned long long v =
            le ? read_le64(&s->e_phoff) : read_be64(&s->e_phoff);
        printf("  %16s: %-12llu [0x%llx]\n", "e_phoff", v, v);
    }
    {
        unsigned long long v =
            le ? read_le64(&s->e_shoff) : read_be64(&s->e_shoff);
        printf("  %16s: %-12llu [0x%llx]\n", "e_shoff", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_flags) : read_be32(&s->e_flags);
        printf("  %16s: %-12u [0x%x]\n", "e_flags", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_ehsize) : read_be16(&s->e_ehsize);
        printf("  %16s: %-12u [0x%x]\n", "e_ehsize", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_phentsize) : read_be16(&s->e_phentsize);
        printf("  %16s: %-12u [0x%x]\n", "e_phentsize", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_phnum) : read_be16(&s->e_phnum);
        printf("  %16s: %-12u [0x%x]\n", "e_phnum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_shentsize) : read_be16(&s->e_shentsize);
        printf("  %16s: %-12u [0x%x]\n", "e_shentsize", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_shnum) : read_be16(&s->e_shnum);
        printf("  %16s: %-12u [0x%x]\n", "e_shnum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_shstrndx) : read_be16(&s->e_shstrndx);
        printf("  %16s: %-12u [0x%x]\n", "e_shstrndx", v, v);
    }
}

Template templates[] = {
    {.name         = "Elf32_Ehdr",
     .get_size     = sizeof_Elf32_Ehdr,
     .pretty_print = prettyprint_Elf32_Ehdr},

    {.name         = "Elf64_Ehdr",
     .get_size     = sizeof_Elf64_Ehdr,
     .pretty_print = prettyprint_Elf64_Ehdr},

};
