
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

    __attribute__((unused)) char* hexstr;
    const Elf32_Ehdr*             s = (const Elf32_Ehdr*)data;
    printf("Elf32_Ehdr: (size: %lu)\n", sizeof(Elf32_Ehdr));

    hexstr = bytes_to_hex((u8_t*)s->e_ident, sizeof(s->e_ident));
    printf("  b+%lu %11s: %s\n", offsetof(Elf32_Ehdr, e_ident), "e_ident",
           hexstr);
    free(hexstr);
    {
        unsigned short v = le ? read_le16(&s->e_type) : read_be16(&s->e_type);
        printf("  b+%lu %11s: %-12u [0x%x]\n", offsetof(Elf32_Ehdr, e_type),
               "e_type", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_machine) : read_be16(&s->e_machine);
        printf("  b+%lu %11s: %-12u [0x%x]\n", offsetof(Elf32_Ehdr, e_machine),
               "e_machine", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->e_version) : read_be32(&s->e_version);
        printf("  b+%lu %11s: %-12u [0x%x]\n", offsetof(Elf32_Ehdr, e_version),
               "e_version", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_entry) : read_be32(&s->e_entry);
        printf("  b+%lu %11s: %-12u [0x%x]\n", offsetof(Elf32_Ehdr, e_entry),
               "e_entry", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_phoff) : read_be32(&s->e_phoff);
        printf("  b+%lu %11s: %-12u [0x%x]\n", offsetof(Elf32_Ehdr, e_phoff),
               "e_phoff", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_shoff) : read_be32(&s->e_shoff);
        printf("  b+%lu %11s: %-12u [0x%x]\n", offsetof(Elf32_Ehdr, e_shoff),
               "e_shoff", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_flags) : read_be32(&s->e_flags);
        printf("  b+%lu %11s: %-12u [0x%x]\n", offsetof(Elf32_Ehdr, e_flags),
               "e_flags", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_ehsize) : read_be16(&s->e_ehsize);
        printf("  b+%lu %11s: %-12u [0x%x]\n", offsetof(Elf32_Ehdr, e_ehsize),
               "e_ehsize", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_phentsize) : read_be16(&s->e_phentsize);
        printf("  b+%lu %11s: %-12u [0x%x]\n",
               offsetof(Elf32_Ehdr, e_phentsize), "e_phentsize", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_phnum) : read_be16(&s->e_phnum);
        printf("  b+%lu %11s: %-12u [0x%x]\n", offsetof(Elf32_Ehdr, e_phnum),
               "e_phnum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_shentsize) : read_be16(&s->e_shentsize);
        printf("  b+%lu %11s: %-12u [0x%x]\n",
               offsetof(Elf32_Ehdr, e_shentsize), "e_shentsize", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_shnum) : read_be16(&s->e_shnum);
        printf("  b+%lu %11s: %-12u [0x%x]\n", offsetof(Elf32_Ehdr, e_shnum),
               "e_shnum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_shstrndx) : read_be16(&s->e_shstrndx);
        printf("  b+%lu %11s: %-12u [0x%x]\n", offsetof(Elf32_Ehdr, e_shstrndx),
               "e_shstrndx", v, v);
    }
}

#include "template_elf64.h"

static size_t sizeof_Elf64_Ehdr() { return sizeof(Elf64_Ehdr); }

static void prettyprint_Elf64_Ehdr(const u8_t* data, size_t size, int le)
{
    if (size < sizeof_Elf64_Ehdr())
        return;

    __attribute__((unused)) char* hexstr;
    const Elf64_Ehdr*             s = (const Elf64_Ehdr*)data;
    printf("Elf64_Ehdr: (size: %lu)\n", sizeof(Elf64_Ehdr));

    hexstr = bytes_to_hex((u8_t*)s->e_ident, sizeof(s->e_ident));
    printf("  b+%lu %11s: %s\n", offsetof(Elf64_Ehdr, e_ident), "e_ident",
           hexstr);
    free(hexstr);
    {
        unsigned short v = le ? read_le16(&s->e_type) : read_be16(&s->e_type);
        printf("  b+%lu %11s: %-12u [0x%x]\n", offsetof(Elf64_Ehdr, e_type),
               "e_type", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_machine) : read_be16(&s->e_machine);
        printf("  b+%lu %11s: %-12u [0x%x]\n", offsetof(Elf64_Ehdr, e_machine),
               "e_machine", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->e_version) : read_be32(&s->e_version);
        printf("  b+%lu %11s: %-12u [0x%x]\n", offsetof(Elf64_Ehdr, e_version),
               "e_version", v, v);
    }
    {
        unsigned long long v =
            le ? read_le64(&s->e_entry) : read_be64(&s->e_entry);
        printf("  b+%lu %11s: %-12llu [0x%llx]\n",
               offsetof(Elf64_Ehdr, e_entry), "e_entry", v, v);
    }
    {
        unsigned long long v =
            le ? read_le64(&s->e_phoff) : read_be64(&s->e_phoff);
        printf("  b+%lu %11s: %-12llu [0x%llx]\n",
               offsetof(Elf64_Ehdr, e_phoff), "e_phoff", v, v);
    }
    {
        unsigned long long v =
            le ? read_le64(&s->e_shoff) : read_be64(&s->e_shoff);
        printf("  b+%lu %11s: %-12llu [0x%llx]\n",
               offsetof(Elf64_Ehdr, e_shoff), "e_shoff", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_flags) : read_be32(&s->e_flags);
        printf("  b+%lu %11s: %-12u [0x%x]\n", offsetof(Elf64_Ehdr, e_flags),
               "e_flags", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_ehsize) : read_be16(&s->e_ehsize);
        printf("  b+%lu %11s: %-12u [0x%x]\n", offsetof(Elf64_Ehdr, e_ehsize),
               "e_ehsize", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_phentsize) : read_be16(&s->e_phentsize);
        printf("  b+%lu %11s: %-12u [0x%x]\n",
               offsetof(Elf64_Ehdr, e_phentsize), "e_phentsize", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_phnum) : read_be16(&s->e_phnum);
        printf("  b+%lu %11s: %-12u [0x%x]\n", offsetof(Elf64_Ehdr, e_phnum),
               "e_phnum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_shentsize) : read_be16(&s->e_shentsize);
        printf("  b+%lu %11s: %-12u [0x%x]\n",
               offsetof(Elf64_Ehdr, e_shentsize), "e_shentsize", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_shnum) : read_be16(&s->e_shnum);
        printf("  b+%lu %11s: %-12u [0x%x]\n", offsetof(Elf64_Ehdr, e_shnum),
               "e_shnum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_shstrndx) : read_be16(&s->e_shstrndx);
        printf("  b+%lu %11s: %-12u [0x%x]\n", offsetof(Elf64_Ehdr, e_shstrndx),
               "e_shstrndx", v, v);
    }
}

#include "template_pe.h"

static size_t sizeof_IMAGE_DOS_HEADER() { return sizeof(IMAGE_DOS_HEADER); }

static void prettyprint_IMAGE_DOS_HEADER(const u8_t* data, size_t size, int le)
{
    if (size < sizeof_IMAGE_DOS_HEADER())
        return;

    __attribute__((unused)) char* hexstr;
    const IMAGE_DOS_HEADER*       s = (const IMAGE_DOS_HEADER*)data;
    printf("IMAGE_DOS_HEADER: (size: %lu)\n", sizeof(IMAGE_DOS_HEADER));

    {
        unsigned short v = le ? read_le16(&s->e_magic) : read_be16(&s->e_magic);
        printf("  b+%lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_magic), "e_magic", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_cblp) : read_be16(&s->e_cblp);
        printf("  b+%lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_cblp), "e_cblp", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_cp) : read_be16(&s->e_cp);
        printf("  b+%lu %10s: %-12u [0x%x]\n", offsetof(IMAGE_DOS_HEADER, e_cp),
               "e_cp", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_crlc) : read_be16(&s->e_crlc);
        printf("  b+%lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_crlc), "e_crlc", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_cparhdr) : read_be16(&s->e_cparhdr);
        printf("  b+%lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_cparhdr), "e_cparhdr", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_minalloc) : read_be16(&s->e_minalloc);
        printf("  b+%lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_minalloc), "e_minalloc", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_maxalloc) : read_be16(&s->e_maxalloc);
        printf("  b+%lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_maxalloc), "e_maxalloc", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_ss) : read_be16(&s->e_ss);
        printf("  b+%lu %10s: %-12u [0x%x]\n", offsetof(IMAGE_DOS_HEADER, e_ss),
               "e_ss", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_sp) : read_be16(&s->e_sp);
        printf("  b+%lu %10s: %-12u [0x%x]\n", offsetof(IMAGE_DOS_HEADER, e_sp),
               "e_sp", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_csum) : read_be16(&s->e_csum);
        printf("  b+%lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_csum), "e_csum", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_ip) : read_be16(&s->e_ip);
        printf("  b+%lu %10s: %-12u [0x%x]\n", offsetof(IMAGE_DOS_HEADER, e_ip),
               "e_ip", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_cs) : read_be16(&s->e_cs);
        printf("  b+%lu %10s: %-12u [0x%x]\n", offsetof(IMAGE_DOS_HEADER, e_cs),
               "e_cs", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_lfarlc) : read_be16(&s->e_lfarlc);
        printf("  b+%lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_lfarlc), "e_lfarlc", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_ovno) : read_be16(&s->e_ovno);
        printf("  b+%lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_ovno), "e_ovno", v, v);
    }
    hexstr = bytes_to_hex((u8_t*)s->e_res, sizeof(s->e_res));
    printf("  b+%lu %10s: %s\n", offsetof(IMAGE_DOS_HEADER, e_res), "e_res",
           hexstr);
    free(hexstr);
    {
        unsigned short v = le ? read_le16(&s->e_oemid) : read_be16(&s->e_oemid);
        printf("  b+%lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_oemid), "e_oemid", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_oeminfo) : read_be16(&s->e_oeminfo);
        printf("  b+%lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_oeminfo), "e_oeminfo", v, v);
    }
    hexstr = bytes_to_hex((u8_t*)s->e_res2, sizeof(s->e_res2));
    printf("  b+%lu %10s: %s\n", offsetof(IMAGE_DOS_HEADER, e_res2), "e_res2",
           hexstr);
    free(hexstr);
    {
        int v = le ? read_le32(&s->e_lfanew) : read_be32(&s->e_lfanew);
        printf("  b+%lu %10s: %-12d [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_lfanew), "e_lfanew", v, v);
    }
}

#include "template_pe.h"

static size_t sizeof_IMAGE_NT_HEADERS64() { return sizeof(IMAGE_NT_HEADERS64); }

static void prettyprint_IMAGE_NT_HEADERS64(const u8_t* data, size_t size,
                                           int le)
{
    if (size < sizeof_IMAGE_NT_HEADERS64())
        return;

    __attribute__((unused)) char* hexstr;
    const IMAGE_NT_HEADERS64*     s = (const IMAGE_NT_HEADERS64*)data;
    printf("IMAGE_NT_HEADERS64: (size: %lu)\n", sizeof(IMAGE_NT_HEADERS64));

    {
        unsigned int v =
            le ? read_le32(&s->Signature) : read_be32(&s->Signature);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, Signature), "Signature", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->Machine) : read_be16(&s->Machine);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, Machine), "Machine", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->NumberOfSections)
                              : read_be16(&s->NumberOfSections);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, NumberOfSections),
               "NumberOfSections", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->TimeDateStamp) : read_be32(&s->TimeDateStamp);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, TimeDateStamp), "TimeDateStamp", v,
               v);
    }
    {
        unsigned int v = le ? read_le32(&s->PointerToSymbolTable)
                            : read_be32(&s->PointerToSymbolTable);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, PointerToSymbolTable),
               "PointerToSymbolTable", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->NumberOfSymbols)
                            : read_be32(&s->NumberOfSymbols);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, NumberOfSymbols), "NumberOfSymbols",
               v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->SizeOfOptionalHeader)
                              : read_be16(&s->SizeOfOptionalHeader);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfOptionalHeader),
               "SizeOfOptionalHeader", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->Characteristics)
                              : read_be16(&s->Characteristics);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, Characteristics), "Characteristics",
               v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->Magic) : read_be16(&s->Magic);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, Magic), "Magic", v, v);
    }
    {
        unsigned char v =
            le ? read8(&s->MajorLinkerVersion) : read8(&s->MajorLinkerVersion);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, MajorLinkerVersion),
               "MajorLinkerVersion", v, v);
    }
    {
        unsigned char v =
            le ? read8(&s->MinorLinkerVersion) : read8(&s->MinorLinkerVersion);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, MinorLinkerVersion),
               "MinorLinkerVersion", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->SizeOfCode) : read_be32(&s->SizeOfCode);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfCode), "SizeOfCode", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfInitializedData)
                            : read_be32(&s->SizeOfInitializedData);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfInitializedData),
               "SizeOfInitializedData", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfUninitializedData)
                            : read_be32(&s->SizeOfUninitializedData);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfUninitializedData),
               "SizeOfUninitializedData", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->AddressOfEntryPoint)
                            : read_be32(&s->AddressOfEntryPoint);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, AddressOfEntryPoint),
               "AddressOfEntryPoint", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->BaseOfCode) : read_be32(&s->BaseOfCode);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, BaseOfCode), "BaseOfCode", v, v);
    }
    {
        unsigned long long v =
            le ? read_le64(&s->ImageBase) : read_be64(&s->ImageBase);
        printf("  b+%lu %27s: %-12llu [0x%llx]\n",
               offsetof(IMAGE_NT_HEADERS64, ImageBase), "ImageBase", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SectionAlignment)
                            : read_be32(&s->SectionAlignment);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, SectionAlignment),
               "SectionAlignment", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->FileAlignment) : read_be32(&s->FileAlignment);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, FileAlignment), "FileAlignment", v,
               v);
    }
    {
        unsigned short v = le ? read_le16(&s->MajorOperatingSystemVersion)
                              : read_be16(&s->MajorOperatingSystemVersion);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, MajorOperatingSystemVersion),
               "MajorOperatingSystemVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MinorOperatingSystemVersion)
                              : read_be16(&s->MinorOperatingSystemVersion);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, MinorOperatingSystemVersion),
               "MinorOperatingSystemVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MajorImageVersion)
                              : read_be16(&s->MajorImageVersion);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, MajorImageVersion),
               "MajorImageVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MinorImageVersion)
                              : read_be16(&s->MinorImageVersion);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, MinorImageVersion),
               "MinorImageVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MajorSubsystemVersion)
                              : read_be16(&s->MajorSubsystemVersion);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, MajorSubsystemVersion),
               "MajorSubsystemVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MinorSubsystemVersion)
                              : read_be16(&s->MinorSubsystemVersion);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, MinorSubsystemVersion),
               "MinorSubsystemVersion", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->Win32VersionValue)
                            : read_be32(&s->Win32VersionValue);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, Win32VersionValue),
               "Win32VersionValue", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->SizeOfImage) : read_be32(&s->SizeOfImage);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfImage), "SizeOfImage", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->SizeOfHeaders) : read_be32(&s->SizeOfHeaders);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfHeaders), "SizeOfHeaders", v,
               v);
    }
    {
        unsigned int v = le ? read_le32(&s->CheckSum) : read_be32(&s->CheckSum);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, CheckSum), "CheckSum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->Subsystem) : read_be16(&s->Subsystem);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, Subsystem), "Subsystem", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->DllCharacteristics)
                              : read_be16(&s->DllCharacteristics);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, DllCharacteristics),
               "DllCharacteristics", v, v);
    }
    {
        unsigned long long v = le ? read_le64(&s->SizeOfStackReserve)
                                  : read_be64(&s->SizeOfStackReserve);
        printf("  b+%lu %27s: %-12llu [0x%llx]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfStackReserve),
               "SizeOfStackReserve", v, v);
    }
    {
        unsigned long long v = le ? read_le64(&s->SizeOfStackCommit)
                                  : read_be64(&s->SizeOfStackCommit);
        printf("  b+%lu %27s: %-12llu [0x%llx]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfStackCommit),
               "SizeOfStackCommit", v, v);
    }
    {
        unsigned long long v = le ? read_le64(&s->SizeOfHeapReserve)
                                  : read_be64(&s->SizeOfHeapReserve);
        printf("  b+%lu %27s: %-12llu [0x%llx]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfHeapReserve),
               "SizeOfHeapReserve", v, v);
    }
    {
        unsigned long long v = le ? read_le64(&s->SizeOfHeapCommit)
                                  : read_be64(&s->SizeOfHeapCommit);
        printf("  b+%lu %27s: %-12llu [0x%llx]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfHeapCommit),
               "SizeOfHeapCommit", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->LoaderFlags) : read_be32(&s->LoaderFlags);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, LoaderFlags), "LoaderFlags", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->NumberOfRvaAndSizes)
                            : read_be32(&s->NumberOfRvaAndSizes);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, NumberOfRvaAndSizes),
               "NumberOfRvaAndSizes", v, v);
    }
}

#include "template_pe.h"

static size_t sizeof_IMAGE_NT_HEADERS32() { return sizeof(IMAGE_NT_HEADERS32); }

static void prettyprint_IMAGE_NT_HEADERS32(const u8_t* data, size_t size,
                                           int le)
{
    if (size < sizeof_IMAGE_NT_HEADERS32())
        return;

    __attribute__((unused)) char* hexstr;
    const IMAGE_NT_HEADERS32*     s = (const IMAGE_NT_HEADERS32*)data;
    printf("IMAGE_NT_HEADERS32: (size: %lu)\n", sizeof(IMAGE_NT_HEADERS32));

    {
        unsigned int v =
            le ? read_le32(&s->Signature) : read_be32(&s->Signature);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, Signature), "Signature", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->Machine) : read_be16(&s->Machine);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, Machine), "Machine", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->NumberOfSections)
                              : read_be16(&s->NumberOfSections);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, NumberOfSections),
               "NumberOfSections", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->TimeDateStamp) : read_be32(&s->TimeDateStamp);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, TimeDateStamp), "TimeDateStamp", v,
               v);
    }
    {
        unsigned int v = le ? read_le32(&s->PointerToSymbolTable)
                            : read_be32(&s->PointerToSymbolTable);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, PointerToSymbolTable),
               "PointerToSymbolTable", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->NumberOfSymbols)
                            : read_be32(&s->NumberOfSymbols);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, NumberOfSymbols), "NumberOfSymbols",
               v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->SizeOfOptionalHeader)
                              : read_be16(&s->SizeOfOptionalHeader);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfOptionalHeader),
               "SizeOfOptionalHeader", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->Characteristics)
                              : read_be16(&s->Characteristics);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, Characteristics), "Characteristics",
               v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->Magic) : read_be16(&s->Magic);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, Magic), "Magic", v, v);
    }
    {
        unsigned char v =
            le ? read8(&s->MajorLinkerVersion) : read8(&s->MajorLinkerVersion);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, MajorLinkerVersion),
               "MajorLinkerVersion", v, v);
    }
    {
        unsigned char v =
            le ? read8(&s->MinorLinkerVersion) : read8(&s->MinorLinkerVersion);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, MinorLinkerVersion),
               "MinorLinkerVersion", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->SizeOfCode) : read_be32(&s->SizeOfCode);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfCode), "SizeOfCode", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfInitializedData)
                            : read_be32(&s->SizeOfInitializedData);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfInitializedData),
               "SizeOfInitializedData", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfUninitializedData)
                            : read_be32(&s->SizeOfUninitializedData);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfUninitializedData),
               "SizeOfUninitializedData", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->AddressOfEntryPoint)
                            : read_be32(&s->AddressOfEntryPoint);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, AddressOfEntryPoint),
               "AddressOfEntryPoint", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->BaseOfCode) : read_be32(&s->BaseOfCode);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, BaseOfCode), "BaseOfCode", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->BaseOfData) : read_be32(&s->BaseOfData);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, BaseOfData), "BaseOfData", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->ImageBase) : read_be32(&s->ImageBase);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, ImageBase), "ImageBase", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SectionAlignment)
                            : read_be32(&s->SectionAlignment);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SectionAlignment),
               "SectionAlignment", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->FileAlignment) : read_be32(&s->FileAlignment);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, FileAlignment), "FileAlignment", v,
               v);
    }
    {
        unsigned short v = le ? read_le16(&s->MajorOperatingSystemVersion)
                              : read_be16(&s->MajorOperatingSystemVersion);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, MajorOperatingSystemVersion),
               "MajorOperatingSystemVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MinorOperatingSystemVersion)
                              : read_be16(&s->MinorOperatingSystemVersion);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, MinorOperatingSystemVersion),
               "MinorOperatingSystemVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MajorImageVersion)
                              : read_be16(&s->MajorImageVersion);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, MajorImageVersion),
               "MajorImageVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MinorImageVersion)
                              : read_be16(&s->MinorImageVersion);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, MinorImageVersion),
               "MinorImageVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MajorSubsystemVersion)
                              : read_be16(&s->MajorSubsystemVersion);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, MajorSubsystemVersion),
               "MajorSubsystemVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MinorSubsystemVersion)
                              : read_be16(&s->MinorSubsystemVersion);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, MinorSubsystemVersion),
               "MinorSubsystemVersion", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->Win32VersionValue)
                            : read_be32(&s->Win32VersionValue);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, Win32VersionValue),
               "Win32VersionValue", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->SizeOfImage) : read_be32(&s->SizeOfImage);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfImage), "SizeOfImage", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->SizeOfHeaders) : read_be32(&s->SizeOfHeaders);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfHeaders), "SizeOfHeaders", v,
               v);
    }
    {
        unsigned int v = le ? read_le32(&s->CheckSum) : read_be32(&s->CheckSum);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, CheckSum), "CheckSum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->Subsystem) : read_be16(&s->Subsystem);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, Subsystem), "Subsystem", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->DllCharacteristics)
                              : read_be16(&s->DllCharacteristics);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, DllCharacteristics),
               "DllCharacteristics", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfStackReserve)
                            : read_be32(&s->SizeOfStackReserve);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfStackReserve),
               "SizeOfStackReserve", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfStackCommit)
                            : read_be32(&s->SizeOfStackCommit);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfStackCommit),
               "SizeOfStackCommit", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfHeapReserve)
                            : read_be32(&s->SizeOfHeapReserve);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfHeapReserve),
               "SizeOfHeapReserve", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfHeapCommit)
                            : read_be32(&s->SizeOfHeapCommit);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfHeapCommit),
               "SizeOfHeapCommit", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->LoaderFlags) : read_be32(&s->LoaderFlags);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, LoaderFlags), "LoaderFlags", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->NumberOfRvaAndSizes)
                            : read_be32(&s->NumberOfRvaAndSizes);
        printf("  b+%lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, NumberOfRvaAndSizes),
               "NumberOfRvaAndSizes", v, v);
    }
}

Template templates[] = {
    {.name         = "Elf32_Ehdr",
     .get_size     = sizeof_Elf32_Ehdr,
     .pretty_print = prettyprint_Elf32_Ehdr},

    {.name         = "Elf64_Ehdr",
     .get_size     = sizeof_Elf64_Ehdr,
     .pretty_print = prettyprint_Elf64_Ehdr},

    {.name         = "IMAGE_DOS_HEADER",
     .get_size     = sizeof_IMAGE_DOS_HEADER,
     .pretty_print = prettyprint_IMAGE_DOS_HEADER},

    {.name         = "IMAGE_NT_HEADERS64",
     .get_size     = sizeof_IMAGE_NT_HEADERS64,
     .pretty_print = prettyprint_IMAGE_NT_HEADERS64},

    {.name         = "IMAGE_NT_HEADERS32",
     .get_size     = sizeof_IMAGE_NT_HEADERS32,
     .pretty_print = prettyprint_IMAGE_NT_HEADERS32},

};
