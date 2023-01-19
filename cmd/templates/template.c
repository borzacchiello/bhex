
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
    printf("Elf32_Ehdr: (%lu)\n", sizeof(Elf32_Ehdr));

    hexstr = bytes_to_hex((u8_t*)s->e_ident, sizeof(s->e_ident));
    printf("  %11s: %s\n", "e_ident", hexstr);
    free(hexstr);
    {
        unsigned short v = le ? read_le16(&s->e_type) : read_be16(&s->e_type);
        printf("  %11s: %-12u [0x%x]\n", "e_type", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_machine) : read_be16(&s->e_machine);
        printf("  %11s: %-12u [0x%x]\n", "e_machine", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->e_version) : read_be32(&s->e_version);
        printf("  %11s: %-12u [0x%x]\n", "e_version", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_entry) : read_be32(&s->e_entry);
        printf("  %11s: %-12u [0x%x]\n", "e_entry", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_phoff) : read_be32(&s->e_phoff);
        printf("  %11s: %-12u [0x%x]\n", "e_phoff", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_shoff) : read_be32(&s->e_shoff);
        printf("  %11s: %-12u [0x%x]\n", "e_shoff", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_flags) : read_be32(&s->e_flags);
        printf("  %11s: %-12u [0x%x]\n", "e_flags", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_ehsize) : read_be16(&s->e_ehsize);
        printf("  %11s: %-12u [0x%x]\n", "e_ehsize", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_phentsize) : read_be16(&s->e_phentsize);
        printf("  %11s: %-12u [0x%x]\n", "e_phentsize", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_phnum) : read_be16(&s->e_phnum);
        printf("  %11s: %-12u [0x%x]\n", "e_phnum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_shentsize) : read_be16(&s->e_shentsize);
        printf("  %11s: %-12u [0x%x]\n", "e_shentsize", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_shnum) : read_be16(&s->e_shnum);
        printf("  %11s: %-12u [0x%x]\n", "e_shnum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_shstrndx) : read_be16(&s->e_shstrndx);
        printf("  %11s: %-12u [0x%x]\n", "e_shstrndx", v, v);
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
    printf("Elf64_Ehdr: (%lu)\n", sizeof(Elf64_Ehdr));

    hexstr = bytes_to_hex((u8_t*)s->e_ident, sizeof(s->e_ident));
    printf("  %11s: %s\n", "e_ident", hexstr);
    free(hexstr);
    {
        unsigned short v = le ? read_le16(&s->e_type) : read_be16(&s->e_type);
        printf("  %11s: %-12u [0x%x]\n", "e_type", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_machine) : read_be16(&s->e_machine);
        printf("  %11s: %-12u [0x%x]\n", "e_machine", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->e_version) : read_be32(&s->e_version);
        printf("  %11s: %-12u [0x%x]\n", "e_version", v, v);
    }
    {
        unsigned long long v =
            le ? read_le64(&s->e_entry) : read_be64(&s->e_entry);
        printf("  %11s: %-12llu [0x%llx]\n", "e_entry", v, v);
    }
    {
        unsigned long long v =
            le ? read_le64(&s->e_phoff) : read_be64(&s->e_phoff);
        printf("  %11s: %-12llu [0x%llx]\n", "e_phoff", v, v);
    }
    {
        unsigned long long v =
            le ? read_le64(&s->e_shoff) : read_be64(&s->e_shoff);
        printf("  %11s: %-12llu [0x%llx]\n", "e_shoff", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_flags) : read_be32(&s->e_flags);
        printf("  %11s: %-12u [0x%x]\n", "e_flags", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_ehsize) : read_be16(&s->e_ehsize);
        printf("  %11s: %-12u [0x%x]\n", "e_ehsize", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_phentsize) : read_be16(&s->e_phentsize);
        printf("  %11s: %-12u [0x%x]\n", "e_phentsize", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_phnum) : read_be16(&s->e_phnum);
        printf("  %11s: %-12u [0x%x]\n", "e_phnum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_shentsize) : read_be16(&s->e_shentsize);
        printf("  %11s: %-12u [0x%x]\n", "e_shentsize", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_shnum) : read_be16(&s->e_shnum);
        printf("  %11s: %-12u [0x%x]\n", "e_shnum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_shstrndx) : read_be16(&s->e_shstrndx);
        printf("  %11s: %-12u [0x%x]\n", "e_shstrndx", v, v);
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
    printf("IMAGE_DOS_HEADER: (%lu)\n", sizeof(IMAGE_DOS_HEADER));

    {
        unsigned short v = le ? read_le16(&s->e_magic) : read_be16(&s->e_magic);
        printf("  %10s: %-12u [0x%x]\n", "e_magic", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_cblp) : read_be16(&s->e_cblp);
        printf("  %10s: %-12u [0x%x]\n", "e_cblp", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_cp) : read_be16(&s->e_cp);
        printf("  %10s: %-12u [0x%x]\n", "e_cp", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_crlc) : read_be16(&s->e_crlc);
        printf("  %10s: %-12u [0x%x]\n", "e_crlc", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_cparhdr) : read_be16(&s->e_cparhdr);
        printf("  %10s: %-12u [0x%x]\n", "e_cparhdr", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_minalloc) : read_be16(&s->e_minalloc);
        printf("  %10s: %-12u [0x%x]\n", "e_minalloc", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_maxalloc) : read_be16(&s->e_maxalloc);
        printf("  %10s: %-12u [0x%x]\n", "e_maxalloc", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_ss) : read_be16(&s->e_ss);
        printf("  %10s: %-12u [0x%x]\n", "e_ss", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_sp) : read_be16(&s->e_sp);
        printf("  %10s: %-12u [0x%x]\n", "e_sp", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_csum) : read_be16(&s->e_csum);
        printf("  %10s: %-12u [0x%x]\n", "e_csum", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_ip) : read_be16(&s->e_ip);
        printf("  %10s: %-12u [0x%x]\n", "e_ip", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_cs) : read_be16(&s->e_cs);
        printf("  %10s: %-12u [0x%x]\n", "e_cs", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_lfarlc) : read_be16(&s->e_lfarlc);
        printf("  %10s: %-12u [0x%x]\n", "e_lfarlc", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_ovno) : read_be16(&s->e_ovno);
        printf("  %10s: %-12u [0x%x]\n", "e_ovno", v, v);
    }
    hexstr = bytes_to_hex((u8_t*)s->e_res, sizeof(s->e_res));
    printf("  %10s: %s\n", "e_res", hexstr);
    free(hexstr);
    {
        unsigned short v = le ? read_le16(&s->e_oemid) : read_be16(&s->e_oemid);
        printf("  %10s: %-12u [0x%x]\n", "e_oemid", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_oeminfo) : read_be16(&s->e_oeminfo);
        printf("  %10s: %-12u [0x%x]\n", "e_oeminfo", v, v);
    }
    hexstr = bytes_to_hex((u8_t*)s->e_res2, sizeof(s->e_res2));
    printf("  %10s: %s\n", "e_res2", hexstr);
    free(hexstr);
    {
        int v = le ? read_le32(&s->e_lfanew) : read_be32(&s->e_lfanew);
        printf("  %10s: %-12d [0x%x]\n", "e_lfanew", v, v);
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
    printf("IMAGE_NT_HEADERS64: (%lu)\n", sizeof(IMAGE_NT_HEADERS64));

    {
        unsigned int v =
            le ? read_le32(&s->Signature) : read_be32(&s->Signature);
        printf("  %27s: %-12u [0x%x]\n", "Signature", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->Machine) : read_be16(&s->Machine);
        printf("  %27s: %-12u [0x%x]\n", "Machine", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->NumberOfSections)
                              : read_be16(&s->NumberOfSections);
        printf("  %27s: %-12u [0x%x]\n", "NumberOfSections", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->TimeDateStamp) : read_be32(&s->TimeDateStamp);
        printf("  %27s: %-12u [0x%x]\n", "TimeDateStamp", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->PointerToSymbolTable)
                            : read_be32(&s->PointerToSymbolTable);
        printf("  %27s: %-12u [0x%x]\n", "PointerToSymbolTable", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->NumberOfSymbols)
                            : read_be32(&s->NumberOfSymbols);
        printf("  %27s: %-12u [0x%x]\n", "NumberOfSymbols", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->SizeOfOptionalHeader)
                              : read_be16(&s->SizeOfOptionalHeader);
        printf("  %27s: %-12u [0x%x]\n", "SizeOfOptionalHeader", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->Characteristics)
                              : read_be16(&s->Characteristics);
        printf("  %27s: %-12u [0x%x]\n", "Characteristics", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->Magic) : read_be16(&s->Magic);
        printf("  %27s: %-12u [0x%x]\n", "Magic", v, v);
    }
    {
        unsigned char v =
            le ? read8(&s->MajorLinkerVersion) : read8(&s->MajorLinkerVersion);
        printf("  %27s: %-12u [0x%x]\n", "MajorLinkerVersion", v, v);
    }
    {
        unsigned char v =
            le ? read8(&s->MinorLinkerVersion) : read8(&s->MinorLinkerVersion);
        printf("  %27s: %-12u [0x%x]\n", "MinorLinkerVersion", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->SizeOfCode) : read_be32(&s->SizeOfCode);
        printf("  %27s: %-12u [0x%x]\n", "SizeOfCode", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfInitializedData)
                            : read_be32(&s->SizeOfInitializedData);
        printf("  %27s: %-12u [0x%x]\n", "SizeOfInitializedData", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfUninitializedData)
                            : read_be32(&s->SizeOfUninitializedData);
        printf("  %27s: %-12u [0x%x]\n", "SizeOfUninitializedData", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->AddressOfEntryPoint)
                            : read_be32(&s->AddressOfEntryPoint);
        printf("  %27s: %-12u [0x%x]\n", "AddressOfEntryPoint", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->BaseOfCode) : read_be32(&s->BaseOfCode);
        printf("  %27s: %-12u [0x%x]\n", "BaseOfCode", v, v);
    }
    {
        unsigned long long v =
            le ? read_le64(&s->ImageBase) : read_be64(&s->ImageBase);
        printf("  %27s: %-12llu [0x%llx]\n", "ImageBase", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SectionAlignment)
                            : read_be32(&s->SectionAlignment);
        printf("  %27s: %-12u [0x%x]\n", "SectionAlignment", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->FileAlignment) : read_be32(&s->FileAlignment);
        printf("  %27s: %-12u [0x%x]\n", "FileAlignment", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MajorOperatingSystemVersion)
                              : read_be16(&s->MajorOperatingSystemVersion);
        printf("  %27s: %-12u [0x%x]\n", "MajorOperatingSystemVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MinorOperatingSystemVersion)
                              : read_be16(&s->MinorOperatingSystemVersion);
        printf("  %27s: %-12u [0x%x]\n", "MinorOperatingSystemVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MajorImageVersion)
                              : read_be16(&s->MajorImageVersion);
        printf("  %27s: %-12u [0x%x]\n", "MajorImageVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MinorImageVersion)
                              : read_be16(&s->MinorImageVersion);
        printf("  %27s: %-12u [0x%x]\n", "MinorImageVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MajorSubsystemVersion)
                              : read_be16(&s->MajorSubsystemVersion);
        printf("  %27s: %-12u [0x%x]\n", "MajorSubsystemVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MinorSubsystemVersion)
                              : read_be16(&s->MinorSubsystemVersion);
        printf("  %27s: %-12u [0x%x]\n", "MinorSubsystemVersion", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->Win32VersionValue)
                            : read_be32(&s->Win32VersionValue);
        printf("  %27s: %-12u [0x%x]\n", "Win32VersionValue", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->SizeOfImage) : read_be32(&s->SizeOfImage);
        printf("  %27s: %-12u [0x%x]\n", "SizeOfImage", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->SizeOfHeaders) : read_be32(&s->SizeOfHeaders);
        printf("  %27s: %-12u [0x%x]\n", "SizeOfHeaders", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->CheckSum) : read_be32(&s->CheckSum);
        printf("  %27s: %-12u [0x%x]\n", "CheckSum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->Subsystem) : read_be16(&s->Subsystem);
        printf("  %27s: %-12u [0x%x]\n", "Subsystem", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->DllCharacteristics)
                              : read_be16(&s->DllCharacteristics);
        printf("  %27s: %-12u [0x%x]\n", "DllCharacteristics", v, v);
    }
    {
        unsigned long long v = le ? read_le64(&s->SizeOfStackReserve)
                                  : read_be64(&s->SizeOfStackReserve);
        printf("  %27s: %-12llu [0x%llx]\n", "SizeOfStackReserve", v, v);
    }
    {
        unsigned long long v = le ? read_le64(&s->SizeOfStackCommit)
                                  : read_be64(&s->SizeOfStackCommit);
        printf("  %27s: %-12llu [0x%llx]\n", "SizeOfStackCommit", v, v);
    }
    {
        unsigned long long v = le ? read_le64(&s->SizeOfHeapReserve)
                                  : read_be64(&s->SizeOfHeapReserve);
        printf("  %27s: %-12llu [0x%llx]\n", "SizeOfHeapReserve", v, v);
    }
    {
        unsigned long long v = le ? read_le64(&s->SizeOfHeapCommit)
                                  : read_be64(&s->SizeOfHeapCommit);
        printf("  %27s: %-12llu [0x%llx]\n", "SizeOfHeapCommit", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->LoaderFlags) : read_be32(&s->LoaderFlags);
        printf("  %27s: %-12u [0x%x]\n", "LoaderFlags", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->NumberOfRvaAndSizes)
                            : read_be32(&s->NumberOfRvaAndSizes);
        printf("  %27s: %-12u [0x%x]\n", "NumberOfRvaAndSizes", v, v);
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
    printf("IMAGE_NT_HEADERS32: (%lu)\n", sizeof(IMAGE_NT_HEADERS32));

    {
        unsigned int v =
            le ? read_le32(&s->Signature) : read_be32(&s->Signature);
        printf("  %27s: %-12u [0x%x]\n", "Signature", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->Machine) : read_be16(&s->Machine);
        printf("  %27s: %-12u [0x%x]\n", "Machine", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->NumberOfSections)
                              : read_be16(&s->NumberOfSections);
        printf("  %27s: %-12u [0x%x]\n", "NumberOfSections", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->TimeDateStamp) : read_be32(&s->TimeDateStamp);
        printf("  %27s: %-12u [0x%x]\n", "TimeDateStamp", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->PointerToSymbolTable)
                            : read_be32(&s->PointerToSymbolTable);
        printf("  %27s: %-12u [0x%x]\n", "PointerToSymbolTable", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->NumberOfSymbols)
                            : read_be32(&s->NumberOfSymbols);
        printf("  %27s: %-12u [0x%x]\n", "NumberOfSymbols", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->SizeOfOptionalHeader)
                              : read_be16(&s->SizeOfOptionalHeader);
        printf("  %27s: %-12u [0x%x]\n", "SizeOfOptionalHeader", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->Characteristics)
                              : read_be16(&s->Characteristics);
        printf("  %27s: %-12u [0x%x]\n", "Characteristics", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->Magic) : read_be16(&s->Magic);
        printf("  %27s: %-12u [0x%x]\n", "Magic", v, v);
    }
    {
        unsigned char v =
            le ? read8(&s->MajorLinkerVersion) : read8(&s->MajorLinkerVersion);
        printf("  %27s: %-12u [0x%x]\n", "MajorLinkerVersion", v, v);
    }
    {
        unsigned char v =
            le ? read8(&s->MinorLinkerVersion) : read8(&s->MinorLinkerVersion);
        printf("  %27s: %-12u [0x%x]\n", "MinorLinkerVersion", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->SizeOfCode) : read_be32(&s->SizeOfCode);
        printf("  %27s: %-12u [0x%x]\n", "SizeOfCode", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfInitializedData)
                            : read_be32(&s->SizeOfInitializedData);
        printf("  %27s: %-12u [0x%x]\n", "SizeOfInitializedData", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfUninitializedData)
                            : read_be32(&s->SizeOfUninitializedData);
        printf("  %27s: %-12u [0x%x]\n", "SizeOfUninitializedData", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->AddressOfEntryPoint)
                            : read_be32(&s->AddressOfEntryPoint);
        printf("  %27s: %-12u [0x%x]\n", "AddressOfEntryPoint", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->BaseOfCode) : read_be32(&s->BaseOfCode);
        printf("  %27s: %-12u [0x%x]\n", "BaseOfCode", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->BaseOfData) : read_be32(&s->BaseOfData);
        printf("  %27s: %-12u [0x%x]\n", "BaseOfData", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->ImageBase) : read_be32(&s->ImageBase);
        printf("  %27s: %-12u [0x%x]\n", "ImageBase", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SectionAlignment)
                            : read_be32(&s->SectionAlignment);
        printf("  %27s: %-12u [0x%x]\n", "SectionAlignment", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->FileAlignment) : read_be32(&s->FileAlignment);
        printf("  %27s: %-12u [0x%x]\n", "FileAlignment", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MajorOperatingSystemVersion)
                              : read_be16(&s->MajorOperatingSystemVersion);
        printf("  %27s: %-12u [0x%x]\n", "MajorOperatingSystemVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MinorOperatingSystemVersion)
                              : read_be16(&s->MinorOperatingSystemVersion);
        printf("  %27s: %-12u [0x%x]\n", "MinorOperatingSystemVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MajorImageVersion)
                              : read_be16(&s->MajorImageVersion);
        printf("  %27s: %-12u [0x%x]\n", "MajorImageVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MinorImageVersion)
                              : read_be16(&s->MinorImageVersion);
        printf("  %27s: %-12u [0x%x]\n", "MinorImageVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MajorSubsystemVersion)
                              : read_be16(&s->MajorSubsystemVersion);
        printf("  %27s: %-12u [0x%x]\n", "MajorSubsystemVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MinorSubsystemVersion)
                              : read_be16(&s->MinorSubsystemVersion);
        printf("  %27s: %-12u [0x%x]\n", "MinorSubsystemVersion", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->Win32VersionValue)
                            : read_be32(&s->Win32VersionValue);
        printf("  %27s: %-12u [0x%x]\n", "Win32VersionValue", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->SizeOfImage) : read_be32(&s->SizeOfImage);
        printf("  %27s: %-12u [0x%x]\n", "SizeOfImage", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->SizeOfHeaders) : read_be32(&s->SizeOfHeaders);
        printf("  %27s: %-12u [0x%x]\n", "SizeOfHeaders", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->CheckSum) : read_be32(&s->CheckSum);
        printf("  %27s: %-12u [0x%x]\n", "CheckSum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->Subsystem) : read_be16(&s->Subsystem);
        printf("  %27s: %-12u [0x%x]\n", "Subsystem", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->DllCharacteristics)
                              : read_be16(&s->DllCharacteristics);
        printf("  %27s: %-12u [0x%x]\n", "DllCharacteristics", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfStackReserve)
                            : read_be32(&s->SizeOfStackReserve);
        printf("  %27s: %-12u [0x%x]\n", "SizeOfStackReserve", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfStackCommit)
                            : read_be32(&s->SizeOfStackCommit);
        printf("  %27s: %-12u [0x%x]\n", "SizeOfStackCommit", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfHeapReserve)
                            : read_be32(&s->SizeOfHeapReserve);
        printf("  %27s: %-12u [0x%x]\n", "SizeOfHeapReserve", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfHeapCommit)
                            : read_be32(&s->SizeOfHeapCommit);
        printf("  %27s: %-12u [0x%x]\n", "SizeOfHeapCommit", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->LoaderFlags) : read_be32(&s->LoaderFlags);
        printf("  %27s: %-12u [0x%x]\n", "LoaderFlags", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->NumberOfRvaAndSizes)
                            : read_be32(&s->NumberOfRvaAndSizes);
        printf("  %27s: %-12u [0x%x]\n", "NumberOfRvaAndSizes", v, v);
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
