
#include <stdio.h>
#include <stddef.h>
#include "../../defs.h"

#include "template.h"
#include "../util/byte_to_str.h"
#include "../util/endian.h"

#include "template_archives.h"

static size_t sizeof_ZipHeader() { return sizeof(ZipHeader); }

static void prettyprint_ZipHeader(const u8_t* data, size_t size, int le)
{
    if (size < sizeof_ZipHeader())
        return;

    __attribute__((unused)) char* hexstr;
    const ZipHeader*              s = (const ZipHeader*)data;
    printf("ZipHeader: (size: %lu)\n", sizeof(ZipHeader));

    {
        int v = le ? read_le32(&s->signatute) : read_be32(&s->signatute);
        printf("  b+%03lu %18s: %-12d [0x%x]\n", offsetof(ZipHeader, signatute),
               "signatute", v, v);
    }
    {
        short v = le ? read_le16(&s->version) : read_be16(&s->version);
        printf("  b+%03lu %18s: %-12d [0x%x]\n", offsetof(ZipHeader, version),
               "version", v, v);
    }
    {
        short v = le ? read_le16(&s->bit_flag) : read_be16(&s->bit_flag);
        printf("  b+%03lu %18s: %-12d [0x%x]\n", offsetof(ZipHeader, bit_flag),
               "bit_flag", v, v);
    }
    {
        short v = le ? read_le16(&s->compression_method)
                     : read_be16(&s->compression_method);
        printf("  b+%03lu %18s: %-12d [0x%x]\n",
               offsetof(ZipHeader, compression_method), "compression_method", v,
               v);
    }
    {
        short v = le ? read_le16(&s->time) : read_be16(&s->time);
        printf("  b+%03lu %18s: %-12d [0x%x]\n", offsetof(ZipHeader, time),
               "time", v, v);
    }
    {
        short v = le ? read_le16(&s->date) : read_be16(&s->date);
        printf("  b+%03lu %18s: %-12d [0x%x]\n", offsetof(ZipHeader, date),
               "date", v, v);
    }
    {
        int v = le ? read_le32(&s->crc) : read_be32(&s->crc);
        printf("  b+%03lu %18s: %-12d [0x%x]\n", offsetof(ZipHeader, crc),
               "crc", v, v);
    }
    {
        int v = le ? read_le32(&s->compressed_size)
                   : read_be32(&s->compressed_size);
        printf("  b+%03lu %18s: %-12d [0x%x]\n",
               offsetof(ZipHeader, compressed_size), "compressed_size", v, v);
    }
    {
        int v = le ? read_le32(&s->uncompressed_size)
                   : read_be32(&s->uncompressed_size);
        printf("  b+%03lu %18s: %-12d [0x%x]\n",
               offsetof(ZipHeader, uncompressed_size), "uncompressed_size", v,
               v);
    }
    {
        short v = le ? read_le16(&s->name_length) : read_be16(&s->name_length);
        printf("  b+%03lu %18s: %-12d [0x%x]\n",
               offsetof(ZipHeader, name_length), "name_length", v, v);
    }
    {
        short v = le ? read_le16(&s->extra_field_length)
                     : read_be16(&s->extra_field_length);
        printf("  b+%03lu %18s: %-12d [0x%x]\n",
               offsetof(ZipHeader, extra_field_length), "extra_field_length", v,
               v);
    }
}

#include "template_archives.h"

static size_t sizeof_TarHeader() { return sizeof(TarHeader); }

static void prettyprint_TarHeader(const u8_t* data, size_t size, int le)
{
    if (size < sizeof_TarHeader())
        return;

    __attribute__((unused)) char* hexstr;
    const TarHeader*              s = (const TarHeader*)data;
    printf("TarHeader: (size: %lu)\n", sizeof(TarHeader));

    printf("  b+%03lu %8s: %.100s\n", offsetof(TarHeader, name), "name",
           s->name);
    printf("  b+%03lu %8s: %.8s\n", offsetof(TarHeader, mode), "mode", s->mode);
    printf("  b+%03lu %8s: %.8s\n", offsetof(TarHeader, uid), "uid", s->uid);
    printf("  b+%03lu %8s: %.8s\n", offsetof(TarHeader, gid), "gid", s->gid);
    printf("  b+%03lu %8s: %.12s\n", offsetof(TarHeader, size), "size",
           s->size);
    printf("  b+%03lu %8s: %.12s\n", offsetof(TarHeader, mtime), "mtime",
           s->mtime);
    printf("  b+%03lu %8s: %.8s\n", offsetof(TarHeader, chksum), "chksum",
           s->chksum);
    {
        char v = le ? read8(&s->typeflag) : read8(&s->typeflag);
        printf("  b+%03lu %8s: %-12d [0x%x]\n", offsetof(TarHeader, typeflag),
               "typeflag", v, v);
    }
    printf("  b+%03lu %8s: %.100s\n", offsetof(TarHeader, linkname), "linkname",
           s->linkname);
    printf("  b+%03lu %8s: %.6s\n", offsetof(TarHeader, magic), "magic",
           s->magic);
    printf("  b+%03lu %8s: %.2s\n", offsetof(TarHeader, version), "version",
           s->version);
    printf("  b+%03lu %8s: %.32s\n", offsetof(TarHeader, uname), "uname",
           s->uname);
    printf("  b+%03lu %8s: %.32s\n", offsetof(TarHeader, gname), "gname",
           s->gname);
    printf("  b+%03lu %8s: %.8s\n", offsetof(TarHeader, devmajor), "devmajor",
           s->devmajor);
    printf("  b+%03lu %8s: %.8s\n", offsetof(TarHeader, devminor), "devminor",
           s->devminor);
    printf("  b+%03lu %8s: %.155s\n", offsetof(TarHeader, prefix), "prefix",
           s->prefix);
    hexstr = bytes_to_hex((u8_t*)s->padding, sizeof(s->padding));
    printf("  b+%03lu %8s: %s\n", offsetof(TarHeader, padding), "padding",
           hexstr);
    free(hexstr);
}

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
    printf("  b+%03lu %11s: %s\n", offsetof(Elf32_Ehdr, e_ident), "e_ident",
           hexstr);
    free(hexstr);
    {
        unsigned short v = le ? read_le16(&s->e_type) : read_be16(&s->e_type);
        printf("  b+%03lu %11s: %-12u [0x%x]\n", offsetof(Elf32_Ehdr, e_type),
               "e_type", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_machine) : read_be16(&s->e_machine);
        printf("  b+%03lu %11s: %-12u [0x%x]\n",
               offsetof(Elf32_Ehdr, e_machine), "e_machine", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->e_version) : read_be32(&s->e_version);
        printf("  b+%03lu %11s: %-12u [0x%x]\n",
               offsetof(Elf32_Ehdr, e_version), "e_version", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_entry) : read_be32(&s->e_entry);
        printf("  b+%03lu %11s: %-12u [0x%x]\n", offsetof(Elf32_Ehdr, e_entry),
               "e_entry", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_phoff) : read_be32(&s->e_phoff);
        printf("  b+%03lu %11s: %-12u [0x%x]\n", offsetof(Elf32_Ehdr, e_phoff),
               "e_phoff", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_shoff) : read_be32(&s->e_shoff);
        printf("  b+%03lu %11s: %-12u [0x%x]\n", offsetof(Elf32_Ehdr, e_shoff),
               "e_shoff", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_flags) : read_be32(&s->e_flags);
        printf("  b+%03lu %11s: %-12u [0x%x]\n", offsetof(Elf32_Ehdr, e_flags),
               "e_flags", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_ehsize) : read_be16(&s->e_ehsize);
        printf("  b+%03lu %11s: %-12u [0x%x]\n", offsetof(Elf32_Ehdr, e_ehsize),
               "e_ehsize", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_phentsize) : read_be16(&s->e_phentsize);
        printf("  b+%03lu %11s: %-12u [0x%x]\n",
               offsetof(Elf32_Ehdr, e_phentsize), "e_phentsize", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_phnum) : read_be16(&s->e_phnum);
        printf("  b+%03lu %11s: %-12u [0x%x]\n", offsetof(Elf32_Ehdr, e_phnum),
               "e_phnum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_shentsize) : read_be16(&s->e_shentsize);
        printf("  b+%03lu %11s: %-12u [0x%x]\n",
               offsetof(Elf32_Ehdr, e_shentsize), "e_shentsize", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_shnum) : read_be16(&s->e_shnum);
        printf("  b+%03lu %11s: %-12u [0x%x]\n", offsetof(Elf32_Ehdr, e_shnum),
               "e_shnum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_shstrndx) : read_be16(&s->e_shstrndx);
        printf("  b+%03lu %11s: %-12u [0x%x]\n",
               offsetof(Elf32_Ehdr, e_shstrndx), "e_shstrndx", v, v);
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
    printf("  b+%03lu %11s: %s\n", offsetof(Elf64_Ehdr, e_ident), "e_ident",
           hexstr);
    free(hexstr);
    {
        unsigned short v = le ? read_le16(&s->e_type) : read_be16(&s->e_type);
        printf("  b+%03lu %11s: %-12u [0x%x]\n", offsetof(Elf64_Ehdr, e_type),
               "e_type", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_machine) : read_be16(&s->e_machine);
        printf("  b+%03lu %11s: %-12u [0x%x]\n",
               offsetof(Elf64_Ehdr, e_machine), "e_machine", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->e_version) : read_be32(&s->e_version);
        printf("  b+%03lu %11s: %-12u [0x%x]\n",
               offsetof(Elf64_Ehdr, e_version), "e_version", v, v);
    }
    {
        unsigned long long v =
            le ? read_le64(&s->e_entry) : read_be64(&s->e_entry);
        printf("  b+%03lu %11s: %-12llu [0x%llx]\n",
               offsetof(Elf64_Ehdr, e_entry), "e_entry", v, v);
    }
    {
        unsigned long long v =
            le ? read_le64(&s->e_phoff) : read_be64(&s->e_phoff);
        printf("  b+%03lu %11s: %-12llu [0x%llx]\n",
               offsetof(Elf64_Ehdr, e_phoff), "e_phoff", v, v);
    }
    {
        unsigned long long v =
            le ? read_le64(&s->e_shoff) : read_be64(&s->e_shoff);
        printf("  b+%03lu %11s: %-12llu [0x%llx]\n",
               offsetof(Elf64_Ehdr, e_shoff), "e_shoff", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->e_flags) : read_be32(&s->e_flags);
        printf("  b+%03lu %11s: %-12u [0x%x]\n", offsetof(Elf64_Ehdr, e_flags),
               "e_flags", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_ehsize) : read_be16(&s->e_ehsize);
        printf("  b+%03lu %11s: %-12u [0x%x]\n", offsetof(Elf64_Ehdr, e_ehsize),
               "e_ehsize", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_phentsize) : read_be16(&s->e_phentsize);
        printf("  b+%03lu %11s: %-12u [0x%x]\n",
               offsetof(Elf64_Ehdr, e_phentsize), "e_phentsize", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_phnum) : read_be16(&s->e_phnum);
        printf("  b+%03lu %11s: %-12u [0x%x]\n", offsetof(Elf64_Ehdr, e_phnum),
               "e_phnum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_shentsize) : read_be16(&s->e_shentsize);
        printf("  b+%03lu %11s: %-12u [0x%x]\n",
               offsetof(Elf64_Ehdr, e_shentsize), "e_shentsize", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_shnum) : read_be16(&s->e_shnum);
        printf("  b+%03lu %11s: %-12u [0x%x]\n", offsetof(Elf64_Ehdr, e_shnum),
               "e_shnum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_shstrndx) : read_be16(&s->e_shstrndx);
        printf("  b+%03lu %11s: %-12u [0x%x]\n",
               offsetof(Elf64_Ehdr, e_shstrndx), "e_shstrndx", v, v);
    }
}

#include "template_mach.h"

static size_t sizeof_mach_header() { return sizeof(mach_header); }

static void prettyprint_mach_header(const u8_t* data, size_t size, int le)
{
    if (size < sizeof_mach_header())
        return;

    __attribute__((unused)) char* hexstr;
    const mach_header*            s = (const mach_header*)data;
    printf("mach_header: (size: %lu)\n", sizeof(mach_header));

    {
        unsigned int v = le ? read_le32(&s->magic) : read_be32(&s->magic);
        printf("  b+%03lu %10s: %-12u [0x%x]\n", offsetof(mach_header, magic),
               "magic", v, v);
    }
    {
        int v = le ? read_le32(&s->cputype) : read_be32(&s->cputype);
        printf("  b+%03lu %10s: %-12d [0x%x]\n", offsetof(mach_header, cputype),
               "cputype", v, v);
    }
    {
        int v = le ? read_le32(&s->cpusubtype) : read_be32(&s->cpusubtype);
        printf("  b+%03lu %10s: %-12d [0x%x]\n",
               offsetof(mach_header, cpusubtype), "cpusubtype", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->filetype) : read_be32(&s->filetype);
        printf("  b+%03lu %10s: %-12u [0x%x]\n",
               offsetof(mach_header, filetype), "filetype", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->ncmds) : read_be32(&s->ncmds);
        printf("  b+%03lu %10s: %-12u [0x%x]\n", offsetof(mach_header, ncmds),
               "ncmds", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->sizeofcmds) : read_be32(&s->sizeofcmds);
        printf("  b+%03lu %10s: %-12u [0x%x]\n",
               offsetof(mach_header, sizeofcmds), "sizeofcmds", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->flags) : read_be32(&s->flags);
        printf("  b+%03lu %10s: %-12u [0x%x]\n", offsetof(mach_header, flags),
               "flags", v, v);
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
        printf("  b+%03lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_magic), "e_magic", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_cblp) : read_be16(&s->e_cblp);
        printf("  b+%03lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_cblp), "e_cblp", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_cp) : read_be16(&s->e_cp);
        printf("  b+%03lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_cp), "e_cp", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_crlc) : read_be16(&s->e_crlc);
        printf("  b+%03lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_crlc), "e_crlc", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_cparhdr) : read_be16(&s->e_cparhdr);
        printf("  b+%03lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_cparhdr), "e_cparhdr", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_minalloc) : read_be16(&s->e_minalloc);
        printf("  b+%03lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_minalloc), "e_minalloc", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_maxalloc) : read_be16(&s->e_maxalloc);
        printf("  b+%03lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_maxalloc), "e_maxalloc", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_ss) : read_be16(&s->e_ss);
        printf("  b+%03lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_ss), "e_ss", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_sp) : read_be16(&s->e_sp);
        printf("  b+%03lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_sp), "e_sp", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_csum) : read_be16(&s->e_csum);
        printf("  b+%03lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_csum), "e_csum", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_ip) : read_be16(&s->e_ip);
        printf("  b+%03lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_ip), "e_ip", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_cs) : read_be16(&s->e_cs);
        printf("  b+%03lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_cs), "e_cs", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_lfarlc) : read_be16(&s->e_lfarlc);
        printf("  b+%03lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_lfarlc), "e_lfarlc", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->e_ovno) : read_be16(&s->e_ovno);
        printf("  b+%03lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_ovno), "e_ovno", v, v);
    }
    hexstr = bytes_to_hex((u8_t*)s->e_res, sizeof(s->e_res));
    printf("  b+%03lu %10s: %s\n", offsetof(IMAGE_DOS_HEADER, e_res), "e_res",
           hexstr);
    free(hexstr);
    {
        unsigned short v = le ? read_le16(&s->e_oemid) : read_be16(&s->e_oemid);
        printf("  b+%03lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_oemid), "e_oemid", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->e_oeminfo) : read_be16(&s->e_oeminfo);
        printf("  b+%03lu %10s: %-12u [0x%x]\n",
               offsetof(IMAGE_DOS_HEADER, e_oeminfo), "e_oeminfo", v, v);
    }
    hexstr = bytes_to_hex((u8_t*)s->e_res2, sizeof(s->e_res2));
    printf("  b+%03lu %10s: %s\n", offsetof(IMAGE_DOS_HEADER, e_res2), "e_res2",
           hexstr);
    free(hexstr);
    {
        int v = le ? read_le32(&s->e_lfanew) : read_be32(&s->e_lfanew);
        printf("  b+%03lu %10s: %-12d [0x%x]\n",
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
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, Signature), "Signature", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->Machine) : read_be16(&s->Machine);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, Machine), "Machine", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->NumberOfSections)
                              : read_be16(&s->NumberOfSections);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, NumberOfSections),
               "NumberOfSections", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->TimeDateStamp) : read_be32(&s->TimeDateStamp);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, TimeDateStamp), "TimeDateStamp", v,
               v);
    }
    {
        unsigned int v = le ? read_le32(&s->PointerToSymbolTable)
                            : read_be32(&s->PointerToSymbolTable);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, PointerToSymbolTable),
               "PointerToSymbolTable", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->NumberOfSymbols)
                            : read_be32(&s->NumberOfSymbols);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, NumberOfSymbols), "NumberOfSymbols",
               v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->SizeOfOptionalHeader)
                              : read_be16(&s->SizeOfOptionalHeader);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfOptionalHeader),
               "SizeOfOptionalHeader", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->Characteristics)
                              : read_be16(&s->Characteristics);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, Characteristics), "Characteristics",
               v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->Magic) : read_be16(&s->Magic);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, Magic), "Magic", v, v);
    }
    {
        unsigned char v =
            le ? read8(&s->MajorLinkerVersion) : read8(&s->MajorLinkerVersion);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, MajorLinkerVersion),
               "MajorLinkerVersion", v, v);
    }
    {
        unsigned char v =
            le ? read8(&s->MinorLinkerVersion) : read8(&s->MinorLinkerVersion);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, MinorLinkerVersion),
               "MinorLinkerVersion", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->SizeOfCode) : read_be32(&s->SizeOfCode);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfCode), "SizeOfCode", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfInitializedData)
                            : read_be32(&s->SizeOfInitializedData);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfInitializedData),
               "SizeOfInitializedData", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfUninitializedData)
                            : read_be32(&s->SizeOfUninitializedData);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfUninitializedData),
               "SizeOfUninitializedData", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->AddressOfEntryPoint)
                            : read_be32(&s->AddressOfEntryPoint);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, AddressOfEntryPoint),
               "AddressOfEntryPoint", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->BaseOfCode) : read_be32(&s->BaseOfCode);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, BaseOfCode), "BaseOfCode", v, v);
    }
    {
        unsigned long long v =
            le ? read_le64(&s->ImageBase) : read_be64(&s->ImageBase);
        printf("  b+%03lu %27s: %-12llu [0x%llx]\n",
               offsetof(IMAGE_NT_HEADERS64, ImageBase), "ImageBase", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SectionAlignment)
                            : read_be32(&s->SectionAlignment);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, SectionAlignment),
               "SectionAlignment", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->FileAlignment) : read_be32(&s->FileAlignment);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, FileAlignment), "FileAlignment", v,
               v);
    }
    {
        unsigned short v = le ? read_le16(&s->MajorOperatingSystemVersion)
                              : read_be16(&s->MajorOperatingSystemVersion);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, MajorOperatingSystemVersion),
               "MajorOperatingSystemVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MinorOperatingSystemVersion)
                              : read_be16(&s->MinorOperatingSystemVersion);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, MinorOperatingSystemVersion),
               "MinorOperatingSystemVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MajorImageVersion)
                              : read_be16(&s->MajorImageVersion);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, MajorImageVersion),
               "MajorImageVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MinorImageVersion)
                              : read_be16(&s->MinorImageVersion);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, MinorImageVersion),
               "MinorImageVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MajorSubsystemVersion)
                              : read_be16(&s->MajorSubsystemVersion);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, MajorSubsystemVersion),
               "MajorSubsystemVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MinorSubsystemVersion)
                              : read_be16(&s->MinorSubsystemVersion);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, MinorSubsystemVersion),
               "MinorSubsystemVersion", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->Win32VersionValue)
                            : read_be32(&s->Win32VersionValue);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, Win32VersionValue),
               "Win32VersionValue", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->SizeOfImage) : read_be32(&s->SizeOfImage);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfImage), "SizeOfImage", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->SizeOfHeaders) : read_be32(&s->SizeOfHeaders);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfHeaders), "SizeOfHeaders", v,
               v);
    }
    {
        unsigned int v = le ? read_le32(&s->CheckSum) : read_be32(&s->CheckSum);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, CheckSum), "CheckSum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->Subsystem) : read_be16(&s->Subsystem);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, Subsystem), "Subsystem", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->DllCharacteristics)
                              : read_be16(&s->DllCharacteristics);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, DllCharacteristics),
               "DllCharacteristics", v, v);
    }
    {
        unsigned long long v = le ? read_le64(&s->SizeOfStackReserve)
                                  : read_be64(&s->SizeOfStackReserve);
        printf("  b+%03lu %27s: %-12llu [0x%llx]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfStackReserve),
               "SizeOfStackReserve", v, v);
    }
    {
        unsigned long long v = le ? read_le64(&s->SizeOfStackCommit)
                                  : read_be64(&s->SizeOfStackCommit);
        printf("  b+%03lu %27s: %-12llu [0x%llx]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfStackCommit),
               "SizeOfStackCommit", v, v);
    }
    {
        unsigned long long v = le ? read_le64(&s->SizeOfHeapReserve)
                                  : read_be64(&s->SizeOfHeapReserve);
        printf("  b+%03lu %27s: %-12llu [0x%llx]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfHeapReserve),
               "SizeOfHeapReserve", v, v);
    }
    {
        unsigned long long v = le ? read_le64(&s->SizeOfHeapCommit)
                                  : read_be64(&s->SizeOfHeapCommit);
        printf("  b+%03lu %27s: %-12llu [0x%llx]\n",
               offsetof(IMAGE_NT_HEADERS64, SizeOfHeapCommit),
               "SizeOfHeapCommit", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->LoaderFlags) : read_be32(&s->LoaderFlags);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS64, LoaderFlags), "LoaderFlags", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->NumberOfRvaAndSizes)
                            : read_be32(&s->NumberOfRvaAndSizes);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
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
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, Signature), "Signature", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->Machine) : read_be16(&s->Machine);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, Machine), "Machine", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->NumberOfSections)
                              : read_be16(&s->NumberOfSections);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, NumberOfSections),
               "NumberOfSections", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->TimeDateStamp) : read_be32(&s->TimeDateStamp);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, TimeDateStamp), "TimeDateStamp", v,
               v);
    }
    {
        unsigned int v = le ? read_le32(&s->PointerToSymbolTable)
                            : read_be32(&s->PointerToSymbolTable);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, PointerToSymbolTable),
               "PointerToSymbolTable", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->NumberOfSymbols)
                            : read_be32(&s->NumberOfSymbols);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, NumberOfSymbols), "NumberOfSymbols",
               v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->SizeOfOptionalHeader)
                              : read_be16(&s->SizeOfOptionalHeader);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfOptionalHeader),
               "SizeOfOptionalHeader", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->Characteristics)
                              : read_be16(&s->Characteristics);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, Characteristics), "Characteristics",
               v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->Magic) : read_be16(&s->Magic);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, Magic), "Magic", v, v);
    }
    {
        unsigned char v =
            le ? read8(&s->MajorLinkerVersion) : read8(&s->MajorLinkerVersion);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, MajorLinkerVersion),
               "MajorLinkerVersion", v, v);
    }
    {
        unsigned char v =
            le ? read8(&s->MinorLinkerVersion) : read8(&s->MinorLinkerVersion);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, MinorLinkerVersion),
               "MinorLinkerVersion", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->SizeOfCode) : read_be32(&s->SizeOfCode);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfCode), "SizeOfCode", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfInitializedData)
                            : read_be32(&s->SizeOfInitializedData);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfInitializedData),
               "SizeOfInitializedData", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfUninitializedData)
                            : read_be32(&s->SizeOfUninitializedData);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfUninitializedData),
               "SizeOfUninitializedData", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->AddressOfEntryPoint)
                            : read_be32(&s->AddressOfEntryPoint);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, AddressOfEntryPoint),
               "AddressOfEntryPoint", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->BaseOfCode) : read_be32(&s->BaseOfCode);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, BaseOfCode), "BaseOfCode", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->BaseOfData) : read_be32(&s->BaseOfData);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, BaseOfData), "BaseOfData", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->ImageBase) : read_be32(&s->ImageBase);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, ImageBase), "ImageBase", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SectionAlignment)
                            : read_be32(&s->SectionAlignment);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SectionAlignment),
               "SectionAlignment", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->FileAlignment) : read_be32(&s->FileAlignment);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, FileAlignment), "FileAlignment", v,
               v);
    }
    {
        unsigned short v = le ? read_le16(&s->MajorOperatingSystemVersion)
                              : read_be16(&s->MajorOperatingSystemVersion);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, MajorOperatingSystemVersion),
               "MajorOperatingSystemVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MinorOperatingSystemVersion)
                              : read_be16(&s->MinorOperatingSystemVersion);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, MinorOperatingSystemVersion),
               "MinorOperatingSystemVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MajorImageVersion)
                              : read_be16(&s->MajorImageVersion);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, MajorImageVersion),
               "MajorImageVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MinorImageVersion)
                              : read_be16(&s->MinorImageVersion);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, MinorImageVersion),
               "MinorImageVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MajorSubsystemVersion)
                              : read_be16(&s->MajorSubsystemVersion);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, MajorSubsystemVersion),
               "MajorSubsystemVersion", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->MinorSubsystemVersion)
                              : read_be16(&s->MinorSubsystemVersion);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, MinorSubsystemVersion),
               "MinorSubsystemVersion", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->Win32VersionValue)
                            : read_be32(&s->Win32VersionValue);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, Win32VersionValue),
               "Win32VersionValue", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->SizeOfImage) : read_be32(&s->SizeOfImage);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfImage), "SizeOfImage", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->SizeOfHeaders) : read_be32(&s->SizeOfHeaders);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfHeaders), "SizeOfHeaders", v,
               v);
    }
    {
        unsigned int v = le ? read_le32(&s->CheckSum) : read_be32(&s->CheckSum);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, CheckSum), "CheckSum", v, v);
    }
    {
        unsigned short v =
            le ? read_le16(&s->Subsystem) : read_be16(&s->Subsystem);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, Subsystem), "Subsystem", v, v);
    }
    {
        unsigned short v = le ? read_le16(&s->DllCharacteristics)
                              : read_be16(&s->DllCharacteristics);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, DllCharacteristics),
               "DllCharacteristics", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfStackReserve)
                            : read_be32(&s->SizeOfStackReserve);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfStackReserve),
               "SizeOfStackReserve", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfStackCommit)
                            : read_be32(&s->SizeOfStackCommit);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfStackCommit),
               "SizeOfStackCommit", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfHeapReserve)
                            : read_be32(&s->SizeOfHeapReserve);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfHeapReserve),
               "SizeOfHeapReserve", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->SizeOfHeapCommit)
                            : read_be32(&s->SizeOfHeapCommit);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, SizeOfHeapCommit),
               "SizeOfHeapCommit", v, v);
    }
    {
        unsigned int v =
            le ? read_le32(&s->LoaderFlags) : read_be32(&s->LoaderFlags);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, LoaderFlags), "LoaderFlags", v, v);
    }
    {
        unsigned int v = le ? read_le32(&s->NumberOfRvaAndSizes)
                            : read_be32(&s->NumberOfRvaAndSizes);
        printf("  b+%03lu %27s: %-12u [0x%x]\n",
               offsetof(IMAGE_NT_HEADERS32, NumberOfRvaAndSizes),
               "NumberOfRvaAndSizes", v, v);
    }
}

Template templates[] = {
    {.name         = "ZipHeader",
     .get_size     = sizeof_ZipHeader,
     .pretty_print = prettyprint_ZipHeader},

    {.name         = "TarHeader",
     .get_size     = sizeof_TarHeader,
     .pretty_print = prettyprint_TarHeader},

    {.name         = "Elf32_Ehdr",
     .get_size     = sizeof_Elf32_Ehdr,
     .pretty_print = prettyprint_Elf32_Ehdr},

    {.name         = "Elf64_Ehdr",
     .get_size     = sizeof_Elf64_Ehdr,
     .pretty_print = prettyprint_Elf64_Ehdr},

    {.name         = "mach_header",
     .get_size     = sizeof_mach_header,
     .pretty_print = prettyprint_mach_header},

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
