// Copyright (c) 2022-2026, bageyelet

#include "data/big_buffers.h"
#include "t_cmd_common.h"
#include "t.h"

#include "../bhengine/vm.h"

#include "data/sample_squashfs.h"
#include "data/sample_gzip.h"
#include "data/sample_gzip_named.h"
#include "data/not_kitty_jpeg.h"
#include "data/sample_lzo.h"
#include "data/sample_fat_macho.h"
#include "data/sample_macho.h"
#include "data/sample_mp3.h"
#include "data/sample_mp4.h"
#include "data/sample_pdf.h"
#include "data/not_kitty_png.h"
#include "data/sample_rpm.h"
#include "data/sample_zip.h"
#include "data/sample_7z.h"
#include "data/sample_bzip2.h"
#include "data/sample_cpio.h"
#include "data/sample_dtb.h"
#include "data/sample_uimage.h"
#include "data/sample_xz.h"
#include "data/sample_zstd.h"
#include "data/sample_ar.h"
#include "data/sample_javaclass.h"
#include "data/sample_pcap.h"
#include "data/sample_pcapng.h"
#include "data/sample_riff.h"
#include "data/sample_sqlite3.h"
#include "data/sample_ubifs.h"
#include "data/sample_ext.h"
#include "data/sample_fat.h"
#include "data/sample_gpt.h"
#include "data/sample_mbr.h"
#include "data/sample_dex.h"
#include "data/sample_gif.h"
#include "data/sample_ogg.h"
#include "data/sample_sfnt.h"
#include "data/sample_wasm.h"
#include "data/sample_x509.h"
#include "data/sample_tar.h"
#include "data/sample_cab.h"
#include "data/sample_iso9660.h"
#include "data/sample_jffs2.h"
#include "data/sample_lha.h"
#include "data/sample_luks.h"
#include "data/sample_lz4.h"
#include "data/sample_qcow2.h"
#include "data/sample_rar.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(template_elf)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000      header: \n"
        "b+00000000         e_ident: \n"
        "b+00000000              ei_mag: 7f454c46\n"
        "b+00000004            ei_class: ELFCLASS32\n"
        "b+00000005             ei_data: ELFDATA2LSB\n"
        "b+00000006          ei_version: 01\n"
        "b+00000007            ei_osabi: ELFOSABI_NONE\n"
        "b+00000008       ei_abiversion: 00\n"
        "b+00000009              ei_pad: 00000000000000\n"
        "b+00000010          e_type: ET_EXEC\n"
        "b+00000012       e_machine: EM_386\n"
        "b+00000014       e_version: 00000001\n"
        "b+00000018         e_entry: 08048074\n"
        "b+0000001c         e_phoff: 00000034\n"
        "b+00000020         e_shoff: 000000a4\n"
        "b+00000024         e_flags: 00000000\n"
        "b+00000028        e_ehsize: 0034\n"
        "b+0000002a     e_phentsize: 0020\n"
        "b+0000002c         e_phnum: 0002\n"
        "b+0000002e     e_shentsize: 0028\n"
        "b+00000030         e_shnum: 0004\n"
        "b+00000032      e_shstrndx: 0003\n"
        "b+00000034        phdr: \n"
        "b+00000034          p_type: PT_LOAD\n"
        "b+00000038        p_offset: 00000000\n"
        "b+0000003c         p_vaddr: 08048000\n"
        "b+00000040         p_paddr: 08048000\n"
        "b+00000044        p_filesz: 00000080\n"
        "b+00000048         p_memsz: 00000080\n"
        "b+0000004c         p_flags: PF_X | PF_R\n"
        "b+00000050         p_align: 00001000\n"
        "b+00000000  PrevPhData: 7f454c46010101000000000000000000...\n"
        "b+00000054        phdr: \n"
        "b+00000054          p_type: PT_LOAD\n"
        "b+00000058        p_offset: 00000080\n"
        "b+0000005c         p_vaddr: 08049080\n"
        "b+00000060         p_paddr: 08049080\n"
        "b+00000064        p_filesz: 0000000c\n"
        "b+00000068         p_memsz: 0000000c\n"
        "b+0000006c         p_flags: PF_W | PF_R\n"
        "b+00000070         p_align: 00001000\n"
        "b+00000080  PrevPhData: 68656c6c6f20776f726c6400\n"
        "b+000000a4        shdr: \n"
        "b+000000a4         sh_name: 00000000\n"
        "b+000000a8         sh_type: SHT_NULL\n"
        "b+000000ac        sh_flags: NONE\n"
        "b+000000b0         sh_addr: 00000000\n"
        "b+000000b4       sh_offset: 00000000\n"
        "b+000000b8         sh_size: 00000000\n"
        "b+000000bc         sh_link: 00000000\n"
        "b+000000c0         sh_info: 00000000\n"
        "b+000000c4    sh_addralign: 00000000\n"
        "b+000000c8      sh_entsize: 00000000\n"
        "b+0000008c  PrevShName: ''\n"
        "b+000000cc        shdr: \n"
        "b+000000cc         sh_name: 0000000b\n"
        "b+000000d0         sh_type: SHT_PROGBITS\n"
        "b+000000d4        sh_flags: SHF_ALLOC | SHF_EXECINSTR\n"
        "b+000000d8         sh_addr: 08048074\n"
        "b+000000dc       sh_offset: 00000074\n"
        "b+000000e0         sh_size: 0000000c\n"
        "b+000000e4         sh_link: 00000000\n"
        "b+000000e8         sh_info: 00000000\n"
        "b+000000ec    sh_addralign: 00000004\n"
        "b+000000f0      sh_entsize: 00000000\n"
        "b+00000097  PrevShName: '.text'\n"
        "b+000000f4        shdr: \n"
        "b+000000f4         sh_name: 00000011\n"
        "b+000000f8         sh_type: SHT_PROGBITS\n"
        "b+000000fc        sh_flags: SHF_WRITE | SHF_ALLOC\n"
        "b+00000100         sh_addr: 08049080\n"
        "b+00000104       sh_offset: 00000080\n"
        "b+00000108         sh_size: 0000000c\n"
        "b+0000010c         sh_link: 00000000\n"
        "b+00000110         sh_info: 00000000\n"
        "b+00000114    sh_addralign: 00000004\n"
        "b+00000118      sh_entsize: 00000000\n"
        "b+0000009d  PrevShName: '.data'\n"
        "b+0000011c        shdr: \n"
        "b+0000011c         sh_name: 00000001\n"
        "b+00000120         sh_type: SHT_STRTAB\n"
        "b+00000124        sh_flags: NONE\n"
        "b+00000128         sh_addr: 00000000\n"
        "b+0000012c       sh_offset: 0000008c\n"
        "b+00000130         sh_size: 00000017\n"
        "b+00000134         sh_link: 00000000\n"
        "b+00000138         sh_info: 00000000\n"
        "b+0000013c    sh_addralign: 00000001\n"
        "b+00000140      sh_entsize: 00000000\n"
        "b+0000008d  PrevShName: '.shstrtab'\n"
        "";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands_on("t ./templates/elf.bhe", elf_fb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(template_elf_xml)(void)
{
    const char* expected =
        "<root><var name=\"header\" type=\"Elf_Ehdr\" off=\"0\"><var "
        "name=\"e_ident\" type=\"ElfIdent\" off=\"0\"><var name=\"ei_mag\" "
        "type=\"u8[]\" off=\"0\"><buffer>7f454c46</buffer></var><var "
        "name=\"ei_class\" type=\"ElfIdentClass\" off=\"4\"><enum_value "
        "mnemonic=\"ELFCLASS32\">1</enum_value></var><var name=\"ei_data\" "
        "type=\"ElfIdentData\" off=\"5\"><enum_value "
        "mnemonic=\"ELFDATA2LSB\">1</enum_value></var><var name=\"ei_version\" "
        "type=\"u8\" off=\"6\"><unum size=\"1\">1</unum></var><var "
        "name=\"ei_osabi\" type=\"ElfIdentOsABI\" off=\"7\"><enum_value "
        "mnemonic=\"ELFOSABI_NONE\">0</enum_value></var><var "
        "name=\"ei_abiversion\" type=\"u8\" off=\"8\"><unum "
        "size=\"1\">0</unum></var><var name=\"ei_pad\" type=\"u8[]\" "
        "off=\"9\"><buffer>00000000000000</buffer></var></var><var "
        "name=\"e_type\" type=\"ElfType\" off=\"16\"><enum_value "
        "mnemonic=\"ET_EXEC\">2</enum_value></var><var name=\"e_machine\" "
        "type=\"ElfMachine\" off=\"18\"><enum_value "
        "mnemonic=\"EM_386\">3</enum_value></var><var name=\"e_version\" "
        "type=\"u32\" off=\"20\"><unum size=\"4\">1</unum></var><var "
        "name=\"e_entry\" type=\"u32\" off=\"24\"><unum "
        "size=\"4\">134512756</unum></var><var name=\"e_phoff\" type=\"u32\" "
        "off=\"28\"><unum size=\"4\">52</unum></var><var name=\"e_shoff\" "
        "type=\"u32\" off=\"32\"><unum size=\"4\">164</unum></var><var "
        "name=\"e_flags\" type=\"u32\" off=\"36\"><unum "
        "size=\"4\">0</unum></var><var name=\"e_ehsize\" type=\"u16\" "
        "off=\"40\"><unum size=\"2\">52</unum></var><var name=\"e_phentsize\" "
        "type=\"u16\" off=\"42\"><unum size=\"2\">32</unum></var><var "
        "name=\"e_phnum\" type=\"u16\" off=\"44\"><unum "
        "size=\"2\">2</unum></var><var name=\"e_shentsize\" type=\"u16\" "
        "off=\"46\"><unum size=\"2\">40</unum></var><var name=\"e_shnum\" "
        "type=\"u16\" off=\"48\"><unum size=\"2\">4</unum></var><var "
        "name=\"e_shstrndx\" type=\"u16\" off=\"50\"><unum "
        "size=\"2\">3</unum></var></var><var name=\"phdr\" type=\"Elf32_Phdr\" "
        "off=\"52\"><var name=\"p_type\" type=\"PhdrType\" "
        "off=\"52\"><enum_value mnemonic=\"PT_LOAD\">1</enum_value></var><var "
        "name=\"p_offset\" type=\"u32\" off=\"56\"><unum "
        "size=\"4\">0</unum></var><var name=\"p_vaddr\" type=\"u32\" "
        "off=\"60\"><unum size=\"4\">134512640</unum></var><var "
        "name=\"p_paddr\" type=\"u32\" off=\"64\"><unum "
        "size=\"4\">134512640</unum></var><var name=\"p_filesz\" type=\"u32\" "
        "off=\"68\"><unum size=\"4\">128</unum></var><var name=\"p_memsz\" "
        "type=\"u32\" off=\"72\"><unum size=\"4\">128</unum></var><var "
        "name=\"p_flags\" type=\"PhdrFlag\" off=\"76\"><enum_value "
        "mnemonic=\"PF_X | PF_R\">5</enum_value></var><var name=\"p_align\" "
        "type=\"u32\" off=\"80\"><unum size=\"4\">4096</unum></var></var><var "
        "name=\"PrevPhData\" type=\"u8[]\" "
        "off=\"0\"><buffer>"
        "7f454c4601010100000000000000000002000300010000007480040834000000a40000"
        "0000000000340020000200280004000300010000000000000000800408008004088000"
        "0000800000000500000000100000010000008000000080900408809004080c0000000c"
        "0000000600000000100000b801000000bb2a000000cd80</buffer></var><var "
        "name=\"phdr\" type=\"Elf32_Phdr\" off=\"84\"><var name=\"p_type\" "
        "type=\"PhdrType\" off=\"84\"><enum_value "
        "mnemonic=\"PT_LOAD\">1</enum_value></var><var name=\"p_offset\" "
        "type=\"u32\" off=\"88\"><unum size=\"4\">128</unum></var><var "
        "name=\"p_vaddr\" type=\"u32\" off=\"92\"><unum "
        "size=\"4\">134516864</unum></var><var name=\"p_paddr\" type=\"u32\" "
        "off=\"96\"><unum size=\"4\">134516864</unum></var><var "
        "name=\"p_filesz\" type=\"u32\" off=\"100\"><unum "
        "size=\"4\">12</unum></var><var name=\"p_memsz\" type=\"u32\" "
        "off=\"104\"><unum size=\"4\">12</unum></var><var name=\"p_flags\" "
        "type=\"PhdrFlag\" off=\"108\"><enum_value mnemonic=\"PF_W | "
        "PF_R\">6</enum_value></var><var name=\"p_align\" type=\"u32\" "
        "off=\"112\"><unum size=\"4\">4096</unum></var></var><var "
        "name=\"PrevPhData\" type=\"u8[]\" "
        "off=\"128\"><buffer>68656c6c6f20776f726c6400</buffer></var><var "
        "name=\"shdr\" type=\"Elf32_Shdr\" off=\"164\"><var name=\"sh_name\" "
        "type=\"u32\" off=\"164\"><unum size=\"4\">0</unum></var><var "
        "name=\"sh_type\" type=\"ShdrType\" off=\"168\"><enum_value "
        "mnemonic=\"SHT_NULL\">0</enum_value></var><var name=\"sh_flags\" "
        "type=\"ShrFlag\" off=\"172\"><enum_value "
        "mnemonic=\"NONE\">0</enum_value></var><var name=\"sh_addr\" "
        "type=\"u32\" off=\"176\"><unum size=\"4\">0</unum></var><var "
        "name=\"sh_offset\" type=\"u32\" off=\"180\"><unum "
        "size=\"4\">0</unum></var><var name=\"sh_size\" type=\"u32\" "
        "off=\"184\"><unum size=\"4\">0</unum></var><var name=\"sh_link\" "
        "type=\"u32\" off=\"188\"><unum size=\"4\">0</unum></var><var "
        "name=\"sh_info\" type=\"u32\" off=\"192\"><unum "
        "size=\"4\">0</unum></var><var name=\"sh_addralign\" type=\"u32\" "
        "off=\"196\"><unum size=\"4\">0</unum></var><var name=\"sh_entsize\" "
        "type=\"u32\" off=\"200\"><unum size=\"4\">0</unum></var></var><var "
        "name=\"PrevShName\" type=\"string\" "
        "off=\"140\"><buffer></buffer></var><var name=\"shdr\" "
        "type=\"Elf32_Shdr\" off=\"204\"><var name=\"sh_name\" type=\"u32\" "
        "off=\"204\"><unum size=\"4\">11</unum></var><var name=\"sh_type\" "
        "type=\"ShdrType\" off=\"208\"><enum_value "
        "mnemonic=\"SHT_PROGBITS\">1</enum_value></var><var name=\"sh_flags\" "
        "type=\"ShrFlag\" off=\"212\"><enum_value mnemonic=\"SHF_ALLOC | "
        "SHF_EXECINSTR\">6</enum_value></var><var name=\"sh_addr\" "
        "type=\"u32\" off=\"216\"><unum size=\"4\">134512756</unum></var><var "
        "name=\"sh_offset\" type=\"u32\" off=\"220\"><unum "
        "size=\"4\">116</unum></var><var name=\"sh_size\" type=\"u32\" "
        "off=\"224\"><unum size=\"4\">12</unum></var><var name=\"sh_link\" "
        "type=\"u32\" off=\"228\"><unum size=\"4\">0</unum></var><var "
        "name=\"sh_info\" type=\"u32\" off=\"232\"><unum "
        "size=\"4\">0</unum></var><var name=\"sh_addralign\" type=\"u32\" "
        "off=\"236\"><unum size=\"4\">4</unum></var><var name=\"sh_entsize\" "
        "type=\"u32\" off=\"240\"><unum size=\"4\">0</unum></var></var><var "
        "name=\"PrevShName\" type=\"string\" "
        "off=\"151\"><buffer>2e74657874</buffer></var><var name=\"shdr\" "
        "type=\"Elf32_Shdr\" off=\"244\"><var name=\"sh_name\" type=\"u32\" "
        "off=\"244\"><unum size=\"4\">17</unum></var><var name=\"sh_type\" "
        "type=\"ShdrType\" off=\"248\"><enum_value "
        "mnemonic=\"SHT_PROGBITS\">1</enum_value></var><var name=\"sh_flags\" "
        "type=\"ShrFlag\" off=\"252\"><enum_value mnemonic=\"SHF_WRITE | "
        "SHF_ALLOC\">3</enum_value></var><var name=\"sh_addr\" type=\"u32\" "
        "off=\"256\"><unum size=\"4\">134516864</unum></var><var "
        "name=\"sh_offset\" type=\"u32\" off=\"260\"><unum "
        "size=\"4\">128</unum></var><var name=\"sh_size\" type=\"u32\" "
        "off=\"264\"><unum size=\"4\">12</unum></var><var name=\"sh_link\" "
        "type=\"u32\" off=\"268\"><unum size=\"4\">0</unum></var><var "
        "name=\"sh_info\" type=\"u32\" off=\"272\"><unum "
        "size=\"4\">0</unum></var><var name=\"sh_addralign\" type=\"u32\" "
        "off=\"276\"><unum size=\"4\">4</unum></var><var name=\"sh_entsize\" "
        "type=\"u32\" off=\"280\"><unum size=\"4\">0</unum></var></var><var "
        "name=\"PrevShName\" type=\"string\" "
        "off=\"157\"><buffer>2e64617461</buffer></var><var name=\"shdr\" "
        "type=\"Elf32_Shdr\" off=\"284\"><var name=\"sh_name\" type=\"u32\" "
        "off=\"284\"><unum size=\"4\">1</unum></var><var name=\"sh_type\" "
        "type=\"ShdrType\" off=\"288\"><enum_value "
        "mnemonic=\"SHT_STRTAB\">3</enum_value></var><var name=\"sh_flags\" "
        "type=\"ShrFlag\" off=\"292\"><enum_value "
        "mnemonic=\"NONE\">0</enum_value></var><var name=\"sh_addr\" "
        "type=\"u32\" off=\"296\"><unum size=\"4\">0</unum></var><var "
        "name=\"sh_offset\" type=\"u32\" off=\"300\"><unum "
        "size=\"4\">140</unum></var><var name=\"sh_size\" type=\"u32\" "
        "off=\"304\"><unum size=\"4\">23</unum></var><var name=\"sh_link\" "
        "type=\"u32\" off=\"308\"><unum size=\"4\">0</unum></var><var "
        "name=\"sh_info\" type=\"u32\" off=\"312\"><unum "
        "size=\"4\">0</unum></var><var name=\"sh_addralign\" type=\"u32\" "
        "off=\"316\"><unum size=\"4\">1</unum></var><var name=\"sh_entsize\" "
        "type=\"u32\" off=\"320\"><unum size=\"4\">0</unum></var></var><var "
        "name=\"PrevShName\" type=\"string\" "
        "off=\"141\"><buffer>2e7368737472746162</buffer></var></root>\n";

    int r = TEST_FAILED;
    if (exec_commands_on("t/x ./templates/elf.bhe", elf_fb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(template_pe)(void)
{
    // clang-format off
    const char* expected = 
        "b+00000000            DosHeader: \n"
        "b+00000000                  e_magic: 5a4d\n"
        "b+00000002                   e_cblp: 0000\n"
        "b+00000004                     e_cp: 4550\n"
        "b+00000006                   e_crlc: 0000\n"
        "b+00000008                e_cparhdr: 8664\n"
        "b+0000000a               e_minalloc: 0001\n"
        "b+0000000c               e_maxalloc: 654d\n"
        "b+0000000e                     e_ss: 7373\n"
        "b+00000010                     e_sp: 6761\n"
        "b+00000012                   e_csum: 4265\n"
        "b+00000014                     e_ip: 786f\n"
        "b+00000016                     e_cs: 0057\n"
        "b+00000018                 e_lfarlc: 0080\n"
        "b+0000001a                   e_ovno: 0022\n"
        "b+0000001c                    e_res: [ 020b, 0000, 0102, 0000 ]\n"
        "b+00000024                  e_oemid: 25ff\n"
        "b+00000026                e_oeminfo: 006a\n"
        "b+00000028                   e_res2: [ 0000, 0000, 00fc, 0000, 000a, 0000, 0000, 4000, 0001, 0000 ]\n"
        "b+0000003c                 e_lfanew: 00000004\n"
        "b+00000004             NTHeader: \n"
        "b+00000004                Signature: 00004550\n"
        "b+00000008               FileHeader: \n"
        "b+00000008                      Machine: AMD64\n"
        "b+0000000a             NumberOfSections: 0001\n"
        "b+0000000c                TimeDateStamp: 7373654d\n"
        "b+00000010         PointerToSymbolTable: 42656761\n"
        "b+00000014              NumberOfSymbols: 0057786f\n"
        "b+00000018         SizeOfOptionalHeader: 0080\n"
        "b+0000001a              Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE\n"
        "b+0000001c      ImageOptionalHeader: \n"
        "b+0000001c                        Magic: 020b\n"
        "b+0000001e           MajorLinkerVersion: 00\n"
        "b+0000001f           MinorLinkerVersion: 00\n"
        "b+00000020                   SizeOfCode: 00000102\n"
        "b+00000024        SizeOfInitializedData: 006a25ff\n"
        "b+00000028      SizeOfUninitializedData: 00000000\n"
        "b+0000002c          AddressOfEntryPoint: 000000fc\n"
        "b+00000030                   BaseOfCode: 0000000a\n"
        "b+00000034                    ImageBase: 0000000140000000\n"
        "b+0000003c             SectionAlignment: 00000004\n"
        "b+00000040                FileAlignment: 00000004\n"
        "b+00000044  MajorOperatingSystemVersion: 8d48\n"
        "b+00000046  MinorOperatingSystemVersion: b852\n"
        "b+00000048            MajorImageVersion: daeb\n"
        "b+0000004a            MinorImageVersion: 0000\n"
        "b+0000004c        MajorSubsystemVersion: 0006\n"
        "b+0000004e        MinorSubsystemVersion: 0000\n"
        "b+00000050            Win32VersionValue: 00000000\n"
        "b+00000054                  SizeOfImage: 0000010c\n"
        "b+00000058                SizeOfHeaders: 000000c4\n"
        "b+0000005c                     CheckSum: 00000000\n"
        "b+00000060                    Subsystem: WINDOWS_GUI\n"
        "b+00000062           DllCharacteristics: HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE\n"
        "b+00000064           SizeOfStackReserve: 0000000000100000\n"
        "b+0000006c            SizeOfStackCommit: 0000000000001000\n"
        "b+00000074            SizeOfHeapReserve: 0000000000100000\n"
        "b+0000007c             SizeOfHeapCommit: 642e323352455355\n"
        "b+00000084                  LoaderFlags: 00006c6c\n"
        "b+00000088          NumberOfRvaAndSizes: 00000002\n"
        "b+0000008c         DataDirArray: \n"
        "b+0000008c                   Export: \n"
        "b+0000008c               VirtualAddress: 0040b941\n"
        "b+00000090                         Size: b0eb0024\n"
        "b+00000094                   Import: \n"
        "b+00000094               VirtualAddress: 000000f4\n"
        "b+00000098                         Size: 00000018\n"
        "b+0000009c                 Resource: \n"
        "b+0000009c               VirtualAddress: 8d4c002e\n"
        "b+000000a0                         Size: e8ebc842\n"
        "b+000000a4                Exception: \n"
        "b+000000a4               VirtualAddress: 00000102\n"
        "b+000000a8                         Size: 00000094\n"
        "b+000000ac                 Security: \n"
        "b+000000ac               VirtualAddress: 00000102\n"
        "b+000000b0                         Size: 00000094\n"
        "b+000000b4               Relocation: \n"
        "b+000000b4               VirtualAddress: 00420041\n"
        "b+000000b8                         Size: 00440043\n"
        "b+000000bc                    Debug: \n"
        "b+000000bc               VirtualAddress: 00460045\n"
        "b+000000c0                         Size: 00000047\n"
        "b+000000c4             Architecture: \n"
        "b+000000c4               VirtualAddress: dcafd83d\n"
        "b+000000c8                         Size: 00540020\n"
        "b+000000cc                GlobalPtr: \n"
        "b+000000cc               VirtualAddress: 006e0069\n"
        "b+000000d0                         Size: 00500079\n"
        "b+000000d4                      Tls: \n"
        "b+000000d4               VirtualAddress: 00200045\n"
        "b+000000d8                         Size: 006e006f\n"
        "b+000000dc               LoadConfig: \n"
        "b+000000dc               VirtualAddress: 00570020\n"
        "b+000000e0                         Size: 006e0069\n"
        "b+000000e4              BoundImport: \n"
        "b+000000e4               VirtualAddress: 006f0064\n"
        "b+000000e8                         Size: 00730077\n"
        "b+000000ec                      Iat: \n"
        "b+000000ec               VirtualAddress: 00310020\n"
        "b+000000f0                         Size: 00000030\n"
        "b+000000f4              DelayImport: \n"
        "b+000000f4               VirtualAddress: 00000108\n"
        "b+000000f8                         Size: 00000000\n"
        "b+000000fc                ClrHeader: \n"
        "b+000000fc               VirtualAddress: 9eebc931\n"
        "b+00000100                         Size: 0000007c\n"
        "b+00000104                 Reserved: \n"
        "b+00000104               VirtualAddress: 00000094\n"
        "b+00000108                         Size: 0000000a\n"
        "b+0000009c        SectionHeader: \n"
        "b+0000009c                     Name: '.'\n"
        "b+000000a4                     Misc: 00000102\n"
        "b+000000a8           VirtualAddress: 00000094\n"
        "b+000000ac            SizeOfRawData: 00000102\n"
        "b+000000b0         PointerToRawData: 00000094\n"
        "b+000000b4     PointerToRelocations: 00420041\n"
        "b+000000b8     PointerToLinenumbers: 00440043\n"
        "b+000000bc      NumberOfRelocations: 0045\n"
        "b+000000be      NumberOfLinenumbers: 0046\n"
        "b+000000c0          Characteristics: CNT_INITIALIZED_DATA\n"
        "[!] section size [ 258 ] is greater than remaining size [ 120 ], trimming\n"
        "b+00000094          SectionData: f4000000180000002e004c8d42c8ebe8...\n"
        "";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands_on("t ./templates/pe.bhe", pe_fb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(template_zip)(void)
{
    // clang-format off
    const char* expected = 
        "b+00000357  endOfCentralDir: \n"
        "b+00000357            signature: 'PK\\x05\\x06'\n"
        "b+0000035b          disk_number: 0000\n"
        "b+0000035d     central_dir_disk: 0000\n"
        "b+0000035f  central_dir_entries: 0005\n"
        "b+00000361        total_entries: 0005\n"
        "b+00000363     central_dir_size: 000001bd\n"
        "b+00000367   central_dir_offset: 0000019a\n"
        "b+0000036b       comment_length: 0000\n"
        "\n"
        "b+0000019a       dirElement: \n"
        "b+0000019a            signature: 'PK\\x01\\x02'\n"
        "b+0000019e      version_made_by: 031e\n"
        "b+000001a0       version_needed: 000a\n"
        "b+000001a2                flags: NONE\n"
        "b+000001a4   compression_method: NO_COMPRESSION\n"
        "b+000001a6             mod_time: a2fa\n"
        "b+000001a8             mod_date: 5ad9\n"
        "b+000001aa                crc32: 153b7d68\n"
        "b+000001ae      compressed_size: 00000005\n"
        "b+000001b2    uncompressed_size: 00000005\n"
        "b+000001b6      filename_length: 0008\n"
        "b+000001b8   extra_field_length: 0018\n"
        "b+000001ba       comment_length: 0000\n"
        "b+000001bc          disk_number: 0000\n"
        "b+000001be  internal_attributes: 0001\n"
        "b+000001c0  external_attributes: 81a40000\n"
        "b+000001c4  local_header_offset: 00000000\n"
        "b+000001c8             filename: 'file.txt'\n"
        "b+000001d0           extraField: \n"
        "b+000001d0                header_id: EXTRA_FIELD_EXTENDED_TIMESTAMP\n"
        "b+000001d2            ext_timestamp: \n"
        "b+000001d2                    data_size: 0005\n"
        "b+000001d4                        flags: 03\n"
        "b+000001d5                         time: 685c3eb8\n"
        "b+000001d9           extraField: \n"
        "b+000001d9                header_id: EXTRA_FIELD_UNIX_NEW\n"
        "b+000001db                 unix_new: \n"
        "b+000001db                    data_size: 000b\n"
        "b+000001dd                      version: 01\n"
        "b+000001de                          uid: \n"
        "b+000001de                             size: 04\n"
        "b+000001df                            value: 000001f5\n"
        "b+000001e3                          gid: \n"
        "b+000001e3                             size: 04\n"
        "b+000001e4                            value: 00000014\n"
        "b+00000000     localElement: \n"
        "b+00000000            signature: 504b0304\n"
        "b+00000004              version: 000a\n"
        "b+00000006                flags: NONE\n"
        "b+00000008          compression: NO_COMPRESSION\n"
        "b+0000000a             mod_time: a2fa\n"
        "b+0000000c             mod_date: 5ad9\n"
        "b+0000000e                crc32: 153b7d68\n"
        "b+00000012      compressed_size: 00000005\n"
        "b+00000016    uncompressed_size: 00000005\n"
        "b+0000001a         filename_len: 0008\n"
        "b+0000001c      extra_field_len: 001c\n"
        "b+0000001e             filename: 'file.txt'\n"
        "b+00000026           extraField: \n"
        "b+00000026                header_id: EXTRA_FIELD_EXTENDED_TIMESTAMP\n"
        "b+00000028            ext_timestamp: \n"
        "b+00000028                    data_size: 0009\n"
        "b+0000002a                        flags: 03\n"
        "b+0000002b                         time: 685c3eb8\n"
        "b+0000002f                         time: 685c3eb9\n"
        "b+00000033           extraField: \n"
        "b+00000033                header_id: EXTRA_FIELD_UNIX_NEW\n"
        "b+00000035                 unix_new: \n"
        "b+00000035                    data_size: 000b\n"
        "b+00000037                      version: 01\n"
        "b+00000038                          uid: \n"
        "b+00000038                             size: 04\n"
        "b+00000039                            value: 000001f5\n"
        "b+0000003d                          gid: \n"
        "b+0000003d                             size: 04\n"
        "b+0000003e                            value: 00000014\n"
        "b+00000042             data: 6369616f0a\n"
        "\n"
        "b+000001e8       dirElement: \n"
        "b+000001e8            signature: 'PK\\x01\\x02'\n"
        "b+000001ec      version_made_by: 031e\n"
        "b+000001ee       version_needed: 000a\n"
        "b+000001f0                flags: NONE\n"
        "b+000001f2   compression_method: NO_COMPRESSION\n"
        "b+000001f4             mod_time: a2f2\n"
        "b+000001f6             mod_date: 5ad9\n"
        "b+000001f8                crc32: 00000000\n"
        "b+000001fc      compressed_size: 00000000\n"
        "b+00000200    uncompressed_size: 00000000\n"
        "b+00000204      filename_length: 0007\n"
        "b+00000206   extra_field_length: 0018\n"
        "b+00000208       comment_length: 0000\n"
        "b+0000020a          disk_number: 0000\n"
        "b+0000020c  internal_attributes: 0000\n"
        "b+0000020e  external_attributes: 41ed0010\n"
        "b+00000212  local_header_offset: 00000047\n"
        "b+00000216             filename: 'folder/'\n"
        "b+0000021d           extraField: \n"
        "b+0000021d                header_id: EXTRA_FIELD_EXTENDED_TIMESTAMP\n"
        "b+0000021f            ext_timestamp: \n"
        "b+0000021f                    data_size: 0005\n"
        "b+00000221                        flags: 03\n"
        "b+00000222                         time: 685c3ea7\n"
        "b+00000226           extraField: \n"
        "b+00000226                header_id: EXTRA_FIELD_UNIX_NEW\n"
        "b+00000228                 unix_new: \n"
        "b+00000228                    data_size: 000b\n"
        "b+0000022a                      version: 01\n"
        "b+0000022b                          uid: \n"
        "b+0000022b                             size: 04\n"
        "b+0000022c                            value: 000001f5\n"
        "b+00000230                          gid: \n"
        "b+00000230                             size: 04\n"
        "b+00000231                            value: 00000014\n"
        "b+00000047     localElement: \n"
        "b+00000047            signature: 504b0304\n"
        "b+0000004b              version: 000a\n"
        "b+0000004d                flags: NONE\n"
        "b+0000004f          compression: NO_COMPRESSION\n"
        "b+00000051             mod_time: a2f2\n"
        "b+00000053             mod_date: 5ad9\n"
        "b+00000055                crc32: 00000000\n"
        "b+00000059      compressed_size: 00000000\n"
        "b+0000005d    uncompressed_size: 00000000\n"
        "b+00000061         filename_len: 0007\n"
        "b+00000063      extra_field_len: 001c\n"
        "b+00000065             filename: 'folder/'\n"
        "b+0000006c           extraField: \n"
        "b+0000006c                header_id: EXTRA_FIELD_EXTENDED_TIMESTAMP\n"
        "b+0000006e            ext_timestamp: \n"
        "b+0000006e                    data_size: 0009\n"
        "b+00000070                        flags: 03\n"
        "b+00000071                         time: 685c3ea7\n"
        "b+00000075                         time: 685c3ec2\n"
        "b+00000079           extraField: \n"
        "b+00000079                header_id: EXTRA_FIELD_UNIX_NEW\n"
        "b+0000007b                 unix_new: \n"
        "b+0000007b                    data_size: 000b\n"
        "b+0000007d                      version: 01\n"
        "b+0000007e                          uid: \n"
        "b+0000007e                             size: 04\n"
        "b+0000007f                            value: 000001f5\n"
        "b+00000083                          gid: \n"
        "b+00000083                             size: 04\n"
        "b+00000084                            value: 00000014\n"
        "\n"
        "b+00000235       dirElement: \n"
        "b+00000235            signature: 'PK\\x01\\x02'\n"
        "b+00000239      version_made_by: 031e\n"
        "b+0000023b       version_needed: 000a\n"
        "b+0000023d                flags: NONE\n"
        "b+0000023f   compression_method: NO_COMPRESSION\n"
        "b+00000241             mod_time: a2eb\n"
        "b+00000243             mod_date: 5ad9\n"
        "b+00000245                crc32: 00000000\n"
        "b+00000249      compressed_size: 00000000\n"
        "b+0000024d    uncompressed_size: 00000000\n"
        "b+00000251      filename_length: 0011\n"
        "b+00000253   extra_field_length: 0018\n"
        "b+00000255       comment_length: 0000\n"
        "b+00000257          disk_number: 0000\n"
        "b+00000259  internal_attributes: 0000\n"
        "b+0000025b  external_attributes: 41ed0010\n"
        "b+0000025f  local_header_offset: 00000088\n"
        "b+00000263             filename: 'folder/subfolder/'\n"
        "b+00000274           extraField: \n"
        "b+00000274                header_id: EXTRA_FIELD_EXTENDED_TIMESTAMP\n"
        "b+00000276            ext_timestamp: \n"
        "b+00000276                    data_size: 0005\n"
        "b+00000278                        flags: 03\n"
        "b+00000279                         time: 685c3e9a\n"
        "b+0000027d           extraField: \n"
        "b+0000027d                header_id: EXTRA_FIELD_UNIX_NEW\n"
        "b+0000027f                 unix_new: \n"
        "b+0000027f                    data_size: 000b\n"
        "b+00000281                      version: 01\n"
        "b+00000282                          uid: \n"
        "b+00000282                             size: 04\n"
        "b+00000283                            value: 000001f5\n"
        "b+00000287                          gid: \n"
        "b+00000287                             size: 04\n"
        "b+00000288                            value: 00000014\n"
        "b+00000088     localElement: \n"
        "b+00000088            signature: 504b0304\n"
        "b+0000008c              version: 000a\n"
        "b+0000008e                flags: NONE\n"
        "b+00000090          compression: NO_COMPRESSION\n"
        "b+00000092             mod_time: a2eb\n"
        "b+00000094             mod_date: 5ad9\n"
        "b+00000096                crc32: 00000000\n"
        "b+0000009a      compressed_size: 00000000\n"
        "b+0000009e    uncompressed_size: 00000000\n"
        "b+000000a2         filename_len: 0011\n"
        "b+000000a4      extra_field_len: 001c\n"
        "b+000000a6             filename: 'folder/subfolder/'\n"
        "b+000000b7           extraField: \n"
        "b+000000b7                header_id: EXTRA_FIELD_EXTENDED_TIMESTAMP\n"
        "b+000000b9            ext_timestamp: \n"
        "b+000000b9                    data_size: 0009\n"
        "b+000000bb                        flags: 03\n"
        "b+000000bc                         time: 685c3e9a\n"
        "b+000000c0                         time: 685c3ec2\n"
        "b+000000c4           extraField: \n"
        "b+000000c4                header_id: EXTRA_FIELD_UNIX_NEW\n"
        "b+000000c6                 unix_new: \n"
        "b+000000c6                    data_size: 000b\n"
        "b+000000c8                      version: 01\n"
        "b+000000c9                          uid: \n"
        "b+000000c9                             size: 04\n"
        "b+000000ca                            value: 000001f5\n"
        "b+000000ce                          gid: \n"
        "b+000000ce                             size: 04\n"
        "b+000000cf                            value: 00000014\n"
        "\n"
        "b+0000028c       dirElement: \n"
        "b+0000028c            signature: 'PK\\x01\\x02'\n"
        "b+00000290      version_made_by: 031e\n"
        "b+00000292       version_needed: 000a\n"
        "b+00000294                flags: NONE\n"
        "b+00000296   compression_method: NO_COMPRESSION\n"
        "b+00000298             mod_time: a2eb\n"
        "b+0000029a             mod_date: 5ad9\n"
        "b+0000029c                crc32: 9d23d8ef\n"
        "b+000002a0      compressed_size: 00000008\n"
        "b+000002a4    uncompressed_size: 00000008\n"
        "b+000002a8      filename_length: 0026\n"
        "b+000002aa   extra_field_length: 0018\n"
        "b+000002ac       comment_length: 0000\n"
        "b+000002ae          disk_number: 0000\n"
        "b+000002b0  internal_attributes: 0001\n"
        "b+000002b2  external_attributes: 81a40000\n"
        "b+000002b6  local_header_offset: 000000d3\n"
        "b+000002ba             filename: 'folder/subfolder/file_in_subfolder.txt'\n"
        "b+000002e0           extraField: \n"
        "b+000002e0                header_id: EXTRA_FIELD_EXTENDED_TIMESTAMP\n"
        "b+000002e2            ext_timestamp: \n"
        "b+000002e2                    data_size: 0005\n"
        "b+000002e4                        flags: 03\n"
        "b+000002e5                         time: 685c3e9a\n"
        "b+000002e9           extraField: \n"
        "b+000002e9                header_id: EXTRA_FIELD_UNIX_NEW\n"
        "b+000002eb                 unix_new: \n"
        "b+000002eb                    data_size: 000b\n"
        "b+000002ed                      version: 01\n"
        "b+000002ee                          uid: \n"
        "b+000002ee                             size: 04\n"
        "b+000002ef                            value: 000001f5\n"
        "b+000002f3                          gid: \n"
        "b+000002f3                             size: 04\n"
        "b+000002f4                            value: 00000014\n"
        "b+000000d3     localElement: \n"
        "b+000000d3            signature: 504b0304\n"
        "b+000000d7              version: 000a\n"
        "b+000000d9                flags: NONE\n"
        "b+000000db          compression: NO_COMPRESSION\n"
        "b+000000dd             mod_time: a2eb\n"
        "b+000000df             mod_date: 5ad9\n"
        "b+000000e1                crc32: 9d23d8ef\n"
        "b+000000e5      compressed_size: 00000008\n"
        "b+000000e9    uncompressed_size: 00000008\n"
        "b+000000ed         filename_len: 0026\n"
        "b+000000ef      extra_field_len: 001c\n"
        "b+000000f1             filename: 'folder/subfolder/file_in_subfolder.txt'\n"
        "b+00000117           extraField: \n"
        "b+00000117                header_id: EXTRA_FIELD_EXTENDED_TIMESTAMP\n"
        "b+00000119            ext_timestamp: \n"
        "b+00000119                    data_size: 0009\n"
        "b+0000011b                        flags: 03\n"
        "b+0000011c                         time: 685c3e9a\n"
        "b+00000120                         time: 685c3e9b\n"
        "b+00000124           extraField: \n"
        "b+00000124                header_id: EXTRA_FIELD_UNIX_NEW\n"
        "b+00000126                 unix_new: \n"
        "b+00000126                    data_size: 000b\n"
        "b+00000128                      version: 01\n"
        "b+00000129                          uid: \n"
        "b+00000129                             size: 04\n"
        "b+0000012a                            value: 000001f5\n"
        "b+0000012e                          gid: \n"
        "b+0000012e                             size: 04\n"
        "b+0000012f                            value: 00000014\n"
        "b+00000133             data: 636f6e74656e740a\n"
        "\n"
        "b+000002f8       dirElement: \n"
        "b+000002f8            signature: 'PK\\x01\\x02'\n"
        "b+000002fc      version_made_by: 031e\n"
        "b+000002fe       version_needed: 000a\n"
        "b+00000300                flags: NONE\n"
        "b+00000302   compression_method: NO_COMPRESSION\n"
        "b+00000304             mod_time: a2f2\n"
        "b+00000306             mod_date: 5ad9\n"
        "b+00000308                crc32: ec6267d3\n"
        "b+0000030c      compressed_size: 0000000c\n"
        "b+00000310    uncompressed_size: 0000000c\n"
        "b+00000314      filename_length: 0019\n"
        "b+00000316   extra_field_length: 0018\n"
        "b+00000318       comment_length: 0000\n"
        "b+0000031a          disk_number: 0000\n"
        "b+0000031c  internal_attributes: 0001\n"
        "b+0000031e  external_attributes: 81a40000\n"
        "b+00000322  local_header_offset: 0000013b\n"
        "b+00000326             filename: 'folder/file_in_folder.txt'\n"
        "b+0000033f           extraField: \n"
        "b+0000033f                header_id: EXTRA_FIELD_EXTENDED_TIMESTAMP\n"
        "b+00000341            ext_timestamp: \n"
        "b+00000341                    data_size: 0005\n"
        "b+00000343                        flags: 03\n"
        "b+00000344                         time: 685c3ea7\n"
        "b+00000348           extraField: \n"
        "b+00000348                header_id: EXTRA_FIELD_UNIX_NEW\n"
        "b+0000034a                 unix_new: \n"
        "b+0000034a                    data_size: 000b\n"
        "b+0000034c                      version: 01\n"
        "b+0000034d                          uid: \n"
        "b+0000034d                             size: 04\n"
        "b+0000034e                            value: 000001f5\n"
        "b+00000352                          gid: \n"
        "b+00000352                             size: 04\n"
        "b+00000353                            value: 00000014\n"
        "b+0000013b     localElement: \n"
        "b+0000013b            signature: 504b0304\n"
        "b+0000013f              version: 000a\n"
        "b+00000141                flags: NONE\n"
        "b+00000143          compression: NO_COMPRESSION\n"
        "b+00000145             mod_time: a2f2\n"
        "b+00000147             mod_date: 5ad9\n"
        "b+00000149                crc32: ec6267d3\n"
        "b+0000014d      compressed_size: 0000000c\n"
        "b+00000151    uncompressed_size: 0000000c\n"
        "b+00000155         filename_len: 0019\n"
        "b+00000157      extra_field_len: 001c\n"
        "b+00000159             filename: 'folder/file_in_folder.txt'\n"
        "b+00000172           extraField: \n"
        "b+00000172                header_id: EXTRA_FIELD_EXTENDED_TIMESTAMP\n"
        "b+00000174            ext_timestamp: \n"
        "b+00000174                    data_size: 0009\n"
        "b+00000176                        flags: 03\n"
        "b+00000177                         time: 685c3ea7\n"
        "b+0000017b                         time: 685c3ea8\n"
        "b+0000017f           extraField: \n"
        "b+0000017f                header_id: EXTRA_FIELD_UNIX_NEW\n"
        "b+00000181                 unix_new: \n"
        "b+00000181                    data_size: 000b\n"
        "b+00000183                      version: 01\n"
        "b+00000184                          uid: \n"
        "b+00000184                             size: 04\n"
        "b+00000185                            value: 000001f5\n"
        "b+00000189                          gid: \n"
        "b+00000189                             size: 04\n"
        "b+0000018a                            value: 00000014\n"
        "b+0000018e             data: 636f6e74656e74203132330a\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_zip, sizeof(sample_zip));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/zip.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_squashfs_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000         superblock: \n"
        "b+00000000                  magic: 'hsqs'\n"
        "b+00000004            inode_count: 00000009\n"
        "b+00000008               mod_time: 68d43dba\n"
        "b+0000000c             block_size: 00020000\n"
        "b+00000010             frag_count: 00000001\n"
        "b+00000014             compressor: GZIP\n"
        "b+00000016              block_log: 0011\n"
        "b+00000018                  flags: INODE_UNCOMPRESSED | DATA_DEDUPLICATED | NFS_EXPORT_TABLE_EXISTS\n"
        "b+0000001a               id_count: 0002\n"
        "b+0000001c          version_major: 0004\n"
        "b+0000001e          version_minor: 0000\n"
        "b+00000020             root_inode: 00000000000000d9\n"
        "b+00000028             bytes_used: 000000000000026f\n"
        "b+00000030               id_table: 0000000000000267\n"
        "b+00000038            xattr_table: ffffffffffffffff\n"
        "b+00000040            inode_table: 000000000000006a\n"
        "b+00000048              dir_table: 0000000000000165\n"
        "b+00000050             frag_table: 0000000000000203\n"
        "b+00000058           export_table: 0000000000000255\n"
        "b+0000006c            inode_h: \n"
        "b+0000006c                   type: NAMED_PIPE\n"
        "b+0000006e            permissions: 01b4\n"
        "b+00000070                    uid: 0000\n"
        "b+00000072                    gid: 0000\n"
        "b+00000074                  mtime: 68d43ce4\n"
        "b+00000078           inode_number: 00000001\n"
        "b+0000007c          inode_ipc: \n"
        "b+0000007c             link_count: 00000001\n"
        "b+00000080            inode_h: \n"
        "b+00000080                   type: SOCKET\n"
        "b+00000082            permissions: 01fd\n"
        "b+00000084                    uid: 0000\n"
        "b+00000086                    gid: 0000\n"
        "b+00000088                  mtime: 68d43d1e\n"
        "b+0000008c           inode_number: 00000002\n"
        "b+00000090          inode_ipc: \n"
        "b+00000090             link_count: 00000001\n"
        "b+00000094            inode_h: \n"
        "b+00000094                   type: BLOCK_DEV\n"
        "b+00000096            permissions: 01a4\n"
        "b+00000098                    uid: 0001\n"
        "b+0000009a                    gid: 0001\n"
        "b+0000009c                  mtime: 68d43d4a\n"
        "b+000000a0           inode_number: 00000003\n"
        "b+000000a4         inode_spec: \n"
        "b+000000a4             link_count: 00000001\n"
        "b+000000a8                dev_num: 000007c8\n"
        "b+000000ac            inode_h: \n"
        "b+000000ac                   type: CHAR_DEV\n"
        "b+000000ae            permissions: 01a4\n"
        "b+000000b0                    uid: 0001\n"
        "b+000000b2                    gid: 0001\n"
        "b+000000b4                  mtime: 68d43d66\n"
        "b+000000b8           inode_number: 00000004\n"
        "b+000000bc         inode_spec: \n"
        "b+000000bc             link_count: 00000001\n"
        "b+000000c0                dev_num: 00005901\n"
        "b+000000c4            inode_h: \n"
        "b+000000c4                   type: FILE\n"
        "b+000000c6            permissions: 01b4\n"
        "b+000000c8                    uid: 0000\n"
        "b+000000ca                    gid: 0000\n"
        "b+000000cc                  mtime: 68d43d77\n"
        "b+000000d0           inode_number: 00000005\n"
        "b+000000d4         inode_file: \n"
        "b+000000d4           blocks_start: 00000000\n"
        "b+000000d8             frag_index: 00000000\n"
        "b+000000dc           block_offset: 00000000\n"
        "b+000000e0              file_size: 00000005\n"
        "b+000000e4        block_sizes: [  ]\n"
        "b+000000e4            inode_h: \n"
        "b+000000e4                   type: SYMLINK\n"
        "b+000000e6            permissions: 01ff\n"
        "b+000000e8                    uid: 0000\n"
        "b+000000ea                    gid: 0000\n"
        "b+000000ec                  mtime: 68d43daf\n"
        "b+000000f0           inode_number: 00000006\n"
        "b+000000f4      inode_symlink: \n"
        "b+000000f4             link_count: 00000001\n"
        "b+000000f8            target_size: 00000009\n"
        "b+000000fc            target_path: 66696c65312e747874\n"
        "b+00000105            inode_h: \n"
        "b+00000105                   type: FILE\n"
        "b+00000107            permissions: 01b4\n"
        "b+00000109                    uid: 0000\n"
        "b+0000010b                    gid: 0000\n"
        "b+0000010d                  mtime: 68d43cbb\n"
        "b+00000111           inode_number: 00000008\n"
        "b+00000115         inode_file: \n"
        "b+00000115           blocks_start: 00000000\n"
        "b+00000119             frag_index: 00000000\n"
        "b+0000011d           block_offset: 00000005\n"
        "b+00000121              file_size: 00000005\n"
        "b+00000125        block_sizes: [  ]\n"
        "b+00000125            inode_h: \n"
        "b+00000125                   type: DIRECTORY\n"
        "b+00000127            permissions: 01fd\n"
        "b+00000129                    uid: 0000\n"
        "b+0000012b                    gid: 0000\n"
        "b+0000012d                  mtime: 68d43cbb\n"
        "b+00000131           inode_number: 00000007\n"
        "b+00000135          inode_dir: \n"
        "b+00000135            block_index: 00000000\n"
        "b+00000139             link_count: 00000002\n"
        "b+0000013d              file_size: 0020\n"
        "b+0000013f           block_offset: 0000\n"
        "b+00000141           parent_inode: 00000009\n"
        "b+00000167         dir_header: \n"
        "b+00000167                  count: 00000000\n"
        "b+0000016b                  start: 00000000\n"
        "b+0000016f           inode_number: 00000008\n"
        "b+00000173          dir_items: [ \n"
        "                              [0]\n"
        "b+00000173                 offset: 0099\n"
        "b+00000175           inode_offset: 0000\n"
        "b+00000177                   type: 0002\n"
        "b+00000179              name_size: 0008\n"
        "b+0000017b                   name: 'file0.txt' ]\n"
        "b+00000184            inode_h: \n"
        "b+00000184                   type: NAMED_PIPE\n"
        "b+00000186            permissions: 0000\n"
        "b+00000188                    uid: 0000\n"
        "b+0000018a                    gid: 0000\n"
        "b+0000018c                  mtime: 00000001\n"
        "b+00000190           inode_number: 00000000\n"
        "b+00000194          inode_ipc: \n"
        "b+00000194             link_count: 00030006\n";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_squashfs, sizeof(sample_squashfs));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/squashfs.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_jpeg_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000       chunk: \n"
        "b+00000000              id: SOI\n"
        "b+00000002  app0_chunk: \n"
        "b+00000002              id: APP0\n"
        "b+00000004            size: 16\n"
        "b+00000006      identifier: 'JFIF'\n"
        "b+0000000b    JFIF_version: 257\n"
        "b+0000000d   density_units: 1\n"
        "b+0000000e       x_density: 72\n"
        "b+00000010       y_density: 72\n"
        "b+00000012     x_thumbnail: 0\n"
        "b+00000013     y_thumbnail: 0\n"
        "b+00000014       chunk: \n"
        "b+00000014              id: DQT\n"
        "b+00000016            size: 67\n"
        "b+00000018            data: 0050373c463c32504641465a55505f78...\n"
        "b+00000059       chunk: \n"
        "b+00000059              id: DQT\n"
        "b+0000005b            size: 67\n"
        "b+0000005d            data: 01555a5a786978eb8282ebffffffffff...\n"
        "b+0000009e       chunk: \n"
        "b+0000009e              id: SOF0\n"
        "b+000000a0            size: 17\n"
        "b+000000a2            data: 080020002003012200021101031101\n"
        "b+000000b1       chunk: \n"
        "b+000000b1              id: DHT\n"
        "b+000000b3            size: 23\n"
        "b+000000b5            data: 00000301000000000000000000000000...\n"
        "b+000000ca       chunk: \n"
        "b+000000ca              id: DHT\n"
        "b+000000cc            size: 37\n"
        "b+000000ce            data: 10010002000503040300000000000000...\n"
        "b+000000f1       chunk: \n"
        "b+000000f1              id: DHT\n"
        "b+000000f3            size: 22\n"
        "b+000000f5            data: 01010101000000000000000000000000...\n"
        "b+00000109       chunk: \n"
        "b+00000109              id: DHT\n"
        "b+0000010b            size: 23\n"
        "b+0000010d            data: 11010101010000000000000000000000...\n"
        "b+00000122  sos_header: \n"
        "b+00000122              id: SOS\n"
        "b+00000124            size: 12\n"
        "b+00000126              ns: 3\n"
        "b+00000127      components: [ \n"
        "                           [0]\n"
        "b+00000127            selector: 1\n"
        "b+00000128             huffman: 0\n"
        "                           [1]\n"
        "b+00000129            selector: 2\n"
        "b+0000012a             huffman: 17\n"
        "                           [2]\n"
        "b+0000012b            selector: 3\n"
        "b+0000012c             huffman: 17 ]\n"
        "b+0000012d              ss: 0\n"
        "b+0000012e              se: 63\n"
        "b+0000012f           ah_al: 0\n"
        "b+00000130    sos_data: d7f6556d8e29a593aa746197dede6fdc...\n"
        "b+0000019b       chunk: \n"
        "b+0000019b              id: EOI\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(not_kitty_jpeg, sizeof(not_kitty_jpeg));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/jpeg.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_png_1)(void)
{
    // clang-format off
    const char* expected = 
    "b+00000000       signature: \n"
    "b+00000000                  b0: 89\n"
    "b+00000001                 png: 'PNG'\n"
    "b+00000004               other: 0d0a1a0a\n"
    "b+00000008            ihdr: \n"
    "b+00000008              length: 0000000d\n"
    "b+0000000c                type: 'IHDR'\n"
    "b+00000010               width: 00000020\n"
    "b+00000014              height: 00000020\n"
    "b+00000018           bit_depth: 08\n"
    "b+00000019          color_type: 03\n"
    "b+0000001a  compression_method: 00\n"
    "b+0000001b       filter_method: 00\n"
    "b+0000001c    interlace_method: 00\n"
    "b+0000001d                 crc: 44a48ac6\n"
    "b+00000021           chunk: \n"
    "b+00000021              length: 00000019\n"
    "b+00000025                type: 'tEXt'\n"
    "b+00000029                data: 536f6674776172650041646f62652049...\n"
    "b+00000042                 crc: 71c9653c\n"
    "b+00000046            plte: \n"
    "b+00000046              length: 0000000f\n"
    "b+0000004a                type: 'PLTE'\n"
    "b+0000004e             entries: [ \n"
    "                               [0]\n"
    "b+0000004e                       r: 66\n"
    "b+0000004f                       g: cc\n"
    "b+00000050                       b: cc\n"
    "                               [1]\n"
    "b+00000051                       r: ff\n"
    "b+00000052                       g: ff\n"
    "b+00000053                       b: ff\n"
    "                               [2]\n"
    "b+00000054                       r: 00\n"
    "b+00000055                       g: 00\n"
    "b+00000056                       b: 00\n"
    "                               [3]\n"
    "b+00000057                       r: 33\n"
    "b+00000058                       g: 99\n"
    "b+00000059                       b: 66\n"
    "                               [4]\n"
    "b+0000005a                       r: 99\n"
    "b+0000005b                       g: ff\n"
    "b+0000005c                       b: cc ]\n"
    "b+0000005d                 crc: 3e4caf15\n"
    "b+00000061            idat: \n"
    "b+00000061              length: 00000061\n"
    "b+00000065                type: 'IDAT'\n"
    "b+00000069     compressed_data: 78dadc93310ec0200c039398ffbfb934...\n"
    "b+000000ca                 crc: b0d7cb9a\n"
    "b+000000ce            iend: \n"
    "b+000000ce              length: 00000000\n"
    "b+000000d2                type: 'IEND'\n"
    "b+000000d6                 crc: ae426082\n"
    "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(not_kitty_png, sizeof(not_kitty_png));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/png.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_mp3_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000        audio: \n"
        "MPEG 2.5 Layer 3 - 8 kbps, 8000 Hz, mono\n"
        "b+00000000            first: \n"
        "b+00000000               header: ffe318c4\n"
        "b+0000000d                 lame: \n"
        "b+0000000d                  encoder: 'LAME3.98.'\n"
        "b+00000016  revision_and_vbr_method: 32\n"
        "b+00000017                  lowpass: 00\n"
        "b+00000018         replay_gain_peak: 00000000\n"
        "b+0000001c        radio_replay_gain: 0000\n"
        "b+0000001e   audiophile_replay_gain: 0000\n"
        "b+00000020   encoding_flags_and_ath: 00\n"
        "b+00000021              abr_bitrate: 00\n"
        "b+00000022        delay_and_padding: 000000\n"
        "b+00000025                     misc: 00\n"
        "b+00000026                 mp3_gain: 00\n"
        "b+00000027      preset_and_surround: 0000\n"
        "b+00000029             music_length: 00000000\n"
        "b+0000002d                music_crc: 0000\n"
        "b+0000002f                  tag_crc: 0000\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_mp3, sizeof(sample_mp3));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/mp3.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_mp4_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000              ftyp: \n"
        "b+00000000              box_size: 00000020\n"
        "b+00000004                  type: 'ftyp'\n"
        "b+00000008           major_brand: 'isom'\n"
        "b+0000000c         minor_version: 00000200\n"
        "b+00000010     compatible_brands: 'isomiso2avc1mp41'\n"
        "b+00000020               box: \n"
        "b+00000020              box_size: 00000008\n"
        "b+00000024                  type: 'free'\n"
        "b+00000028               box: \n"
        "b+00000028              box_size: 00000008\n"
        "b+0000002c                  type: 'mdat'\n"
        "b+00000030         container: \n"
        "b+00000030              box_size: 000000d6\n"
        "b+00000034                  type: 'moov'\n"
        "b+00000038                  mvhd: \n"
        "b+00000038                  box_size: 0000006c\n"
        "b+0000003c                      type: 'mvhd'\n"
        "b+00000040                   version: 00\n"
        "b+00000041                     flags: 000000\n"
        "b+00000044             creation_time: 00000000\n"
        "b+00000048         modification_time: 00000000\n"
        "b+0000004c                 timescale: 000003e8\n"
        "b+00000050                  duration: 00000000\n"
        "b+00000054                      rate: \n"
        "b+00000054                       integer: 0001\n"
        "b+00000056                      fraction: 0000\n"
        "b+00000058                    volume: \n"
        "b+00000058                       integer: 01\n"
        "b+00000059                      fraction: 00\n"
        "b+0000005a                  reserved: 0000\n"
        "b+0000005c                 reserved2: [ 00000000, 00000000 ]\n"
        "b+00000064                    matrix: \n"
        "b+00000064                        values: [ 00010000, 00000000, 00000000, 00000000, 00010000, 00000000, 00000000, 00000000, 40000000 ]\n"
        "b+00000088               pre_defined: [ 00000000, 00000000, 00000000, 00000000, 00000000, 00000000 ]\n"
        "b+000000a0             next_track_id: 00000002\n"
        "b+000000a4             container: \n"
        "b+000000a4                  box_size: 00000062\n"
        "b+000000a8                      type: 'udta'\n"
        "b+000000ac                      meta: \n"
        "b+000000ac                      box_size: 0000005a\n"
        "b+000000b0                          type: 'meta'\n"
        "b+000000b4                       version: 00\n"
        "b+000000b5                         flags: 000000\n"
        "b+000000b8                          hdlr: \n"
        "b+000000b8                          box_size: 00000021\n"
        "b+000000bc                              type: 'hdlr'\n"
        "b+000000c0                           version: 00\n"
        "b+000000c1                             flags: 000000\n"
        "b+000000c4                       pre_defined: 00000000\n"
        "b+000000c8                      handler_type: MDIR\n"
        "b+000000cc                          reserved: [ 6170706c, 00000000, 00000000 ]\n"
        "b+000000d8                              name: ''\n"
        "b+000000d9                     container: \n"
        "b+000000d9                          box_size: 0000002d\n"
        "b+000000dd                              type: 'ilst'\n"
        "b+000000e1                         container: \n"
        "b+000000e1                              box_size: 00000025\n"
        "b+000000e5                                  type: '\\xa9too'\n"
        "b+000000e9                                  data: \n"
        "b+000000e9                                  box_size: 0000001d\n"
        "b+000000ed                                      type: 'data'\n"
        "b+000000f1                            type_indicator: 00000001\n"
        "b+000000f5                                    locale: 00000000\n"
        "b+000000f9                                     value: 'Lavf57.41.100'\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_mp4, sizeof(sample_mp4));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/mp4.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_lzo_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000              block: \n"
        "b+00000000                 header: \n"
        "b+00000000                      magic: 894c5a4f000d0a1a0a\n"
        "b+00000009                    version: 1040\n"
        "b+0000000b                lib_version: 20a0\n"
        "b+0000000d  version_needed_to_extract: 0940\n"
        "b+0000000f                     method: 03\n"
        "b+00000010                      level: 09\n"
        "b+00000011                   flags_hi: F_OS_UNIX\n"
        "b+00000013                   flags_lo: F_ADLER32_D\n"
        "b+00000015                       mode: 000081a4\n"
        "b+00000019                  mtime_low: 659200bc\n"
        "b+0000001d                 mtime_high: 00000000\n"
        "b+00000021               filename_len: 14\n"
        "b+00000022                   filename: 'sample_lzo_input.txt'\n"
        "b+00000036            header_checksum: e5e60ca9\n"
        "b+0000003a                dst_len: 0000000a\n"
        "b+0000003e                src_len: 0000000a\n"
        "b+00000042              d_adler32: 153b0394\n"
        "b+00000046                   data: 68656c6c6f206c7a6f0a\n"
        "b+00000050                dst_len: 00000000\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_lzo, sizeof(sample_lzo));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/lzo.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_gzip_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000       member: \n"
        "b+00000000           header: \n"
        "b+00000000                  id1: 1f\n"
        "b+00000001                  id2: 8b\n"
        "b+00000002   compression_method: DEFLATE\n"
        "b+00000003                flags: NONE\n"
        "b+00000004                mtime: 00000000\n"
        "b+00000008          extra_flags: DEFAULT_COMPRESSION\n"
        "b+00000009                   os: UNIX\n"
        "b+0000000a  compressed_data: cb48cdc9c95748afca2ce00200\n"
        "b+00000017            crc32: 56637c39\n"
        "b+0000001b       input_size: 0000000b\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_gzip, sizeof(sample_gzip));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/gzip.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_rpm_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000             lead: \n"
        "b+00000000                magic: edabeedb\n"
        "b+00000004                major: 03\n"
        "b+00000005                minor: 00\n"
        "b+00000006                 type: 0000\n"
        "b+00000008             arch_num: 0001\n"
        "b+0000000a                 name: 'test-pkg'\n"
        "b+0000004c               os_num: 0001\n"
        "b+0000004e             sig_type: 0005\n"
        "b+00000050             reserved: 00000000000000000000000000000000\n"
        "b+00000060          sig_hdr: \n"
        "b+00000060                magic: 8eade8\n"
        "b+00000063              version: 01\n"
        "b+00000064             reserved: 00000000\n"
        "b+00000068          index_count: 00000001\n"
        "b+0000006c           store_size: 00000004\n"
        "b+00000070      index_entry: \n"
        "b+00000070                  tag: RPMTAG_SIGSIZE\n"
        "b+00000074                 type: RPM_INT32_TYPE\n"
        "b+00000078               offset: 00000000\n"
        "b+0000007c                count: 00000001\n"
        "b+00000080             data: [ 0000002a ]\n"
        "b+00000080         raw_data: 0000002a\n"
        "b+00000084          padding: 00000000\n"
        "b+00000088         main_hdr: \n"
        "b+00000088                magic: 8eade8\n"
        "b+0000008b              version: 01\n"
        "b+0000008c             reserved: 00000000\n"
        "b+00000090          index_count: 00000002\n"
        "b+00000094           store_size: 0000000f\n"
        "b+00000098      index_entry: \n"
        "b+00000098                  tag: RPMTAG_NAME\n"
        "b+0000009c                 type: RPM_STRING_TYPE\n"
        "b+000000a0               offset: 00000000\n"
        "b+000000a4                count: 00000001\n"
        "b+000000b8             data: 'test-pkg'\n"
        "b+000000a8      index_entry: \n"
        "b+000000a8                  tag: RPMTAG_VERSION\n"
        "b+000000ac                 type: RPM_STRING_TYPE\n"
        "b+000000b0               offset: 00000009\n"
        "b+000000b4                count: 00000001\n"
        "b+000000c1             data: '1.0.0'\n"
        "b+000000b8         raw_data: 746573742d706b6700312e302e3000\n"
        "b+000000c7  compressed_cpio: deadbeef\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_rpm, sizeof(sample_rpm));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/rpm.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_pdf_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000     header: \n"
        "b+00000000          magic: '%PDF-'\n"
        "b+00000005        version: '1.4'\n"
        "b+00000009     object: \n"
        "b+00000009             id: '1'\n"
        "b+0000000b     generation: '0'\n"
        "b+0000000d        keyword: 'obj'\n"
        "b+00000010           body: 0a3c3c2f54797065202f436174616c6f...\n"
        "b+00000032    keyword_end: 'endobj'\n"
        "b+00000039     object: \n"
        "b+00000039             id: '2'\n"
        "b+0000003b     generation: '0'\n"
        "b+0000003d        keyword: 'obj'\n"
        "b+00000040           body: 0a3c3c2f54797065202f50616765730a...\n"
        "b+0000006a    keyword_end: 'endobj'\n"
        "b+00000071     object: \n"
        "b+00000071             id: '3'\n"
        "b+00000073     generation: '0'\n"
        "b+00000075        keyword: 'obj'\n"
        "b+00000078           body: 0a3c3c2f54797065202f506167650a2f...\n"
        "b+000000fa    keyword_end: 'endobj'\n"
        "b+00000101     object: \n"
        "b+00000101             id: '4'\n"
        "b+00000103     generation: '0'\n"
        "b+00000105        keyword: 'obj'\n"
        "b+00000108           body: 0a3c3c2f54797065202f466f6e740a2f...\n"
        "b+00000165    keyword_end: 'endobj'\n"
        "b+0000016c     object: \n"
        "b+0000016c             id: '5'\n"
        "b+0000016e     generation: '0'\n"
        "b+00000170        keyword: 'obj'\n"
        "b+00000173           body: 0a3c3c2f4c656e6774682035330a3e3e...\n"
        "b+000001bf    keyword_end: 'endobj'\n"
        "b+000001c6       xref: \n"
        "b+000001c6        keyword: 'xref'\n"
        "b+000001cb     subsection: \n"
        "b+000001cb           first_id: '0'\n"
        "b+000001cd              count: '6'\n"
        "b+000001cf            entries: [ \n"
        "                              [0]\n"
        "b+000001cf                 offset: '0000000000'\n"
        "b+000001d9                  sep_0: 20\n"
        "b+000001da             generation: '65535'\n"
        "b+000001df                  sep_1: 20\n"
        "b+000001e0                   type: f\n"
        "b+000001e1                  eol_0: 0a\n"
        "                              [1]\n"
        "b+000001e2                 offset: '0000000009'\n"
        "b+000001ec                  sep_0: 20\n"
        "b+000001ed             generation: '00000'\n"
        "b+000001f2                  sep_1: 20\n"
        "b+000001f3                   type: n\n"
        "b+000001f4                  eol_0: 0a\n"
        "                              [2]\n"
        "b+000001f5                 offset: '0000000063'\n"
        "b+000001ff                  sep_0: 20\n"
        "b+00000200             generation: '00000'\n"
        "b+00000205                  sep_1: 20\n"
        "b+00000206                   type: n\n"
        "b+00000207                  eol_0: 0a\n"
        "                              [3]\n"
        "b+00000208                 offset: '0000000124'\n"
        "b+00000212                  sep_0: 20\n"
        "b+00000213             generation: '00000'\n"
        "b+00000218                  sep_1: 20\n"
        "b+00000219                   type: n\n"
        "b+0000021a                  eol_0: 0a\n"
        "                              [4]\n"
        "b+0000021b                 offset: '0000000277'\n"
        "b+00000225                  sep_0: 20\n"
        "b+00000226             generation: '00000'\n"
        "b+0000022b                  sep_1: 20\n"
        "b+0000022c                   type: n\n"
        "b+0000022d                  eol_0: 0a\n"
        "                              [5]\n"
        "b+0000022e                 offset: '0000000392'\n"
        "b+00000238                  sep_0: 20\n"
        "b+00000239             generation: '00000'\n"
        "b+0000023e                  sep_1: 20\n"
        "b+0000023f                   type: n\n"
        "b+00000240                  eol_0: 0a ]\n"
        "b+00000241    trailer: \n"
        "b+00000241        keyword: 'trailer'\n"
        "b+00000249           dict: '<</Size 6\\x0a/Root 1 0 R\\x0a>>\\x0a'\n"
        "b+00000262  startxref: \n"
        "b+00000262        keyword: 'startxref'\n"
        "b+0000026c         offset: '495'\n"
        "b+00000270        eof: \n"
        "b+00000270         marker: '%%EOF'\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_pdf, sizeof(sample_pdf));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/pdf.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_xml_quiet_mode)(void)
{
    // a string read while the print is disabled must not leak its bytes in the
    // XML output: only 'b' is expected
    const char* expected =
        "<root><var name=\"b\" type=\"u8\" "
        "off=\"3\"><unum size=\"1\">70</unum></var></root>\n";

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_pdf, sizeof(sample_pdf));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on(
               "t/i/x \"disable_print(); char s[3]; enable_print(); u8 b;\"",
               tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_gzip_named)(void)
{
    // the FNAME path: the header name is read with the 'string' type, so it
    // shows up as one field instead of one line per character
    // clang-format off
    const char* expected =
        "b+00000000       member: \n"
        "b+00000000           header: \n"
        "b+00000000                  id1: 1f\n"
        "b+00000001                  id2: 8b\n"
        "b+00000002   compression_method: DEFLATE\n"
        "b+00000003                flags: FNAME\n"
        "b+00000004                mtime: 00000000\n"
        "b+00000008          extra_flags: DEFAULT_COMPRESSION\n"
        "b+00000009                   os: UNIX\n"
        "b+0000000a             filename: 'hi.txt'\n"
        "b+00000011  compressed_data: cb48cdc9c95748afca2ce00200\n"
        "b+0000001e            crc32: 56637c39\n"
        "b+00000022       input_size: 0000000b\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_gzip_named, sizeof(sample_gzip_named));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/gzip.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_list_1)(void)
{
    // clang-format off
    const char* expected =
        "Available templates:\n"
        "\nAvailable template structs:\n"
        "\nAvailable template named procs:\n";
    // clang-format on

    int r = TEST_SUCCEEDED;
    ASSERT(exec_commands("t/l") == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// The 'id' hooks are named procs, but 't/l' is a menu of what a user can run
// against a file, and those two are run by the scan. They stay callable.
int TEST(template_list_hides_identify_procs)(void)
{
    // clang-format off
    const char* expected =
        "Available templates:\n"
        "  cab\n"
        "\nAvailable template structs:\n"
        "  cab.cab_header_t\n"
        "  cab.cab_file_t\n"
        "  cab.cab_data_t\n"
        "  cab.cab_folder_t\n"
        "\nAvailable template named procs:\n"
        "  cab.list_files\n";
    // clang-format on

    int r = TEST_SUCCEEDED;
    bhengine_vm_add_template(bhengine_vm_get(), "cab", "./templates/cab.bhe");

    ASSERT(exec_commands("t/l") == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    bhengine_vm_remove_template(bhengine_vm_get(), "cab");
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

// ... and hiding them from the listing must not make them unreachable
int TEST(template_identify_proc_still_callable)(void)
{
    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_cab, sizeof(sample_cab));
    ASSERT(tfb != NULL);
    bhengine_vm_add_template(bhengine_vm_get(), "cab", "./templates/cab.bhe");

    ASSERT(exec_commands_on("t cab._identify", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X("result: 653\n\n", out);
    bhex_free(out);

end:
    bhengine_vm_remove_template(bhengine_vm_get(), "cab");
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_invalid_name)(void)
{
    int r = TEST_SUCCEEDED;
    // A non-existent template name should fail
    ASSERT(exec_commands("t nonexistent_template_xyz") != 0);

end:
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_rpm_xml)(void)
{
    int              r   = TEST_SUCCEEDED;
    char*            out = NULL;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_rpm, sizeof(sample_rpm));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t/x ./templates/rpm.bhe", tfb) == 0);

    // Just verify that we got XML-like output
    out = strbuilder_reset(sb);
    ASSERT(out != NULL);
    ASSERT(strstr(out, "<root>") != NULL);
    ASSERT(strstr(out, "name=\"lead\"") != NULL);
    ASSERT(strstr(out, "edabeedb") != NULL);
    ASSERT(strstr(out, "</root>") != NULL);

end:
    bhex_free(out);
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_interactive_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000  a: 4e455458\n"
        "b+00000004  b: 4748504a\n";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(pseudo_random, sizeof(pseudo_random));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on_ex("t/i \"u32 a; u32 b;\"", tfb, 0) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_macho_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000          header: \n"
        "b+00000000               magic: MH_MAGIC_64\n"
        "b+00000004             cputype: CPU_TYPE_X86_64\n"
        "b+00000008          cpusubtype: 00000003\n"
        "b+0000000c            filetype: MH_EXECUTE\n"
        "b+00000010               ncmds: 00000001\n"
        "b+00000014          sizeofcmds: 00000048\n"
        "b+00000018               flags: MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE\n"
        "b+0000001c            reserved: 00000000\n"
        "b+00000020     LoadCommand: \n"
        "b+00000020                 cmd: LC_SEGMENT_64\n"
        "b+00000024             cmdsize: 00000048\n"
        "b+00000028             segname: '__TEXT'\n"
        "b+00000038              vmaddr: 0000000100000000\n"
        "b+00000040              vmsize: 0000000000001000\n"
        "b+00000048             fileoff: 0000000000000000\n"
        "b+00000050            filesize: 0000000000000068\n"
        "b+00000058             maxprot: VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE\n"
        "b+0000005c            initprot: VM_PROT_READ | VM_PROT_EXECUTE\n"
        "b+00000060              nsects: 00000000\n"
        "b+00000064               flags: NONE\n";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_macho, sizeof(sample_macho));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/macho.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_fat_macho_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000       fatHeader: \n"
        "b+00000000               magic: FAT_MAGIC\n"
        "b+00000004           nfat_arch: 00000001\n"
        "b+00000008            arch: \n"
        "b+00000008             cputype: CPU_TYPE_X86_64\n"
        "b+0000000c          cpusubtype: 00000003\n"
        "b+00000010              offset: 0000001c\n"
        "b+00000014                size: 00000068\n"
        "b+00000018               align: 00000000\n"
        "b+0000001c  EmbeddedHeader: \n"
        "b+0000001c               magic: MH_MAGIC_64\n"
        "b+00000020             cputype: CPU_TYPE_X86_64\n"
        "b+00000024          cpusubtype: 00000003\n"
        "b+00000028            filetype: MH_EXECUTE\n"
        "b+0000002c               ncmds: 00000001\n"
        "b+00000030          sizeofcmds: 00000048\n"
        "b+00000034               flags: MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE\n"
        "b+00000038            reserved: 00000000\n"
        "b+0000003c     LoadCommand: \n"
        "b+0000003c                 cmd: LC_SEGMENT_64\n"
        "b+00000040             cmdsize: 00000048\n"
        "b+00000044             segname: '__TEXT'\n"
        "b+00000054              vmaddr: 0000000100000000\n"
        "b+0000005c              vmsize: 0000000000001000\n"
        "b+00000064             fileoff: 0000000000000000\n"
        "b+0000006c            filesize: 0000000000000068\n"
        "b+00000074             maxprot: VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE\n"
        "b+00000078            initprot: VM_PROT_READ | VM_PROT_EXECUTE\n"
        "b+0000007c              nsects: 00000000\n"
        "b+00000080               flags: NONE\n";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_fat_macho, sizeof(sample_fat_macho));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/macho.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_sevenzip_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000          header: \n"
        "b+00000000               magic: 377abcaf271c\n"
        "b+00000006       version_major: 00\n"
        "b+00000007       version_minor: 04\n"
        "b+00000008  start_header_crc32: 6526163d\n"
        "b+0000000c  next_header_offset: 0000000000000032\n"
        "b+00000014    next_header_size: 0000000000000052\n"
        "b+0000001c   next_header_crc32: eaa9e7ca\n"
        "b+00000020  packed_streams: e00071002a5d00311a08d4f5ca141d2a...\n"
        "b+00000052     next_header: \n"
        "b+00000052                  id: kHeader\n"
        "b+00000053     main_streams_id: kMainStreamsInfo\n"
        "b+00000054           pack_info: \n"
        "b+00000054                      id: kPackInfo\n"
        "b+00000055                pack_pos: \n"
        "b+00000055                      number: 00\n"
        "b+00000056        num_pack_streams: \n"
        "b+00000056                      number: 01\n"
        "b+00000057                 size_id: kSize\n"
        "b+00000058               pack_size: \n"
        "b+00000058                      number: 32\n"
        "b+00000059                  end_id: kEnd\n"
        "b+0000005a         unpack_info: \n"
        "b+0000005a                      id: kUnPackInfo\n"
        "b+0000005b               folder_id: kFolder\n"
        "b+0000005c             num_folders: \n"
        "b+0000005c                      number: 01\n"
        "b+0000005d                external: 00\n"
        "b+0000005e                  folder: \n"
        "b+0000005e                  num_coders: \n"
        "b+0000005e                          number: 01\n"
        "b+0000005f                 coder_flags: 21\n"
        "b+00000060                    coder_id: 21\n"
        "    coder: LZMA2\n"
        "b+00000061             properties_size: \n"
        "b+00000061                          number: 01\n"
        "b+00000062                  properties: 00\n"
        "b+00000063                sizes_id: kCodersUnPackSize\n"
        "b+00000064             unpack_size: \n"
        "b+00000064                      number: 72\n"
        "";
    // clang-format on

    int              r   = TEST_SUCCEEDED;
    DummyFilebuffer* tfb = dummyfilebuffer_create(sample_7z, sizeof(sample_7z));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/7z.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_bzip2_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000           header: \n"
        "b+00000000                magic: 'BZh'\n"
        "b+00000003                level: 9\n"
        "b+00000004      first_block: \n"
        "b+00000004          block_magic: 314159265359\n"
        "b+0000000a            block_crc: 21fb1ef0\n"
        "b+0000000e  compressed_data: 000011918040053646dc60200050a1a6...\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_bzip2, sizeof(sample_bzip2));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/bzip2.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_cpio_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000     entry: \n"
        "b+00000000         magic: '070701'\n"
        "b+00000006           ino: '00000001'\n"
        "b+0000000e          mode: '000081A4'\n"
        "b+00000016           uid: '00000000'\n"
        "b+0000001e           gid: '00000000'\n"
        "b+00000026         nlink: '00000001'\n"
        "b+0000002e         mtime: '00000000'\n"
        "b+00000036      filesize: '0000000B'\n"
        "b+0000003e      devmajor: '00000000'\n"
        "b+00000046      devminor: '00000000'\n"
        "b+0000004e     rdevmajor: '00000000'\n"
        "b+00000056     rdevminor: '00000000'\n"
        "b+0000005e      namesize: '0000000A'\n"
        "b+00000066         check: '00000000'\n"
        "b+0000006e          name: 'hello.txt'\n"
        "b+00000078          data: 68656c6c6f20626865780a\n"
        "b+00000083  data_padding: 00\n"
        "b+00000084     entry: \n"
        "b+00000084         magic: '070701'\n"
        "b+0000008a           ino: '00000002'\n"
        "b+00000092          mode: '000041ED'\n"
        "b+0000009a           uid: '00000000'\n"
        "b+000000a2           gid: '00000000'\n"
        "b+000000aa         nlink: '00000001'\n"
        "b+000000b2         mtime: '00000000'\n"
        "b+000000ba      filesize: '00000000'\n"
        "b+000000c2      devmajor: '00000000'\n"
        "b+000000ca      devminor: '00000000'\n"
        "b+000000d2     rdevmajor: '00000000'\n"
        "b+000000da     rdevminor: '00000000'\n"
        "b+000000e2      namesize: '00000004'\n"
        "b+000000ea         check: '00000000'\n"
        "b+000000f2          name: 'dir'\n"
        "b+000000f6  name_padding: 0000\n"
        "b+000000f8     entry: \n"
        "b+000000f8         magic: '070701'\n"
        "b+000000fe           ino: '00000000'\n"
        "b+00000106          mode: '00000000'\n"
        "b+0000010e           uid: '00000000'\n"
        "b+00000116           gid: '00000000'\n"
        "b+0000011e         nlink: '00000001'\n"
        "b+00000126         mtime: '00000000'\n"
        "b+0000012e      filesize: '00000000'\n"
        "b+00000136      devmajor: '00000000'\n"
        "b+0000013e      devminor: '00000000'\n"
        "b+00000146     rdevmajor: '00000000'\n"
        "b+0000014e     rdevminor: '00000000'\n"
        "b+00000156      namesize: '0000000B'\n"
        "b+0000015e         check: '00000000'\n"
        "b+00000166          name: 'TRAILER!!!'\n"
        "b+00000171  name_padding: 000000\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_cpio, sizeof(sample_cpio));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/cpio.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_dtb_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000           header: \n"
        "b+00000000                magic: d00dfeed\n"
        "b+00000004            totalsize: 00000151\n"
        "b+00000008        off_dt_struct: 00000038\n"
        "b+0000000c       off_dt_strings: 0000010c\n"
        "b+00000010       off_mem_rsvmap: 00000028\n"
        "b+00000014              version: 00000011\n"
        "b+00000018    last_comp_version: 00000010\n"
        "b+0000001c      boot_cpuid_phys: 00000000\n"
        "b+00000020      size_dt_strings: 00000045\n"
        "b+00000024       size_dt_struct: 000000d4\n"
        "b+00000028  reserved_memory: \n"
        "b+00000028              address: 0000000000000000\n"
        "b+00000030                 size: 0000000000000000\n"
        "b+00000038             node: \n"
        "b+00000038                token: BEGIN_NODE\n"
        "b+0000003c                 name: ''\n"
        "b+0000003d         name_padding: 000000\n"
        "  property: #address-cells\n"
        "b+00000040         property: \n"
        "b+00000040                token: PROP\n"
        "b+00000044            value_len: 00000004\n"
        "b+00000048             name_off: 00000000\n"
        "b+0000004c                value: 00000001\n"
        "  property: #size-cells\n"
        "b+00000050         property: \n"
        "b+00000050                token: PROP\n"
        "b+00000054            value_len: 00000004\n"
        "b+00000058             name_off: 0000000f\n"
        "b+0000005c                value: 00000001\n"
        "  property: model\n"
        "b+00000060         property: \n"
        "b+00000060                token: PROP\n"
        "b+00000064            value_len: 00000010\n"
        "b+00000068             name_off: 0000001b\n"
        "b+0000006c                value: 62686578207465737420626f61726400\n"
        "  property: compatible\n"
        "b+0000007c         property: \n"
        "b+0000007c                token: PROP\n"
        "b+00000080            value_len: 0000000f\n"
        "b+00000084             name_off: 00000021\n"
        "b+00000088                value: 626865782c74657374626f61726400\n"
        "b+00000097        value_padding: 00\n"
        "b+00000098             node: \n"
        "b+00000098                token: BEGIN_NODE\n"
        "b+0000009c                 name: 'memory@40000000'\n"
        "  property: device_type\n"
        "b+000000ac         property: \n"
        "b+000000ac                token: PROP\n"
        "b+000000b0            value_len: 00000007\n"
        "b+000000b4             name_off: 0000002c\n"
        "b+000000b8                value: 6d656d6f727900\n"
        "b+000000bf        value_padding: 00\n"
        "  property: reg\n"
        "b+000000c0         property: \n"
        "b+000000c0                token: PROP\n"
        "b+000000c4            value_len: 00000008\n"
        "b+000000c8             name_off: 00000038\n"
        "b+000000cc                value: 4000000008000000\n"
        "b+000000d4         end_node: END_NODE\n"
        "b+000000d8             node: \n"
        "b+000000d8                token: BEGIN_NODE\n"
        "b+000000dc                 name: 'chosen'\n"
        "b+000000e3         name_padding: 00\n"
        "  property: bootargs\n"
        "b+000000e4         property: \n"
        "b+000000e4                token: PROP\n"
        "b+000000e8            value_len: 0000000e\n"
        "b+000000ec             name_off: 0000003c\n"
        "b+000000f0                value: 636f6e736f6c653d747479533000\n"
        "b+000000fe        value_padding: 0000\n"
        "b+00000100         end_node: END_NODE\n"
        "b+00000104         end_node: END_NODE\n"
        "b+00000108              end: END\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_dtb, sizeof(sample_dtb));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/dtb.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_uimage_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000    header: \n"
        "b+00000000         magic: 27051956\n"
        "b+00000004          hcrc: 3c04782a\n"
        "b+00000008     timestamp: 5f2e4b00\n"
        "b+0000000c     data_size: 0000004e\n"
        "b+00000010  load_address: 80008000\n"
        "b+00000014   entry_point: 80008040\n"
        "b+00000018          dcrc: 9651f74f\n"
        "b+0000001c            os: LINUX\n"
        "b+0000001d          arch: ARM\n"
        "b+0000001e          type: KERNEL\n"
        "b+0000001f   compression: BZIP2\n"
        "b+00000020          name: 'bhex test kernel'\n"
        "b+00000040   payload: 425a683931415926535921fb1ef00000...\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_uimage, sizeof(sample_uimage));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/uimage.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_xz_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000           header: \n"
        "b+00000000                magic: fd377a585a00\n"
        "b+00000006             reserved: 00\n"
        "b+00000007           check_type: CRC32\n"
        "b+00000008          flags_crc32: 36de2269\n"
        "b+0000000c     block_header: \n"
        "b+0000000c          header_size: 04\n"
        "b+0000000d          block_flags: c0\n"
        "b+0000000e      compressed_size: 32\n"
        "b+0000000f    uncompressed_size: 72\n"
        "b+00000010               filter: \n"
        "b+00000010                filter_id: LZMA2\n"
        "b+00000011          properties_size: 01\n"
        "b+00000012               properties: 1c\n"
        "b+00000013       header_padding: 000000000000000000\n"
        "b+0000001c         header_crc32: 536eecf3\n"
        "b+00000020  compressed_data: e00071002a5d00311a08d4f5ca141d2a...\n"
        "b+00000052    block_padding: 0000\n"
        "b+00000054            check: 7d1a6a4a\n"
        "b+00000058  index_indicator: 00\n"
        "b+00000059     record_count: 01\n"
        "b+0000005a           record: \n"
        "b+0000005a        unpadded_size: 4a\n"
        "b+0000005b    uncompressed_size: 72\n"
        "b+0000005c      index_crc32: 941b02b4\n"
        "b+00000060           footer: \n"
        "b+00000060         footer_crc32: 0d994290\n"
        "b+00000064        backward_size: 00000001\n"
        "b+00000068             reserved: 00\n"
        "b+00000069           check_type: CRC32\n"
        "b+0000006a                magic: 'YZ'\n"
        "";
    // clang-format on

    int              r   = TEST_SUCCEEDED;
    DummyFilebuffer* tfb = dummyfilebuffer_create(sample_xz, sizeof(sample_xz));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/xz.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_zstd_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000              frame: \n"
        "b+00000000                 header: \n"
        "b+00000000                      magic: fd2fb528\n"
        "b+00000004    frame_header_descriptor: 24\n"
        "b+00000005         frame_content_size: 72\n"
        "b+00000006                  block: \n"
        "b+00000006               block_header: 650100\n"
        "b+00000009            compressed_data: 72c2080fd0e7aa9228e5b84abe0462d3...\n"
        "b+00000035       content_checksum: 3cf59b5a\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_zstd, sizeof(sample_zstd));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/zstd.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_ar_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000   magic: '!<arch>\\x0a'\n"
        "b+00000008  member: \n"
        "b+00000008        name: 'a.txt/          '\n"
        "b+00000018       mtime: '0           '\n"
        "b+00000024         uid: '0     '\n"
        "b+0000002a         gid: '0     '\n"
        "b+00000030        mode: '644     '\n"
        "b+00000038        size: '11        '\n"
        "b+00000042        fmag: '`\\x0a'\n"
        "b+00000044        data: 68656c6c6f20626865780a\n"
        "b+0000004f     padding: 0a\n"
        "b+00000050  member: \n"
        "b+00000050        name: 'b.bin/          '\n"
        "b+00000060       mtime: '0           '\n"
        "b+0000006c         uid: '0     '\n"
        "b+00000072         gid: '0     '\n"
        "b+00000078        mode: '644     '\n"
        "b+00000080        size: '4         '\n"
        "b+0000008a        fmag: '`\\x0a'\n"
        "b+0000008c        data: 01020304\n"
        "";
    // clang-format on

    int              r   = TEST_SUCCEEDED;
    DummyFilebuffer* tfb = dummyfilebuffer_create(sample_ar, sizeof(sample_ar));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/ar.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_javaclass_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000                magic: cafebabe\n"
        "b+00000004        minor_version: 0000\n"
        "b+00000006        major_version: JAVA_21\n"
        "b+00000008  constant_pool_count: 0020\n"
        "b+0000000a             constant: \n"
        "b+0000000a                      tag: METHODREF\n"
        "b+0000000b              first_index: 0002\n"
        "b+0000000d             second_index: 0003\n"
        "b+0000000f             constant: \n"
        "b+0000000f                      tag: CLASS\n"
        "b+00000010                    index: 0004\n"
        "b+00000012             constant: \n"
        "b+00000012                      tag: NAME_AND_TYPE\n"
        "b+00000013              first_index: 0005\n"
        "b+00000015             second_index: 0006\n"
        "b+00000017             constant: \n"
        "b+00000017                      tag: UTF8\n"
        "b+00000018                   length: 0010\n"
        "b+0000001a                     text: 'java/lang/Object'\n"
        "b+0000002a             constant: \n"
        "b+0000002a                      tag: UTF8\n"
        "b+0000002b                   length: 0006\n"
        "b+0000002d                     text: '<init>'\n"
        "b+00000033             constant: \n"
        "b+00000033                      tag: UTF8\n"
        "b+00000034                   length: 0003\n"
        "b+00000036                     text: '()V'\n"
        "b+00000039             constant: \n"
        "b+00000039                      tag: FIELDREF\n"
        "b+0000003a              first_index: 0008\n"
        "b+0000003c             second_index: 0009\n"
        "b+0000003e             constant: \n"
        "b+0000003e                      tag: CLASS\n"
        "b+0000003f                    index: 000a\n"
        "b+00000041             constant: \n"
        "b+00000041                      tag: NAME_AND_TYPE\n"
        "b+00000042              first_index: 000b\n"
        "b+00000044             second_index: 000c\n"
        "b+00000046             constant: \n"
        "b+00000046                      tag: UTF8\n"
        "b+00000047                   length: 0010\n"
        "b+00000049                     text: 'java/lang/System'\n"
        "b+00000059             constant: \n"
        "b+00000059                      tag: UTF8\n"
        "b+0000005a                   length: 0003\n"
        "b+0000005c                     text: 'out'\n"
        "b+0000005f             constant: \n"
        "b+0000005f                      tag: UTF8\n"
        "b+00000060                   length: 0015\n"
        "b+00000062                     text: 'Ljava/io/PrintStream;'\n"
        "b+00000077             constant: \n"
        "b+00000077                      tag: CLASS\n"
        "b+00000078                    index: 000e\n"
        "b+0000007a             constant: \n"
        "b+0000007a                      tag: UTF8\n"
        "b+0000007b                   length: 0005\n"
        "b+0000007d                     text: 'Hello'\n"
        "b+00000082             constant: \n"
        "b+00000082                      tag: STRING\n"
        "b+00000083                    index: 0010\n"
        "b+00000085             constant: \n"
        "b+00000085                      tag: UTF8\n"
        "b+00000086                   length: 000a\n"
        "b+00000088                     text: 'hello bhex'\n"
        "b+00000092             constant: \n"
        "b+00000092                      tag: METHODREF\n"
        "b+00000093              first_index: 0012\n"
        "b+00000095             second_index: 0013\n"
        "b+00000097             constant: \n"
        "b+00000097                      tag: CLASS\n"
        "b+00000098                    index: 0014\n"
        "b+0000009a             constant: \n"
        "b+0000009a                      tag: NAME_AND_TYPE\n"
        "b+0000009b              first_index: 0015\n"
        "b+0000009d             second_index: 0016\n"
        "b+0000009f             constant: \n"
        "b+0000009f                      tag: UTF8\n"
        "b+000000a0                   length: 0013\n"
        "b+000000a2                     text: 'java/io/PrintStream'\n"
        "b+000000b5             constant: \n"
        "b+000000b5                      tag: UTF8\n"
        "b+000000b6                   length: 0007\n"
        "b+000000b8                     text: 'println'\n"
        "b+000000bf             constant: \n"
        "b+000000bf                      tag: UTF8\n"
        "b+000000c0                   length: 0015\n"
        "b+000000c2                     text: '(Ljava/lang/String;)V'\n"
        "b+000000d7             constant: \n"
        "b+000000d7                      tag: UTF8\n"
        "b+000000d8                   length: 0008\n"
        "b+000000da                     text: 'GREETING'\n"
        "b+000000e2             constant: \n"
        "b+000000e2                      tag: UTF8\n"
        "b+000000e3                   length: 0012\n"
        "b+000000e5                     text: 'Ljava/lang/String;'\n"
        "b+000000f7             constant: \n"
        "b+000000f7                      tag: UTF8\n"
        "b+000000f8                   length: 000d\n"
        "b+000000fa                     text: 'ConstantValue'\n"
        "b+00000107             constant: \n"
        "b+00000107                      tag: UTF8\n"
        "b+00000108                   length: 0004\n"
        "b+0000010a                     text: 'Code'\n"
        "b+0000010e             constant: \n"
        "b+0000010e                      tag: UTF8\n"
        "b+0000010f                   length: 000f\n"
        "b+00000111                     text: 'LineNumberTable'\n"
        "b+00000120             constant: \n"
        "b+00000120                      tag: UTF8\n"
        "b+00000121                   length: 0004\n"
        "b+00000123                     text: 'main'\n"
        "b+00000127             constant: \n"
        "b+00000127                      tag: UTF8\n"
        "b+00000128                   length: 0016\n"
        "b+0000012a                     text: '([Ljava/lang/String;)V'\n"
        "b+00000140             constant: \n"
        "b+00000140                      tag: UTF8\n"
        "b+00000141                   length: 000a\n"
        "b+00000143                     text: 'SourceFile'\n"
        "b+0000014d             constant: \n"
        "b+0000014d                      tag: UTF8\n"
        "b+0000014e                   length: 000a\n"
        "b+00000150                     text: 'Hello.java'\n"
        "b+0000015a         access_flags: PUBLIC | SUPER\n"
        "b+0000015c           this_class: 000d\n"
        "b+0000015e          super_class: 0002\n"
        "b+00000160     interfaces_count: 0000\n"
        "b+00000162         fields_count: 0001\n"
        "b+00000164                field: \n"
        "b+00000164             access_flags: STATIC | FINAL\n"
        "b+00000166               name_index: 0017\n"
        "b+00000168         descriptor_index: 0018\n"
        "b+0000016a         attributes_count: 0001\n"
        "b+0000016c                attribute: \n"
        "b+0000016c         attribute_name_index: 0019\n"
        "b+0000016e             attribute_length: 00000002\n"
        "b+00000172                         info: 000f\n"
        "b+00000174        methods_count: 0002\n"
        "b+00000176               method: \n"
        "b+00000176             access_flags: PUBLIC\n"
        "b+00000178               name_index: 0005\n"
        "b+0000017a         descriptor_index: 0006\n"
        "b+0000017c         attributes_count: 0001\n"
        "b+0000017e                attribute: \n"
        "b+0000017e         attribute_name_index: 001a\n"
        "b+00000180             attribute_length: 0000001d\n"
        "b+00000184                         info: 00010001000000052ab70001b1000000...\n"
        "b+000001a1               method: \n"
        "b+000001a1             access_flags: PUBLIC | STATIC\n"
        "b+000001a3               name_index: 001c\n"
        "b+000001a5         descriptor_index: 001d\n"
        "b+000001a7         attributes_count: 0001\n"
        "b+000001a9                attribute: \n"
        "b+000001a9         attribute_name_index: 001a\n"
        "b+000001ab             attribute_length: 00000021\n"
        "b+000001af                         info: 0002000100000009b20007120fb60011...\n"
        "b+000001d0     attributes_count: 0001\n"
        "b+000001d2            attribute: \n"
        "b+000001d2     attribute_name_index: 001e\n"
        "b+000001d4         attribute_length: 00000002\n"
        "b+000001d8                     info: 001f\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_javaclass, sizeof(sample_javaclass));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/javaclass.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_pcap_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000            header: \n"
        "b+00000000                 magic: a1b2c3d4\n"
        "b+00000004         version_major: 0002\n"
        "b+00000006         version_minor: 0004\n"
        "b+00000008              thiszone: 00000000\n"
        "b+0000000c               sigfigs: 00000000\n"
        "b+00000010               snaplen: 0000ffff\n"
        "b+00000014               network: ETHERNET\n"
        "b+00000018            record: \n"
        "b+00000018                ts_sec: 5f2e4b00\n"
        "b+0000001c               ts_usec: 00000000\n"
        "b+00000020              incl_len: 00000036\n"
        "b+00000024              orig_len: 00000036\n"
        "b+00000028               eth: \n"
        "b+00000028                   dst: ffffffffffff\n"
        "b+0000002e                   src: 001122334455\n"
        "b+00000034                  type: ETH_TYPE_IP\n"
        "b+00000036                ip: \n"
        "b+00000036           version_ihl: 45\n"
        "b+00000037       type_of_service: 00\n"
        "b+00000038          total_length: 0028\n"
        "b+0000003a        identification: 0001\n"
        "b+0000003c        flags_fragment: 0000\n"
        "b+0000003e          time_to_live: 40\n"
        "b+0000003f              protocol: IPPROTO_TCP\n"
        "b+00000040       header_checksum: 7ccd\n"
        "b+00000042        source_address: 7f000001\n"
        "b+00000046          dest_address: 7f000001\n"
        "b+0000004a               tcp: \n"
        "b+0000004a           source_port: 04d2\n"
        "b+0000004c             dest_port: 0050\n"
        "b+0000004e          sequence_num: 00000000\n"
        "b+00000052               ack_num: 00000000\n"
        "b+00000056  data_offset_reserved: 50\n"
        "b+00000057                 flags: TCP_FLAG_SYN\n"
        "b+00000058           window_size: 2000\n"
        "b+0000005a              checksum: 0000\n"
        "b+0000005c        urgent_pointer: 0000\n"
        "b+0000005e            record: \n"
        "b+0000005e                ts_sec: 5f2e4b00\n"
        "b+00000062               ts_usec: 00000000\n"
        "b+00000066              incl_len: 00000036\n"
        "b+0000006a              orig_len: 00000036\n"
        "b+0000006e               eth: \n"
        "b+0000006e                   dst: ffffffffffff\n"
        "b+00000074                   src: 001122334455\n"
        "b+0000007a                  type: ETH_TYPE_IP\n"
        "b+0000007c                ip: \n"
        "b+0000007c           version_ihl: 45\n"
        "b+0000007d       type_of_service: 00\n"
        "b+0000007e          total_length: 0028\n"
        "b+00000080        identification: 0001\n"
        "b+00000082        flags_fragment: 0000\n"
        "b+00000084          time_to_live: 40\n"
        "b+00000085              protocol: IPPROTO_TCP\n"
        "b+00000086       header_checksum: 7ccd\n"
        "b+00000088        source_address: 7f000001\n"
        "b+0000008c          dest_address: 7f000001\n"
        "b+00000090               tcp: \n"
        "b+00000090           source_port: 04d2\n"
        "b+00000092             dest_port: 0050\n"
        "b+00000094          sequence_num: 00000000\n"
        "b+00000098               ack_num: 00000000\n"
        "b+0000009c  data_offset_reserved: 50\n"
        "b+0000009d                 flags: TCP_FLAG_SYN\n"
        "b+0000009e           window_size: 2000\n"
        "b+000000a0              checksum: 0000\n"
        "b+000000a2        urgent_pointer: 0000\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_pcap, sizeof(sample_pcap));
    ASSERT(tfb != NULL);

    // pcap.bhe pulls the ethernet/IP/TCP structs out of net.bhe with the '#'
    // operator, so the template it imports has to be registered first
    ASSERT(register_imported_template("net", "./templates/net.bhe") == 0);
    ASSERT(exec_commands_on("t ./templates/pcap.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    unregister_imported_template("net");
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_pcapng_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000             block: \n"
        "b+00000000            block_type: SECTION_HEADER\n"
        "b+00000004          total_length: 0000001c\n"
        "b+00000008        section_header: \n"
        "b+00000008          byte_order_magic: 1a2b3c4d\n"
        "b+0000000c             version_major: 0001\n"
        "b+0000000e             version_minor: 0000\n"
        "b+00000010            section_length: ffffffffffffffff\n"
        "b+00000018  total_length_trailer: 0000001c\n"
        "b+0000001c             block: \n"
        "b+0000001c            block_type: INTERFACE_DESCRIPTION\n"
        "b+00000020          total_length: 00000014\n"
        "b+00000024             interface: \n"
        "b+00000024                  linktype: ETHERNET\n"
        "b+00000026                  reserved: 0000\n"
        "b+00000028                   snaplen: 0000ffff\n"
        "b+0000002c  total_length_trailer: 00000014\n"
        "b+00000030             block: \n"
        "b+00000030            block_type: ENHANCED_PACKET\n"
        "b+00000034          total_length: 00000044\n"
        "b+00000038                packet: \n"
        "b+00000038              interface_id: 00000000\n"
        "b+0000003c            timestamp_high: 00000000\n"
        "b+00000040             timestamp_low: 00000000\n"
        "b+00000044              captured_len: 00000022\n"
        "b+00000048              original_len: 00000022\n"
        "b+0000004c           packet_data: ffffffffffffffffffffffffffff4500...\n"
        "b+0000006e        packet_padding: 0000\n"
        "b+00000070  total_length_trailer: 00000044\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_pcapng, sizeof(sample_pcapng));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/pcapng.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_riff_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000            magic: 'RIFF'\n"
        "b+00000004        riff_size: 0000004c\n"
        "b+00000008        form_type: 'WAVE'\n"
        "b+0000000c            chunk: \n"
        "b+0000000c                   id: 'fmt '\n"
        "b+00000010           chunk_size: 00000010\n"
        "b+00000014                  fmt: \n"
        "b+00000014                   format: PCM\n"
        "b+00000016                 channels: 0001\n"
        "b+00000018              sample_rate: 00001f40\n"
        "b+0000001c                byte_rate: 00003e80\n"
        "b+00000020              block_align: 0002\n"
        "b+00000022          bits_per_sample: 0010\n"
        "b+00000024            chunk: \n"
        "b+00000024                   id: 'data'\n"
        "b+00000028           chunk_size: 00000028\n"
        "b+0000002c                 data: 00000100020003000400050006000700...\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_riff, sizeof(sample_riff));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/riff.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_sqlite3_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000               header: \n"
        "b+00000000                    magic: 'SQLite format 3'\n"
        "b+00000010                page_size: 0200\n"
        "b+00000012            write_version: 01\n"
        "b+00000013             read_version: 01\n"
        "b+00000014           reserved_space: 00\n"
        "b+00000015     max_payload_fraction: 40\n"
        "b+00000016     min_payload_fraction: 20\n"
        "b+00000017    leaf_payload_fraction: 20\n"
        "b+00000018      file_change_counter: 00000003\n"
        "b+0000001c               page_count: 00000002\n"
        "b+00000020      first_freelist_page: 00000000\n"
        "b+00000024      freelist_page_count: 00000000\n"
        "b+00000028            schema_cookie: 00000002\n"
        "b+0000002c            schema_format: NULL_IN_INDEX\n"
        "b+00000030  default_page_cache_size: 00000000\n"
        "b+00000034  largest_root_btree_page: 00000000\n"
        "b+00000038            text_encoding: UTF8\n"
        "b+0000003c             user_version: 00000000\n"
        "b+00000040       incremental_vacuum: 00000000\n"
        "b+00000044           application_id: 00000000\n"
        "b+00000048                 reserved: 00000000000000000000000000000000...\n"
        "b+0000005c        version_valid_for: 00000003\n"
        "b+00000060           sqlite_version: 002e7a71\n"
        "  sqlite version: 3 46 1\n"
        "b+00000064                page1: \n"
        "b+00000064                page_type: TABLE_LEAF\n"
        "b+00000065          first_freeblock: 0000\n"
        "b+00000067               cell_count: 0001\n"
        "b+00000069       cell_content_start: 01bf\n"
        "b+0000006b    fragmented_free_bytes: 00\n"
        "b+0000006c            cell_pointers: [ 01bf ]\n"
        "b+00000200                 page: \n"
        "b+00000200                page_type: TABLE_LEAF\n"
        "b+00000201          first_freeblock: 0000\n"
        "b+00000203               cell_count: 0005\n"
        "b+00000205       cell_content_start: 01ce\n"
        "b+00000207    fragmented_free_bytes: 00\n"
        "b+00000208            cell_pointers: [ 01f6, 01ec, 01e2, 01d8, 01ce ]\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_sqlite3, sizeof(sample_sqlite3));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/sqlite3.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_ubifs_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000     superblock: \n"
        "b+00000000                 ch: \n"
        "b+00000000                  magic: 06101831\n"
        "b+00000004                    crc: abca2b18\n"
        "b+00000008                  sqnum: 0000000000000001\n"
        "b+00000010                    len: 00001000\n"
        "b+00000014              node_type: SUPERBLOCK\n"
        "b+00000015             group_type: 00\n"
        "b+00000016                padding: 0000\n"
        "b+00000018            padding: 0000\n"
        "b+0000001a           key_hash: R5\n"
        "b+0000001b            key_fmt: 00\n"
        "b+0000001c              flags: NONE\n"
        "b+00000020        min_io_size: 00000800\n"
        "b+00000024           leb_size: 0001f000\n"
        "b+00000028            leb_cnt: 0000017a\n"
        "b+0000002c        max_leb_cnt: 000007fc\n"
        "b+00000030      max_bud_bytes: 0000000000800000\n"
        "b+00000038           log_lebs: 00000005\n"
        "b+0000003c           lpt_lebs: 00000002\n"
        "b+00000040          orph_lebs: 00000001\n"
        "b+00000044          jhead_cnt: 00000001\n"
        "b+00000048             fanout: 00000008\n"
        "b+0000004c          lsave_cnt: 00000100\n"
        "b+00000050        fmt_version: 00000004\n"
        "b+00000054      default_compr: LZO\n"
        "b+00000056           padding1: 0000\n"
        "b+00000058             rp_uid: 00000000\n"
        "b+0000005c             rp_gid: 00000000\n"
        "b+00000060            rp_size: 0000000000000000\n"
        "b+00000068          time_gran: 00000001\n"
        "b+0000006c               uuid: 101112131415161718191a1b1c1d1e1f\n"
        "b+0000007c  ro_compat_version: 00000000\n"
        "b+00000080               hmac: 00000000000000000000000000000000...\n"
        "b+000000c0           hmac_wkm: 00000000000000000000000000000000...\n"
        "b+00000100          hash_algo: 0000\n"
        "b+00000102           hash_mst: 00000000000000000000000000000000...\n"
        "b+00000142           padding2: 00000000000000000000000000000000...\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_ubifs, sizeof(sample_ubifs));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/ubifs.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_ext_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000             boot_area: 00000000000000000000000000000000...\n"
        "b+00000400            superblock: \n"
        "b+00000400              inodes_count: 00000400\n"
        "b+00000404           blocks_count_lo: 00001000\n"
        "b+00000408  reserved_blocks_count_lo: 000000cc\n"
        "b+0000040c      free_blocks_count_lo: 00000ed8\n"
        "b+00000410         free_inodes_count: 000003f5\n"
        "b+00000414          first_data_block: 00000001\n"
        "b+00000418            log_block_size: 00000000\n"
        "b+0000041c          log_cluster_size: 00000000\n"
        "b+00000420          blocks_per_group: 00002000\n"
        "b+00000424        clusters_per_group: 00002000\n"
        "b+00000428          inodes_per_group: 00000080\n"
        "b+0000042c                     mtime: 5f2e4b00\n"
        "b+00000430                     wtime: 5f2e4b00\n"
        "b+00000434               mount_count: 0001\n"
        "b+00000436           max_mount_count: ffff\n"
        "b+00000438                     magic: ef53\n"
        "b+0000043a                     state: CLEAN\n"
        "b+0000043c                    errors: CONTINUE\n"
        "b+0000043e           minor_rev_level: 0000\n"
        "b+00000440                 lastcheck: 5f2e4b00\n"
        "b+00000444             checkinterval: 00000000\n"
        "b+00000448                creator_os: LINUX\n"
        "b+0000044c                 rev_level: DYNAMIC\n"
        "b+00000450            default_resuid: 0000\n"
        "b+00000452            default_resgid: 0000\n"
        "b+00000454               first_inode: 0000000b\n"
        "b+00000458                inode_size: 0100\n"
        "b+0000045a            block_group_nr: 0000\n"
        "b+0000045c            feature_compat: EXT_ATTR | RESIZE_INODE | DIR_INDEX\n"
        "b+00000460          feature_incompat: FILETYPE | EXTENTS | SIXTY_FOUR_BIT | FLEX_BG\n"
        "b+00000464         feature_ro_compat: SPARSE_SUPER | LARGE_FILE | HUGE_FILE | DIR_NLINK | EXTRA_ISIZE | METADATA_CSUM\n"
        "b+00000468                      uuid: 202122232425262728292a2b2c2d2e2f\n"
        "b+00000478               volume_name: 'bhextest'\n"
        "b+00000488              last_mounted: ''\n"
        "b+000004c8    algorithm_usage_bitmap: 00000000\n"
        "b+000004cc           prealloc_blocks: 00\n"
        "b+000004cd       prealloc_dir_blocks: 00\n"
        "b+000004ce       reserved_gdt_blocks: 0000\n"
        "b+000004d0              journal_uuid: 00000000000000000000000000000000\n"
        "b+000004e0              journal_inum: 00000000\n"
        "b+000004e4               journal_dev: 00000000\n"
        "b+000004e8               last_orphan: 00000000\n"
        "b+000004ec                 hash_seed: [ 00000000, 00000000, 00000000, 00000000 ]\n"
        "b+000004fc          def_hash_version: 00\n"
        "b+000004fd           jnl_backup_type: 00\n"
        "b+000004fe                 desc_size: 0040\n"
        "b+00000500        default_mount_opts: 0000000c\n"
        "b+00000504             first_meta_bg: 00000000\n"
        "b+00000508                 mkfs_time: 00000000\n"
        "b+0000050c                jnl_blocks: [ 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, 00000000, ... ]\n"
        "b+00000550           blocks_count_hi: 00000000\n"
        "b+00000554  reserved_blocks_count_hi: 00000000\n"
        "b+00000558      free_blocks_count_hi: 00000000\n"
        "b+0000055c                 remainder: 00000000000000000000000000000000...\n"
        "  ext4, 1024 byte blocks, 4194304 bytes\n"
        "\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_ext, sizeof(sample_ext));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/ext.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_fat_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000              bpb: \n"
        "b+00000000            jump_boot: eb3c90\n"
        "b+00000003             oem_name: 'BHEX    '\n"
        "b+0000000b     bytes_per_sector: 0200\n"
        "b+0000000d  sectors_per_cluster: 01\n"
        "b+0000000e     reserved_sectors: 0001\n"
        "b+00000010             num_fats: 02\n"
        "b+00000011         root_entries: 0010\n"
        "b+00000013     total_sectors_16: 0008\n"
        "b+00000015                media: f8\n"
        "b+00000016   sectors_per_fat_16: 0001\n"
        "b+00000018    sectors_per_track: 0001\n"
        "b+0000001a            num_heads: 0001\n"
        "b+0000001c       hidden_sectors: 00000000\n"
        "b+00000020     total_sectors_32: 00000000\n"
        "b+00000024             ebpb: \n"
        "b+00000024         drive_number: 80\n"
        "b+00000025             reserved: 00\n"
        "b+00000026       boot_signature: 29\n"
        "b+00000027            volume_id: 12345678\n"
        "b+0000002b         volume_label: 'BHEXVOL    '\n"
        "b+00000036              fs_type: 'FAT12   '\n"
        "b+000001fe   boot_signature: aa55\n"
        "  FAT12, 4 clusters\n"
        "b+00000600            entry: \n"
        "b+00000600                 name: 'HELLO   TXT'\n"
        "b+0000060b           attributes: ARCHIVE\n"
        "b+0000060c          nt_reserved: 00\n"
        "b+0000060d    create_time_tenth: 00\n"
        "b+0000060e          create_time: 0000\n"
        "b+00000610          create_date: 0000\n"
        "b+00000612     last_access_date: 0000\n"
        "b+00000614   first_cluster_high: 0000\n"
        "b+00000616           write_time: 0000\n"
        "b+00000618           write_date: 0000\n"
        "b+0000061a    first_cluster_low: 0002\n"
        "b+0000061c            file_size: 0000000b\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_fat, sizeof(sample_fat));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/fat.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_gpt_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000           protective_mbr: 00000000000000000000000000000000...\n"
        "b+000001be         protective_entry: 00000200eeffffff010000000f000000\n"
        "b+000001ce              mbr_padding: 00000000000000000000000000000000...\n"
        "b+000001fe            mbr_signature: aa55\n"
        "b+00000200                   header: \n"
        "b+00000200                        magic: 'EFI PART'\n"
        "b+00000208                     revision: 00010000\n"
        "b+0000020c                  header_size: 0000005c\n"
        "b+00000210                 header_crc32: 803a39ee\n"
        "b+00000214                     reserved: 00000000\n"
        "b+00000218                       my_lba: 0000000000000001\n"
        "b+00000220                alternate_lba: 000000000000000f\n"
        "b+00000228             first_usable_lba: 0000000000000004\n"
        "b+00000230              last_usable_lba: 000000000000000c\n"
        "b+00000238                    disk_guid: 0ff94b7eda6c154a8a31ccebd8f48883\n"
        "b+00000248          partition_entry_lba: 0000000000000002\n"
        "b+00000250        num_partition_entries: 00000008\n"
        "b+00000254      size_of_partition_entry: 00000080\n"
        "b+00000258  partition_entry_array_crc32: cc326593\n"
        "b+00000400                  entries: [ \n"
        "                                    [0]\n"
        "b+00000400          partition_type_guid: 28732ac11ff8d211ba4b00a0c93ec93b\n"
        "    EFI System\n"
        "b+00000410        unique_partition_guid: fd13e0d5ae7c014d9ded6e676b2f80bf\n"
        "b+00000420                 starting_lba: 0000000000000004\n"
        "b+00000428                   ending_lba: 0000000000000005\n"
        "b+00000430                   attributes: 0000000000000000\n"
        "b+00000438               partition_name: 'EFI System'\n"
        "                                    [1]\n"
        "b+00000480          partition_type_guid: af3dc60f838472478e793d69d8477de4\n"
        "    Linux filesystem\n"
        "b+00000490        unique_partition_guid: 889f3343fecc6041a23ac4597a3eb54f\n"
        "b+000004a0                 starting_lba: 0000000000000006\n"
        "b+000004a8                   ending_lba: 000000000000000c\n"
        "b+000004b0                   attributes: 0000000000000000\n"
        "b+000004b8               partition_name: 'Linux root'\n"
        "                                    [2]\n"
        "b+00000500          partition_type_guid: 00000000000000000000000000000000\n"
        "b+00000510        unique_partition_guid: 00000000000000000000000000000000\n"
        "b+00000520                 starting_lba: 0000000000000000\n"
        "b+00000528                   ending_lba: 0000000000000000\n"
        "b+00000530                   attributes: 0000000000000000\n"
        "b+00000538               partition_name: ''\n"
        "                                    [3]\n"
        "b+00000580          partition_type_guid: 00000000000000000000000000000000\n"
        "b+00000590        unique_partition_guid: 00000000000000000000000000000000\n"
        "b+000005a0                 starting_lba: 0000000000000000\n"
        "b+000005a8                   ending_lba: 0000000000000000\n"
        "b+000005b0                   attributes: 0000000000000000\n"
        "b+000005b8               partition_name: ''\n"
        "                                    [4]\n"
        "b+00000600          partition_type_guid: 00000000000000000000000000000000\n"
        "b+00000610        unique_partition_guid: 00000000000000000000000000000000\n"
        "b+00000620                 starting_lba: 0000000000000000\n"
        "b+00000628                   ending_lba: 0000000000000000\n"
        "b+00000630                   attributes: 0000000000000000\n"
        "b+00000638               partition_name: ''\n"
        "                                    [5]\n"
        "b+00000680          partition_type_guid: 00000000000000000000000000000000\n"
        "b+00000690        unique_partition_guid: 00000000000000000000000000000000\n"
        "b+000006a0                 starting_lba: 0000000000000000\n"
        "b+000006a8                   ending_lba: 0000000000000000\n"
        "b+000006b0                   attributes: 0000000000000000\n"
        "b+000006b8               partition_name: ''\n"
        "                                    [6]\n"
        "b+00000700          partition_type_guid: 00000000000000000000000000000000\n"
        "b+00000710        unique_partition_guid: 00000000000000000000000000000000\n"
        "b+00000720                 starting_lba: 0000000000000000\n"
        "b+00000728                   ending_lba: 0000000000000000\n"
        "b+00000730                   attributes: 0000000000000000\n"
        "b+00000738               partition_name: ''\n"
        "                                    [7]\n"
        "b+00000780          partition_type_guid: 00000000000000000000000000000000\n"
        "b+00000790        unique_partition_guid: 00000000000000000000000000000000\n"
        "b+000007a0                 starting_lba: 0000000000000000\n"
        "b+000007a8                   ending_lba: 0000000000000000\n"
        "b+000007b0                   attributes: 0000000000000000\n"
        "b+000007b8               partition_name: '' ]\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_gpt, sizeof(sample_gpt));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/gpt.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_mbr_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000     boot_code: fa33c000000000000000000000000000...\n"
        "b+000001be     partition: \n"
        "b+000001be            status: 80\n"
        "b+000001bf         first_chs: \n"
        "b+000001bf                  head: 01\n"
        "b+000001c0  sector_cylinder_high: 01\n"
        "b+000001c1          cylinder_low: 00\n"
        "b+000001c2    partition_type: FAT32_LBA\n"
        "b+000001c3          last_chs: \n"
        "b+000001c3                  head: fe\n"
        "b+000001c4  sector_cylinder_high: ff\n"
        "b+000001c5          cylinder_low: ff\n"
        "b+000001c6         start_lba: 00000800\n"
        "b+000001ca      sector_count: 00005000\n"
        "b+000001ce     partition: \n"
        "b+000001ce            status: 00\n"
        "b+000001cf         first_chs: \n"
        "b+000001cf                  head: 01\n"
        "b+000001d0  sector_cylinder_high: 01\n"
        "b+000001d1          cylinder_low: 00\n"
        "b+000001d2    partition_type: LINUX\n"
        "b+000001d3          last_chs: \n"
        "b+000001d3                  head: fe\n"
        "b+000001d4  sector_cylinder_high: ff\n"
        "b+000001d5          cylinder_low: ff\n"
        "b+000001d6         start_lba: 00005800\n"
        "b+000001da      sector_count: 0000a000\n"
        "b+000001de     partition: \n"
        "b+000001de            status: 00\n"
        "b+000001df         first_chs: \n"
        "b+000001df                  head: 00\n"
        "b+000001e0  sector_cylinder_high: 00\n"
        "b+000001e1          cylinder_low: 00\n"
        "b+000001e2    partition_type: EMPTY\n"
        "b+000001e3          last_chs: \n"
        "b+000001e3                  head: 00\n"
        "b+000001e4  sector_cylinder_high: 00\n"
        "b+000001e5          cylinder_low: 00\n"
        "b+000001e6         start_lba: 00000000\n"
        "b+000001ea      sector_count: 00000000\n"
        "b+000001ee     partition: \n"
        "b+000001ee            status: 00\n"
        "b+000001ef         first_chs: \n"
        "b+000001ef                  head: 00\n"
        "b+000001f0  sector_cylinder_high: 00\n"
        "b+000001f1          cylinder_low: 00\n"
        "b+000001f2    partition_type: EMPTY\n"
        "b+000001f3          last_chs: \n"
        "b+000001f3                  head: 00\n"
        "b+000001f4  sector_cylinder_high: 00\n"
        "b+000001f5          cylinder_low: 00\n"
        "b+000001f6         start_lba: 00000000\n"
        "b+000001fa      sector_count: 00000000\n"
        "b+000001fe     signature: aa55\n"
        "  partition 0 at byte 1048576 size 10485760\n"
        "  partition 1 at byte 11534336 size 20971520\n"
        "\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_mbr, sizeof(sample_mbr));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/mbr.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_dex_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000       header: \n"
        "b+00000000            magic: 'dex\\x0a035'\n"
        "b+00000008         checksum: d9700bbe\n"
        "b+0000000c        signature: 1d9c3f88730d0ed6caa377d4520465e7...\n"
        "b+00000020        file_size: 0000008c\n"
        "b+00000024      header_size: 00000070\n"
        "b+00000028       endian_tag: 12345678\n"
        "b+0000002c        link_size: 00000000\n"
        "b+00000030         link_off: 00000000\n"
        "b+00000034          map_off: 00000070\n"
        "b+00000038  string_ids_size: 00000000\n"
        "b+0000003c   string_ids_off: 00000000\n"
        "b+00000040    type_ids_size: 00000000\n"
        "b+00000044     type_ids_off: 00000000\n"
        "b+00000048   proto_ids_size: 00000000\n"
        "b+0000004c    proto_ids_off: 00000000\n"
        "b+00000050   field_ids_size: 00000000\n"
        "b+00000054    field_ids_off: 00000000\n"
        "b+00000058  method_ids_size: 00000000\n"
        "b+0000005c   method_ids_off: 00000000\n"
        "b+00000060  class_defs_size: 00000000\n"
        "b+00000064   class_defs_off: 00000000\n"
        "b+00000068        data_size: 0000001c\n"
        "b+0000006c         data_off: 00000070\n"
        "  version: 035\n"
        "b+00000070     map_size: 00000002\n"
        "b+00000074         item: \n"
        "b+00000074        item_type: HEADER_ITEM\n"
        "b+00000076           unused: 0000\n"
        "b+00000078             size: 00000001\n"
        "b+0000007c           offset: 00000000\n"
        "b+00000080         item: \n"
        "b+00000080        item_type: MAP_LIST\n"
        "b+00000082           unused: 0000\n"
        "b+00000084             size: 00000001\n"
        "b+00000088           offset: 00000070\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_dex, sizeof(sample_dex));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/dex.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_gif_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000              header: \n"
        "b+00000000                   magic: 'GIF'\n"
        "b+00000003                 version: '89a'\n"
        "b+00000006                   width: 0001\n"
        "b+00000008                  height: 0001\n"
        "b+0000000a                  packed: 80\n"
        "b+0000000b  background_color_index: 00\n"
        "b+0000000c      pixel_aspect_ratio: 00\n"
        "b+0000000d      global_color_table: ffffff000000\n"
        "b+00000013               image: \n"
        "b+00000013               separator: 2c\n"
        "b+00000014                    left: 0000\n"
        "b+00000016                     top: 0000\n"
        "b+00000018                   width: 0001\n"
        "b+0000001a                  height: 0001\n"
        "b+0000001c                  packed: 00\n"
        "b+0000001d       lzw_min_code_size: 02\n"
        "b+0000001e          image_data: \n"
        "b+0000001e                    data: 02440100\n"
        "b+00000022             trailer: 3b\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_gif, sizeof(sample_gif));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/gif.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_ogg_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000          page: \n"
        "b+00000000   capture_pattern: 'OggS'\n"
        "b+00000004    stream_version: 00\n"
        "b+00000005       header_type: FIRST\n"
        "b+00000006  granule_position: 0000000000000000\n"
        "b+0000000e  bitstream_serial: 1234abcd\n"
        "b+00000012     page_sequence: 00000000\n"
        "b+00000016     page_checksum: b4663ccf\n"
        "b+0000001a     page_segments: 01\n"
        "b+0000001b     segment_table: 1e\n"
        "b+0000001c         page_data: 01766f72626973000000000000000000...\n"
        "b+0000003a          page: \n"
        "b+0000003a   capture_pattern: 'OggS'\n"
        "b+0000003e    stream_version: 00\n"
        "b+0000003f       header_type: LAST\n"
        "b+00000040  granule_position: 0000000000000064\n"
        "b+00000048  bitstream_serial: 1234abcd\n"
        "b+0000004c     page_sequence: 00000001\n"
        "b+00000050     page_checksum: 29a2fa92\n"
        "b+00000054     page_segments: 01\n"
        "b+00000055     segment_table: 11\n"
        "b+00000056         page_data: 617564696f2d697368207061796c6f61...\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_ogg, sizeof(sample_ogg));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/ogg.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_sfnt_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000    sfnt_version: TRUETYPE\n"
        "b+00000004      num_tables: 0002\n"
        "b+00000006    search_range: 0020\n"
        "b+00000008  entry_selector: 0001\n"
        "b+0000000a     range_shift: 0000\n"
        "b+0000000c           table: \n"
        "b+0000000c                 tag: 'head'\n"
        "b+00000010            checksum: 62fb44c5\n"
        "b+00000014              offset: 0000002c\n"
        "b+00000018              length: 00000036\n"
        "b+0000001c           table: \n"
        "b+0000001c                 tag: 'maxp'\n"
        "b+00000020            checksum: 00005000\n"
        "b+00000024              offset: 00000064\n"
        "b+00000028              length: 00000006\n"
        "  font ends at 0\n"
        "\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_sfnt, sizeof(sample_sfnt));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/sfnt.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_wasm_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000         magic: 0061736d\n"
        "b+00000004       version: 00000001\n"
        "b+00000008       section: \n"
        "b+00000008        section_id: TYPE\n"
        "b+00000009      section_size: 04\n"
        "b+0000000a  section_data: 01600000\n"
        "b+0000000e       section: \n"
        "b+0000000e        section_id: FUNCTION\n"
        "b+0000000f      section_size: 02\n"
        "b+00000010  section_data: 0100\n"
        "b+00000012       section: \n"
        "b+00000012        section_id: EXPORT\n"
        "b+00000013      section_size: 07\n"
        "b+00000014  section_data: 01036e6f700000\n"
        "b+0000001b       section: \n"
        "b+0000001b        section_id: CODE\n"
        "b+0000001c      section_size: 04\n"
        "b+0000001d  section_data: 0102000b\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_wasm, sizeof(sample_wasm));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/wasm.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_x509_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000      certificate_tag: SEQUENCE\n"
        "b+00000001   certificate_length: 820327\n"
        "  certificate is 811 bytes\n"
        "b+00000004      tbs_certificate: \n"
        "b+00000004                      tag: SEQUENCE\n"
        "b+00000005             length_field: 82020f\n"
        "b+00000008                    value: a0030201020214626af93e8a4c46a6fc...\n"
        "b+00000217  signature_algorithm: \n"
        "b+00000217                      tag: SEQUENCE\n"
        "b+00000218             length_field: 0d\n"
        "b+00000219                    value: 06092a864886f70d01010b0500\n"
        "b+00000226      signature_value: \n"
        "b+00000226                      tag: BIT_STRING\n"
        "b+00000227             length_field: 820101\n"
        "b+0000022a                    value: 008bd0e803f4d54b8b16319b53b66163...\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_x509, sizeof(sample_x509));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/x509.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_tar_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000  header: \n"
        "b+00000000        name: 'hello.txt'\n"
        "b+00000064        mode: '0000664'\n"
        "b+0000006c         uid: '0000000'\n"
        "b+00000074         gid: '0000000'\n"
        "b+0000007c        size: '00000000013'\n"
        "b+00000088       mtime: '00000000000'\n"
        "b+00000094      chksum: '007605'\n"
        "b+0000009c    typeflag: 0\n"
        "b+0000009d    linkname: ''\n"
        "b+00000101       magic: 'ustar'\n"
        "b+00000107     version: '00'\n"
        "b+00000109       uname: ''\n"
        "b+00000129       gname: ''\n"
        "b+00000149    devmajor: ''\n"
        "b+00000151    devminor: ''\n"
        "b+00000159      prefix: ''\n"
        "b+000001f4     padding: 000000000000000000000000\n"
        "b+00000200    data: 68656c6c6f20626865780a\n"
        "b+00000400  header: \n"
        "b+00000400        name: 'bin.dat'\n"
        "b+00000464        mode: '0000664'\n"
        "b+0000046c         uid: '0000000'\n"
        "b+00000474         gid: '0000000'\n"
        "b+0000047c        size: '00000000004'\n"
        "b+00000488       mtime: '00000000000'\n"
        "b+00000494      chksum: '007203'\n"
        "b+0000049c    typeflag: 0\n"
        "b+0000049d    linkname: ''\n"
        "b+00000501       magic: 'ustar'\n"
        "b+00000507     version: '00'\n"
        "b+00000509       uname: ''\n"
        "b+00000529       gname: ''\n"
        "b+00000549    devmajor: ''\n"
        "b+00000551    devminor: ''\n"
        "b+00000559      prefix: ''\n"
        "b+000005f4     padding: 000000000000000000000000\n"
        "b+00000600    data: 01020304\n"
        "b+00000800  header: \n"
        "b+00000800        name: ''\n"
        "b+00000864        mode: ''\n"
        "b+0000086c         uid: ''\n"
        "b+00000874         gid: ''\n"
        "b+0000087c        size: ''\n"
        "b+00000888       mtime: ''\n"
        "b+00000894      chksum: ''\n"
        "b+0000089c    typeflag: '\\x00'\n"
        "b+0000089d    linkname: ''\n"
        "b+00000901       magic: ''\n"
        "b+00000907     version: ''\n"
        "b+00000909       uname: ''\n"
        "b+00000929       gname: ''\n"
        "b+00000949    devmajor: ''\n"
        "b+00000951    devminor: ''\n"
        "b+00000959      prefix: ''\n"
        "b+000009f4     padding: 000000000000000000000000\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_tar, sizeof(sample_tar));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/tar.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_cab_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000          header: \n"
        "b+00000000           signature: 'MSCF'\n"
        "b+00000004           reserved1: 00000000\n"
        "b+00000008          cb_cabinet: 0000028d\n"
        "b+0000000c           reserved2: 00000000\n"
        "b+00000010          coff_files: 0000002c\n"
        "b+00000014           reserved3: 00000000\n"
        "b+00000018       version_minor: 03\n"
        "b+00000019       version_major: 01\n"
        "b+0000001a           n_folders: 0001\n"
        "b+0000001c             n_files: 0002\n"
        "b+0000001e               flags: NONE\n"
        "b+00000020              set_id: 1234\n"
        "b+00000022       cabinet_index: 0000\n"
        "b+00000024          folder: \n"
        "b+00000024      coff_cab_start: 00000066\n"
        "b+00000028              n_data: 0001\n"
        "b+0000002a         compression: NONE\n"
        "b+0000002b              window: 00\n"
        "b+0000002c            file: \n"
        "b+0000002c             cb_file: 0000001f\n"
        "b+00000030   uoff_folder_start: 00000000\n"
        "b+00000034            i_folder: 0000\n"
        "b+00000036                date: 5d05\n"
        "b+00000038                time: 645c\n"
        "b+0000003a             attribs: ARCH\n"
        "b+0000003c                name: 'hello.txt'\n"
        "b+00000046            file: \n"
        "b+00000046             cb_file: 00000200\n"
        "b+0000004a   uoff_folder_start: 0000001f\n"
        "b+0000004e            i_folder: 0000\n"
        "b+00000050                date: 5d05\n"
        "b+00000052                time: 645c\n"
        "b+00000054             attribs: ARCH\n"
        "b+00000056                name: 'data\\nested.bin'\n"
        "folder 0 data blocks:\n"
        "b+00000066           block: \n"
        "b+00000066                csum: 5d09350c\n"
        "b+0000006a             cb_data: 021f\n"
        "b+0000006c           cb_uncomp: 021f\n"
        "b+0000006e            data: 48656c6c6f2066726f6d206120626865...\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_cab, sizeof(sample_cab));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/cab.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_iso9660_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00008000         volume_descriptor: \n"
        "b+00008000                          type: PRIMARY\n"
        "b+00008001                            id: 'CD001'\n"
        "b+00008006                       version: 01\n"
        "b+00008007                         flags: 00\n"
        "b+00008008                     system_id: 'BHEX                            '\n"
        "b+00008028                     volume_id: 'BHEX_SAMPLE                     '\n"
        "b+00008048                       unused2: 0000000000000000\n"
        "b+00008050             volume_space_size: \n"
        "b+00008050                                le: 0000001b\n"
        "b+00008054                                be: 0000001b\n"
        "b+00008058              escape_sequences: 00000000000000000000000000000000...\n"
        "b+00008078               volume_set_size: \n"
        "b+00008078                                le: 0001\n"
        "b+0000807a                                be: 0001\n"
        "b+0000807c             volume_seq_number: \n"
        "b+0000807c                                le: 0001\n"
        "b+0000807e                                be: 0001\n"
        "b+00008080            logical_block_size: \n"
        "b+00008080                                le: 0800\n"
        "b+00008082                                be: 0800\n"
        "b+00008084               path_table_size: \n"
        "b+00008084                                le: 00000018\n"
        "b+00008088                                be: 00000018\n"
        "b+0000808c             type_l_path_table: 00000013\n"
        "b+00008090         opt_type_l_path_table: 00000000\n"
        "b+00008094             type_m_path_table: 00000014\n"
        "b+00008098         opt_type_m_path_table: 00000000\n"
        "b+0000809c         root_directory_record: \n"
        "b+0000809c                            length: 22\n"
        "b+0000809d                   ext_attr_length: 00\n"
        "b+0000809e                            extent: \n"
        "b+0000809e                                    le: 00000015\n"
        "b+000080a2                                    be: 00000015\n"
        "b+000080a6                       data_length: \n"
        "b+000080a6                                    le: 00000800\n"
        "b+000080aa                                    be: 00000800\n"
        "b+000080ae                       recorded_at: \n"
        "b+000080ae                      years_since_1900: 7e\n"
        "b+000080af                                 month: 08\n"
        "b+000080b0                                   day: 05\n"
        "b+000080b1                                  hour: 0c\n"
        "b+000080b2                                minute: 00\n"
        "b+000080b3                                second: 00\n"
        "b+000080b4                            gmt_offset: 00\n"
        "b+000080b5                             flags: DIRECTORY\n"
        "b+000080b6                    file_unit_size: 00\n"
        "b+000080b7                    interleave_gap: 00\n"
        "b+000080b8                 volume_seq_number: \n"
        "b+000080b8                                    le: 0001\n"
        "b+000080ba                                    be: 0001\n"
        "b+000080bc                    file_id_length: 01\n"
        "b+000080bd                           file_id: 00\n"
        "b+000080be                 volume_set_id: 'BHEX_SET                                                                                                                        '\n"
        "b+0000813e                  publisher_id: 'BHEX                                                                                                                            '\n"
        "b+000081be              data_preparer_id: 'BHEX TEMPLATE CORPUS                                                                                                            '\n"
        "b+0000823e                application_id: 'BHEX                                                                                                                            '\n"
        "b+000082be             copyright_file_id: '                                     '\n"
        "b+000082e3              abstract_file_id: '                                     '\n"
        "b+00008308         bibliographic_file_id: '                                     '\n"
        "b+0000832d                    created_at: \n"
        "b+0000832d                              year: '2026'\n"
        "b+00008331                             month: '08'\n"
        "b+00008333                               day: '05'\n"
        "b+00008335                              hour: '12'\n"
        "b+00008337                            minute: '00'\n"
        "b+00008339                            second: '00'\n"
        "b+0000833b                      centiseconds: '00'\n"
        "b+0000833d                        gmt_offset: 00\n"
        "b+0000833e                   modified_at: \n"
        "b+0000833e                              year: '2026'\n"
        "b+00008342                             month: '08'\n"
        "b+00008344                               day: '05'\n"
        "b+00008346                              hour: '12'\n"
        "b+00008348                            minute: '00'\n"
        "b+0000834a                            second: '00'\n"
        "b+0000834c                      centiseconds: '00'\n"
        "b+0000834e                        gmt_offset: 00\n"
        "b+0000834f                    expires_at: \n"
        "b+0000834f                              year: '0000'\n"
        "b+00008353                             month: '00'\n"
        "b+00008355                               day: '00'\n"
        "b+00008357                              hour: '00'\n"
        "b+00008359                            minute: '00'\n"
        "b+0000835b                            second: '00'\n"
        "b+0000835d                      centiseconds: '00'\n"
        "b+0000835f                        gmt_offset: 00\n"
        "b+00008360                  effective_at: \n"
        "b+00008360                              year: '2026'\n"
        "b+00008364                             month: '08'\n"
        "b+00008366                               day: '05'\n"
        "b+00008368                              hour: '12'\n"
        "b+0000836a                            minute: '00'\n"
        "b+0000836c                            second: '00'\n"
        "b+0000836e                      centiseconds: '00'\n"
        "b+00008370                        gmt_offset: 00\n"
        "b+00008371        file_structure_version: 01\n"
        "b+00008372                     reserved1: 00\n"
        "b+00008373              application_used: 00000000000000000000000000000000...\n"
        "b+00008573                     reserved2: 00000000000000000000000000000000...\n"
        "b+00008800               boot_record: \n"
        "b+00008800                          type: BOOT_RECORD\n"
        "b+00008801                            id: 'CD001'\n"
        "b+00008806                       version: 01\n"
        "b+00008807                boot_system_id: 'EL TORITO SPECIFICATION'\n"
        "b+00008827                       boot_id: ''\n"
        "b+00008847           boot_catalog_sector: 00000019\n"
        "b+0000884b               boot_system_use: 00000000000000000000000000000000...\n"
        "b+00009000  volume_descriptor_header: \n"
        "b+00009000                          type: TERMINATOR\n"
        "b+00009001                            id: 'CD001'\n"
        "b+00009006                       version: 01\n"
        "b+0000c800           boot_validation: \n"
        "b+0000c800                     header_id: 01\n"
        "b+0000c801                   platform_id: 00\n"
        "b+0000c802                      reserved: 0000\n"
        "b+0000c804                  manufacturer: 'BHEX'\n"
        "b+0000c81c                      checksum: b523\n"
        "b+0000c81e                         key55: 55\n"
        "b+0000c81f                         keyAA: aa\n"
        "b+0000c820                boot_entry: \n"
        "b+0000c820                      bootable: 88\n"
        "b+0000c821                    media_type: NO_EMULATION\n"
        "b+0000c822                  load_segment: 0000\n"
        "b+0000c824                   system_type: 00\n"
        "b+0000c825                       unused1: 00\n"
        "b+0000c826                  sector_count: 0004\n"
        "b+0000c828                      load_rba: 0000001a\n"
        "b+0000c82c                       unused2: 00000000000000000000000000000000...\n"
        "b+00009800         path_table_record: \n"
        "b+00009800                   name_length: 01\n"
        "b+00009801               ext_attr_length: 00\n"
        "b+00009802                        extent: 00000015\n"
        "b+00009806                  parent_index: 0001\n"
        "b+00009808                          name: 00\n"
        "b+00009809                       padding: 00\n"
        "b+0000980a         path_table_record: \n"
        "b+0000980a                   name_length: 06\n"
        "b+0000980b               ext_attr_length: 00\n"
        "b+0000980c                        extent: 00000016\n"
        "b+00009810                  parent_index: 0001\n"
        "b+00009812                          name: 'SUBDIR'\n"
        "path table: 2 directories\n"
        "directory 1 contents:\n"
        "b+0000a800                dir_record: \n"
        "b+0000a800                        length: 22\n"
        "b+0000a801               ext_attr_length: 00\n"
        "b+0000a802                        extent: \n"
        "b+0000a802                                le: 00000015\n"
        "b+0000a806                                be: 00000015\n"
        "b+0000a80a                   data_length: \n"
        "b+0000a80a                                le: 00000800\n"
        "b+0000a80e                                be: 00000800\n"
        "b+0000a812                   recorded_at: \n"
        "b+0000a812                  years_since_1900: 7e\n"
        "b+0000a813                             month: 08\n"
        "b+0000a814                               day: 05\n"
        "b+0000a815                              hour: 0c\n"
        "b+0000a816                            minute: 00\n"
        "b+0000a817                            second: 00\n"
        "b+0000a818                        gmt_offset: 00\n"
        "b+0000a819                         flags: DIRECTORY\n"
        "b+0000a81a                file_unit_size: 00\n"
        "b+0000a81b                interleave_gap: 00\n"
        "b+0000a81c             volume_seq_number: \n"
        "b+0000a81c                                le: 0001\n"
        "b+0000a81e                                be: 0001\n"
        "b+0000a820                file_id_length: 01\n"
        "b+0000a821                       file_id: 00\n"
        "b+0000a822                dir_record: \n"
        "b+0000a822                        length: 22\n"
        "b+0000a823               ext_attr_length: 00\n"
        "b+0000a824                        extent: \n"
        "b+0000a824                                le: 00000015\n"
        "b+0000a828                                be: 00000015\n"
        "b+0000a82c                   data_length: \n"
        "b+0000a82c                                le: 00000800\n"
        "b+0000a830                                be: 00000800\n"
        "b+0000a834                   recorded_at: \n"
        "b+0000a834                  years_since_1900: 7e\n"
        "b+0000a835                             month: 08\n"
        "b+0000a836                               day: 05\n"
        "b+0000a837                              hour: 0c\n"
        "b+0000a838                            minute: 00\n"
        "b+0000a839                            second: 00\n"
        "b+0000a83a                        gmt_offset: 00\n"
        "b+0000a83b                         flags: DIRECTORY\n"
        "b+0000a83c                file_unit_size: 00\n"
        "b+0000a83d                interleave_gap: 00\n"
        "b+0000a83e             volume_seq_number: \n"
        "b+0000a83e                                le: 0001\n"
        "b+0000a840                                be: 0001\n"
        "b+0000a842                file_id_length: 01\n"
        "b+0000a843                       file_id: 01\n"
        "b+0000a844                dir_record: \n"
        "b+0000a844                        length: 2e\n"
        "b+0000a845               ext_attr_length: 00\n"
        "b+0000a846                        extent: \n"
        "b+0000a846                                le: 00000017\n"
        "b+0000a84a                                be: 00000017\n"
        "b+0000a84e                   data_length: \n"
        "b+0000a84e                                le: 00000024\n"
        "b+0000a852                                be: 00000024\n"
        "b+0000a856                   recorded_at: \n"
        "b+0000a856                  years_since_1900: 7e\n"
        "b+0000a857                             month: 08\n"
        "b+0000a858                               day: 05\n"
        "b+0000a859                              hour: 0c\n"
        "b+0000a85a                            minute: 00\n"
        "b+0000a85b                            second: 00\n"
        "b+0000a85c                        gmt_offset: 00\n"
        "b+0000a85d                         flags: NONE\n"
        "b+0000a85e                file_unit_size: 00\n"
        "b+0000a85f                interleave_gap: 00\n"
        "b+0000a860             volume_seq_number: \n"
        "b+0000a860                                le: 0001\n"
        "b+0000a862                                be: 0001\n"
        "b+0000a864                file_id_length: 0c\n"
        "b+0000a865                       file_id: 'README.TXT;1'\n"
        "b+0000a871                    system_use: 00\n"
        "b+0000a872                dir_record: \n"
        "b+0000a872                        length: 28\n"
        "b+0000a873               ext_attr_length: 00\n"
        "b+0000a874                        extent: \n"
        "b+0000a874                                le: 00000016\n"
        "b+0000a878                                be: 00000016\n"
        "b+0000a87c                   data_length: \n"
        "b+0000a87c                                le: 00000800\n"
        "b+0000a880                                be: 00000800\n"
        "b+0000a884                   recorded_at: \n"
        "b+0000a884                  years_since_1900: 7e\n"
        "b+0000a885                             month: 08\n"
        "b+0000a886                               day: 05\n"
        "b+0000a887                              hour: 0c\n"
        "b+0000a888                            minute: 00\n"
        "b+0000a889                            second: 00\n"
        "b+0000a88a                        gmt_offset: 00\n"
        "b+0000a88b                         flags: DIRECTORY\n"
        "b+0000a88c                file_unit_size: 00\n"
        "b+0000a88d                interleave_gap: 00\n"
        "b+0000a88e             volume_seq_number: \n"
        "b+0000a88e                                le: 0001\n"
        "b+0000a890                                be: 0001\n"
        "b+0000a892                file_id_length: 06\n"
        "b+0000a893                       file_id: 'SUBDIR'\n"
        "b+0000a899                    system_use: 00\n"
        "directory 2 contents:\n"
        "b+0000b000                dir_record: \n"
        "b+0000b000                        length: 22\n"
        "b+0000b001               ext_attr_length: 00\n"
        "b+0000b002                        extent: \n"
        "b+0000b002                                le: 00000016\n"
        "b+0000b006                                be: 00000016\n"
        "b+0000b00a                   data_length: \n"
        "b+0000b00a                                le: 00000800\n"
        "b+0000b00e                                be: 00000800\n"
        "b+0000b012                   recorded_at: \n"
        "b+0000b012                  years_since_1900: 7e\n"
        "b+0000b013                             month: 08\n"
        "b+0000b014                               day: 05\n"
        "b+0000b015                              hour: 0c\n"
        "b+0000b016                            minute: 00\n"
        "b+0000b017                            second: 00\n"
        "b+0000b018                        gmt_offset: 00\n"
        "b+0000b019                         flags: DIRECTORY\n"
        "b+0000b01a                file_unit_size: 00\n"
        "b+0000b01b                interleave_gap: 00\n"
        "b+0000b01c             volume_seq_number: \n"
        "b+0000b01c                                le: 0001\n"
        "b+0000b01e                                be: 0001\n"
        "b+0000b020                file_id_length: 01\n"
        "b+0000b021                       file_id: 00\n"
        "b+0000b022                dir_record: \n"
        "b+0000b022                        length: 22\n"
        "b+0000b023               ext_attr_length: 00\n"
        "b+0000b024                        extent: \n"
        "b+0000b024                                le: 00000015\n"
        "b+0000b028                                be: 00000015\n"
        "b+0000b02c                   data_length: \n"
        "b+0000b02c                                le: 00000800\n"
        "b+0000b030                                be: 00000800\n"
        "b+0000b034                   recorded_at: \n"
        "b+0000b034                  years_since_1900: 7e\n"
        "b+0000b035                             month: 08\n"
        "b+0000b036                               day: 05\n"
        "b+0000b037                              hour: 0c\n"
        "b+0000b038                            minute: 00\n"
        "b+0000b039                            second: 00\n"
        "b+0000b03a                        gmt_offset: 00\n"
        "b+0000b03b                         flags: DIRECTORY\n"
        "b+0000b03c                file_unit_size: 00\n"
        "b+0000b03d                interleave_gap: 00\n"
        "b+0000b03e             volume_seq_number: \n"
        "b+0000b03e                                le: 0001\n"
        "b+0000b040                                be: 0001\n"
        "b+0000b042                file_id_length: 01\n"
        "b+0000b043                       file_id: 01\n"
        "b+0000b044                dir_record: \n"
        "b+0000b044                        length: 2e\n"
        "b+0000b045               ext_attr_length: 00\n"
        "b+0000b046                        extent: \n"
        "b+0000b046                                le: 00000018\n"
        "b+0000b04a                                be: 00000018\n"
        "b+0000b04e                   data_length: \n"
        "b+0000b04e                                le: 00000078\n"
        "b+0000b052                                be: 00000078\n"
        "b+0000b056                   recorded_at: \n"
        "b+0000b056                  years_since_1900: 7e\n"
        "b+0000b057                             month: 08\n"
        "b+0000b058                               day: 05\n"
        "b+0000b059                              hour: 0c\n"
        "b+0000b05a                            minute: 00\n"
        "b+0000b05b                            second: 00\n"
        "b+0000b05c                        gmt_offset: 00\n"
        "b+0000b05d                         flags: NONE\n"
        "b+0000b05e                file_unit_size: 00\n"
        "b+0000b05f                interleave_gap: 00\n"
        "b+0000b060             volume_seq_number: \n"
        "b+0000b060                                le: 0001\n"
        "b+0000b062                                be: 0001\n"
        "b+0000b064                file_id_length: 0c\n"
        "b+0000b065                       file_id: 'NESTED.BIN;1'\n"
        "b+0000b071                    system_use: 00\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_iso9660, sizeof(sample_iso9660));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/iso9660.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_jffs2_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000          node: \n"
        "b+00000000             magic: 1985\n"
        "b+00000002          nodetype: CLEANMARKER\n"
        "b+00000004            totlen: 0000000c\n"
        "b+00000008           hdr_crc: e41eb0b1\n"
        "b+0000000c         inode: \n"
        "b+0000000c              node: \n"
        "b+0000000c                 magic: 1985\n"
        "b+0000000e              nodetype: INODE\n"
        "b+00000010                totlen: 00000044\n"
        "b+00000014               hdr_crc: 98f7fb1d\n"
        "b+00000018               ino: 00000001\n"
        "b+0000001c           version: 00000001\n"
        "b+00000020              mode: 000041ed\n"
        "b+00000024               uid: 0000\n"
        "b+00000026               gid: 0000\n"
        "b+00000028             isize: 00000000\n"
        "b+0000002c             atime: 6a64f040\n"
        "b+00000030             mtime: 6a64f040\n"
        "b+00000034             ctime: 6a64f040\n"
        "b+00000038            offset: 00000000\n"
        "b+0000003c             csize: 00000000\n"
        "b+00000040             dsize: 00000000\n"
        "b+00000044             compr: NONE\n"
        "b+00000045         usercompr: 00\n"
        "b+00000046             flags: 0000\n"
        "b+00000048          data_crc: 00000000\n"
        "b+0000004c          node_crc: 8734003f\n"
        "b+00000050              data: \n"
        "b+00000050        dirent: \n"
        "b+00000050              node: \n"
        "b+00000050                 magic: 1985\n"
        "b+00000052              nodetype: DIRENT\n"
        "b+00000054                totlen: 00000031\n"
        "b+00000058               hdr_crc: 4282d91d\n"
        "b+0000005c              pino: 00000001\n"
        "b+00000060           version: 00000001\n"
        "b+00000064               ino: 00000002\n"
        "b+00000068            mctime: 6a64f040\n"
        "b+0000006c             nsize: 09\n"
        "b+0000006d              type: REG\n"
        "b+0000006e            unused: 0000\n"
        "b+00000070          node_crc: 592bf0ee\n"
        "b+00000074          name_crc: f469da15\n"
        "b+00000078              name: 'hello.txt'\n"
        "b+00000081  node_padding: 000000\n"
        "b+00000084         inode: \n"
        "b+00000084              node: \n"
        "b+00000084                 magic: 1985\n"
        "b+00000086              nodetype: INODE\n"
        "b+00000088                totlen: 00000064\n"
        "b+0000008c               hdr_crc: 38c55423\n"
        "b+00000090               ino: 00000002\n"
        "b+00000094           version: 00000001\n"
        "b+00000098              mode: 000081a4\n"
        "b+0000009c               uid: 0000\n"
        "b+0000009e               gid: 0000\n"
        "b+000000a0             isize: 00000020\n"
        "b+000000a4             atime: 6a64f040\n"
        "b+000000a8             mtime: 6a64f040\n"
        "b+000000ac             ctime: 6a64f040\n"
        "b+000000b0            offset: 00000000\n"
        "b+000000b4             csize: 00000020\n"
        "b+000000b8             dsize: 00000020\n"
        "b+000000bc             compr: NONE\n"
        "b+000000bd         usercompr: 00\n"
        "b+000000be             flags: 0000\n"
        "b+000000c0          data_crc: d65af04e\n"
        "b+000000c4          node_crc: 2244834c\n"
        "b+000000c8              data: 48656c6c6f2066726f6d206120626865...\n"
        "b+000000e8        dirent: \n"
        "b+000000e8              node: \n"
        "b+000000e8                 magic: 1985\n"
        "b+000000ea              nodetype: DIRENT\n"
        "b+000000ec                totlen: 0000002e\n"
        "b+000000f0               hdr_crc: 4af89ed4\n"
        "b+000000f4              pino: 00000001\n"
        "b+000000f8           version: 00000001\n"
        "b+000000fc               ino: 00000003\n"
        "b+00000100            mctime: 6a64f040\n"
        "b+00000104             nsize: 06\n"
        "b+00000105              type: DIR\n"
        "b+00000106            unused: 0000\n"
        "b+00000108          node_crc: 93f755b3\n"
        "b+0000010c          name_crc: 68418c5a\n"
        "b+00000110              name: 'subdir'\n"
        "b+00000116  node_padding: 0000\n"
        "b+00000118         inode: \n"
        "b+00000118              node: \n"
        "b+00000118                 magic: 1985\n"
        "b+0000011a              nodetype: INODE\n"
        "b+0000011c                totlen: 00000044\n"
        "b+00000120               hdr_crc: 98f7fb1d\n"
        "b+00000124               ino: 00000003\n"
        "b+00000128           version: 00000001\n"
        "b+0000012c              mode: 000041ed\n"
        "b+00000130               uid: 0000\n"
        "b+00000132               gid: 0000\n"
        "b+00000134             isize: 00000000\n"
        "b+00000138             atime: 6a64f040\n"
        "b+0000013c             mtime: 6a64f040\n"
        "b+00000140             ctime: 6a64f040\n"
        "b+00000144            offset: 00000000\n"
        "b+00000148             csize: 00000000\n"
        "b+0000014c             dsize: 00000000\n"
        "b+00000150             compr: NONE\n"
        "b+00000151         usercompr: 00\n"
        "b+00000152             flags: 0000\n"
        "b+00000154          data_crc: 00000000\n"
        "b+00000158          node_crc: fc57d987\n"
        "b+0000015c              data: \n"
        "b+0000015c          node: \n"
        "b+0000015c             magic: 1985\n"
        "b+0000015e          nodetype: PADDING\n"
        "b+00000160            totlen: 00000ea4\n"
        "b+00000164           hdr_crc: 7b5a9ce9\n"
        "b+00000168     node_data: ffffffffffffffffffffffffffffffff...\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_jffs2, sizeof(sample_jffs2));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/jffs2.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_lha_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000          entry: \n"
        "b+00000000             header: \n"
        "b+00000000            header_size: 22\n"
        "b+00000001        header_checksum: e3\n"
        "b+00000002                 method: '-lh0-'\n"
        "b+00000007            packed_size: 0000001e\n"
        "b+0000000b          original_size: 0000001e\n"
        "b+0000000f          dos_timestamp: 5d05645c\n"
        "b+00000013              attribute: 20\n"
        "b+00000014               level_id: 01\n"
        "b+00000015            name_length: 09\n"
        "b+00000016                   name: 'hello.txt'\n"
        "b+0000001f                  crc16: 33d3\n"
        "b+00000021              os_id: UNIX\n"
        "b+00000022   next_header_size: 0000\n"
        "b+00000024               data: 48656c6c6f2066726f6d206120626865...\n"
        "b+00000042          entry: \n"
        "b+00000042             header: \n"
        "b+00000042            header_size: 26\n"
        "b+00000043        header_checksum: df\n"
        "b+00000044                 method: '-lh0-'\n"
        "b+00000049            packed_size: 00000021\n"
        "b+0000004d          original_size: 00000021\n"
        "b+00000051          dos_timestamp: 5d05645c\n"
        "b+00000055              attribute: 20\n"
        "b+00000056               level_id: 01\n"
        "b+00000057            name_length: 0d\n"
        "b+00000058                   name: 'docs\\notes.md'\n"
        "b+00000065                  crc16: 2548\n"
        "b+00000067              os_id: UNIX\n"
        "b+00000068   next_header_size: 0000\n"
        "b+0000006a               data: 23206e6f7465730a0a73746f7265642c...\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_lha, sizeof(sample_lha));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/lha.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_luks_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000               header: \n"
        "b+00000000                    magic: 'LUKS\\xba\\xbe'\n"
        "b+00000006                  version: 0001\n"
        "b+00000008              cipher_name: 'aes'\n"
        "b+00000028              cipher_mode: 'xts-plain64'\n"
        "b+00000048                hash_spec: 'sha256'\n"
        "b+00000068           payload_offset: 00000808\n"
        "b+0000006c                key_bytes: 00000020\n"
        "b+00000070                mk_digest: 000102030405060708090a0b0c0d0e0f...\n"
        "b+00000084           mk_digest_salt: 00070e151c232a31383f464d545b6269...\n"
        "b+000000a4     mk_digest_iterations: 0001dadf\n"
        "b+000000a8                     uuid: 'c9e0f1a2-3b4c-4d5e-8f90-a1b2c3d4e5f6'\n"
        "b+000000d0                 keyslots: [ \n"
        "                                    [0]\n"
        "b+000000d0                       active: ENABLED\n"
        "b+000000d4                   iterations: 0003d090\n"
        "b+000000d8                         salt: 000102030405060708090a0b0c0d0e0f...\n"
        "b+000000f8          key_material_offset: 00000008\n"
        "b+000000fc                      stripes: 00000fa0\n"
        "                                    [1]\n"
        "b+00000100                       active: ENABLED\n"
        "b+00000104                   iterations: 0003d091\n"
        "b+00000108                         salt: 0d0e0f101112131415161718191a1b1c...\n"
        "b+00000128          key_material_offset: 00000108\n"
        "b+0000012c                      stripes: 00000fa0\n"
        "                                    [2]\n"
        "b+00000130                       active: DISABLED\n"
        "b+00000134                   iterations: 0003d092\n"
        "b+00000138                         salt: 1a1b1c1d1e1f20212223242526272829...\n"
        "b+00000158          key_material_offset: 00000208\n"
        "b+0000015c                      stripes: 00000fa0\n"
        "                                    [3]\n"
        "b+00000160                       active: DISABLED\n"
        "b+00000164                   iterations: 0003d093\n"
        "b+00000168                         salt: 2728292a2b2c2d2e2f30313233343536...\n"
        "b+00000188          key_material_offset: 00000308\n"
        "b+0000018c                      stripes: 00000fa0\n"
        "                                    [4]\n"
        "b+00000190                       active: DISABLED\n"
        "b+00000194                   iterations: 0003d094\n"
        "b+00000198                         salt: 3435363738393a3b3c3d3e3f40414243...\n"
        "b+000001b8          key_material_offset: 00000408\n"
        "b+000001bc                      stripes: 00000fa0\n"
        "                                    [5]\n"
        "b+000001c0                       active: DISABLED\n"
        "b+000001c4                   iterations: 0003d095\n"
        "b+000001c8                         salt: 4142434445464748494a4b4c4d4e4f50...\n"
        "b+000001e8          key_material_offset: 00000508\n"
        "b+000001ec                      stripes: 00000fa0\n"
        "                                    [6]\n"
        "b+000001f0                       active: DISABLED\n"
        "b+000001f4                   iterations: 0003d096\n"
        "b+000001f8                         salt: 4e4f505152535455565758595a5b5c5d...\n"
        "b+00000218          key_material_offset: 00000608\n"
        "b+0000021c                      stripes: 00000fa0\n"
        "                                    [7]\n"
        "b+00000220                       active: DISABLED\n"
        "b+00000224                   iterations: 0003d097\n"
        "b+00000228                         salt: 5b5c5d5e5f606162636465666768696a...\n"
        "b+00000248          key_material_offset: 00000708\n"
        "b+0000024c                      stripes: 00000fa0 ]\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_luks, sizeof(sample_luks));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/luks.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_lz4_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000            frame: \n"
        "b+00000000                magic: 184d2204\n"
        "b+00000004           descriptor: \n"
        "b+00000004                      flg: CONTENT_CSUM | CONTENT_SIZE | BLOCK_CSUM | BLOCK_INDEP | VERSION_1\n"
        "b+00000005                       bd: MAX_64KB\n"
        "b+00000006             content_size: 000000000000071f\n"
        "b+0000000e          header_checksum: 10\n"
        "b+0000000f           block_size: 00000052\n"
        "b+00000013                 data: f12662686578206c7a34206672616d65...\n"
        "b+00000065       block_checksum: 00375aae\n"
        "b+00000069           block_size: 00000000\n"
        "b+0000006d     content_checksum: 95f6cae9\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_lz4, sizeof(sample_lz4));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/lz4.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_qcow2_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000               header: \n"
        "b+00000000                    magic: 'QFI\\xfb'\n"
        "b+00000004                  version: 00000003\n"
        "b+00000008      backing_file_offset: 0000000000000000\n"
        "b+00000010        backing_file_size: 00000000\n"
        "b+00000014             cluster_bits: 00000009\n"
        "b+00000018                     size: 0000000000010000\n"
        "b+00000020             crypt_method: NONE\n"
        "b+00000024                  l1_size: 00000002\n"
        "b+00000028          l1_table_offset: 0000000000000600\n"
        "b+00000030    refcount_table_offset: 0000000000000200\n"
        "b+00000038  refcount_table_clusters: 00000001\n"
        "b+0000003c             nb_snapshots: 00000000\n"
        "b+00000040         snapshots_offset: 0000000000000000\n"
        "b+00000048    incompatible_features: NONE\n"
        "b+00000050      compatible_features: NONE\n"
        "b+00000058       autoclear_features: NONE\n"
        "b+00000060           refcount_order: 00000004\n"
        "b+00000064            header_length: 00000068\n"
        "cluster size: 512 bytes\n"
        "b+00000068            extension: \n"
        "b+00000068                     type: FEATURE_NAME_TABLE\n"
        "b+0000006c                   length: 00000060\n"
        "b+00000070             features: [ \n"
        "                                [0]\n"
        "b+00000070             feature_type: 00\n"
        "b+00000071               bit_number: 00\n"
        "b+00000072                     name: 'dirty bit'\n"
        "                                [1]\n"
        "b+000000a0             feature_type: 00\n"
        "b+000000a1               bit_number: 01\n"
        "b+000000a2                     name: 'corrupt bit' ]\n"
        "b+000000d0            extension: \n"
        "b+000000d0                     type: END\n"
        "b+000000d4                   length: 00000000\n"
        "L1 table: 1 of 2 entries allocated\n"
        "b+00000600             l1_table: [ 8000000000000800, 0000000000000000 ]\n"
        "refcount table: 1 of 64 entries allocated\n"
        "b+00000200       refcount_table: [ 0000000000000400, 0000000000000000, 0000000000000000, 0000000000000000, 0000000000000000, 0000000000000000, 0000000000000000, 0000000000000000, ... ]\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_qcow2, sizeof(sample_qcow2));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/qcow2.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(template_rar_1)(void)
{
    // clang-format off
    const char* expected =
        "b+00000000    signature: 526172211a070100\n"
        "b+00000008       record: \n"
        "b+00000008     header_crc32: 32331ac5\n"
        "b+0000000c      header_size: 03\n"
        "b+0000000d      header_type: MAIN\n"
        "b+0000000e     header_flags: NONE\n"
        "b+0000000f      main_header: \n"
        "b+0000000f        archive_flags: NONE\n"
        "b+00000010       record: \n"
        "b+00000010     header_crc32: 373940b8\n"
        "b+00000014      header_size: 1a\n"
        "b+00000015      header_type: FILE\n"
        "b+00000016     header_flags: DATA_AREA\n"
        "b+00000017  data_size_field: 1e\n"
        "b+00000018      file_header: \n"
        "b+00000018           file_flags: MTIME | CRC32\n"
        "b+00000019        unpacked_size: 1e\n"
        "b+0000001a           attributes: 20\n"
        "b+0000001b                mtime: 68900000\n"
        "b+0000001f           data_crc32: 9a9e0111\n"
        "b+00000023     compression_info: 00\n"
        "    = version 0 method 0 dictionary 128 KB\n"
        "b+00000024              host_os: WINDOWS\n"
        "b+00000025            name_size: 09\n"
        "b+00000026                 name: 'hello.txt'\n"
        "b+0000002f             data: 48656c6c6f2066726f6d206120626865...\n"
        "b+0000004d       record: \n"
        "b+0000004d     header_crc32: 036017cd\n"
        "b+00000051      header_size: 1e\n"
        "b+00000052      header_type: FILE\n"
        "b+00000053     header_flags: DATA_AREA\n"
        "b+00000054  data_size_field: 21\n"
        "b+00000055      file_header: \n"
        "b+00000055           file_flags: MTIME | CRC32\n"
        "b+00000056        unpacked_size: 21\n"
        "b+00000057           attributes: 20\n"
        "b+00000058                mtime: 68900000\n"
        "b+0000005c           data_crc32: 956a0e80\n"
        "b+00000060     compression_info: 00\n"
        "    = version 0 method 0 dictionary 128 KB\n"
        "b+00000061              host_os: WINDOWS\n"
        "b+00000062            name_size: 0d\n"
        "b+00000063                 name: 'docs\\notes.md'\n"
        "b+00000070             data: 23206e6f7465730a0a73746f7265642c...\n"
        "b+00000091       record: \n"
        "b+00000091     header_crc32: 353ab219\n"
        "b+00000095      header_size: 03\n"
        "b+00000096      header_type: END\n"
        "b+00000097     header_flags: NONE\n"
        "b+00000098   end_of_archive: \n"
        "b+00000098            end_flags: NONE\n"
        "";
    // clang-format on

    int              r = TEST_SUCCEEDED;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_rar, sizeof(sample_rar));
    ASSERT(tfb != NULL);
    ASSERT(exec_commands_on("t ./templates/rar.bhe", tfb) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}
