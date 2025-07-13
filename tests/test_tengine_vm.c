#include "t_cmd_common.h"
#include "filebuffer.h"
#include "strbuilder.h"
#include "alloc.h"
#include "t.h"

#include "../tengine/vm.h"
#include "data/net.h"
#include "data/sample_zip.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

static const char* empty_dirs[] = {NULL};

int TEST(use_struct_of_another_file)(void)
{
    fb_undo_all(elf_fb->fb);

    const char* prog = "net#eth_header a;";
    // clang-format off
    const char* expected = 
        "b+00000000           a: \n"
        "b+00000000                            dst: 7f454c460101\n"
        "b+00000006                            src: 010000000000\n"
        "b+0000000c                           type: ETH_TYPE_INVALID_ZERO\n";
    // clang-format on

    int        r  = TEST_FAILED;
    TEngineVM* vm = tengine_vm_create(empty_dirs);
    if (vm == NULL) {
        return 0;
    }
    if (tengine_vm_add_template(vm, "net", "./templates/net.bhe") != 0) {
        print_err_sb();
        goto end;
    }
    if (tengine_vm_process_string(vm, elf_fb->fb, prog) != 0) {
        goto end;
    }

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);
end:
    tengine_vm_destroy(vm);
    return r;
}

int TEST(use_complex_struct_of_another_file)(void)
{
    fb_undo_all(elf_fb->fb);

    const char* prog = "elf#Elf_Ehdr h;";
    // clang-format off
    const char* expected = 
        "b+00000000         h: \n"
        "b+00000000                   e_ident: \n"
        "b+00000000                        ei_mag: 7f454c46\n"
        "b+00000004                      ei_class: ELFCLASS32\n"
        "b+00000005                       ei_data: ELFDATA2LSB\n"
        "b+00000006                    ei_version: 01\n"
        "b+00000007                      ei_osabi: ELFOSABI_NONE\n"
        "b+00000008                 ei_abiversion: 00\n"
        "b+00000009                        ei_pad: 000000000000\n"
        "b+0000000f                     ei_nident: 00\n"
        "b+00000010                    e_type: ET_EXEC\n"
        "b+00000012                 e_machine: EM_386\n"
        "b+00000014                 e_version: 00000001\n"
        "b+00000018                   e_entry: 08048074\n"
        "b+0000001c                   e_phoff: 00000034\n"
        "b+00000020                   e_shoff: 000000a4\n"
        "b+00000024                   e_flags: 00000000\n"
        "b+00000028                  e_ehsize: 0034\n"
        "b+0000002a               e_phentsize: 0020\n"
        "b+0000002c                   e_phnum: 0002\n"
        "b+0000002e               e_shentsize: 0028\n"
        "b+00000030                   e_shnum: 0004\n"
        "b+00000032                e_shstrndx: 0003\n";
    // clang-format on

    int        r  = TEST_FAILED;
    TEngineVM* vm = tengine_vm_create(empty_dirs);
    if (vm == NULL)
        return 0;
    if (tengine_vm_add_template(vm, "elf", "./templates/elf.bhe") != 0)
        goto end;

    if (tengine_vm_process_string(vm, elf_fb->fb, prog) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    tengine_vm_destroy(vm);
    return r;
}

int TEST(use_enum_of_another_file)(void)
{
    fb_undo_all(elf_fb->fb);

    const char* prog = "fwd(0x12); elf#ElfMachine m;";
    // clang-format off
    const char* expected =
        "b+00000012           m: EM_386\n";
    // clang-format on

    int        r  = TEST_FAILED;
    TEngineVM* vm = tengine_vm_create(empty_dirs);
    if (vm == NULL)
        return 0;
    if (tengine_vm_add_template(vm, "elf", "./templates/elf.bhe") != 0)
        goto end;

    if (tengine_vm_process_string(vm, elf_fb->fb, prog) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    tengine_vm_destroy(vm);
    return r;
}

int TEST(template_tcp)(void)
{
    // clang-format off
    const char* prog = "net#eth_header eth; net#ipv4_header ip; net#tcp_header tcp;";
    const char* expected = 
        "b+00000000          eth: \n"
        "b+00000000                            dst: d4925e9eae53\n"
        "b+00000006                            src: e0d4e86835e9\n"
        "b+0000000c                           type: ETH_TYPE_IP\n"
        "b+0000000e           ip: \n"
        "b+0000000e                    version_ihl: 45\n"
        "b+0000000f                type_of_service: 00\n"
        "b+00000010                   total_length: 0028\n"
        "b+00000012                 identification: 1fd8\n"
        "b+00000014                 flags_fragment: 4000\n"
        "b+00000016                   time_to_live: 80\n"
        "b+00000017                       protocol: IPPROTO_TCP\n"
        "b+00000018                header_checksum: 0000\n"
        "b+0000001a                 source_address: c0a80155\n"
        "b+0000001e                   dest_address: a04f680a\n"
        "b+00000022          tcp: \n"
        "b+00000022                    source_port: ee8d\n"
        "b+00000024                      dest_port: 01bb\n"
        "b+00000026                   sequence_num: 1fc51680\n"
        "b+0000002a                        ack_num: 1bd3a788\n"
        "b+0000002e           data_offset_reserved: 50\n"
        "b+0000002f                          flags: TCP_FLAG_ACK\n"
        "b+00000030                    window_size: 00fa\n"
        "b+00000032                       checksum: ca71\n"
        "b+00000034                 urgent_pointer: 0000\n";
    // clang-format on

    int              r   = TEST_SUCCEEDED;
    DummyFilebuffer* tfb = NULL;
    TEngineVM*       vm  = tengine_vm_create(empty_dirs);
    ASSERT(vm != NULL);
    ASSERT(tengine_vm_add_template(vm, "net", "./templates/net.bhe") == 0);

    tfb = dummyfilebuffer_create(tcp_pkt, sizeof(tcp_pkt));
    ASSERT(tfb != NULL);
    ASSERT(tengine_vm_process_string(vm, tfb->fb, prog) == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    if (tfb)
        dummyfilebuffer_destroy(tfb);
    tengine_vm_destroy(vm);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}

int TEST(zip_list_files)(void)
{
    // clang-format off
    const char* expected = 
        "file.txt [ 5 bytes ] \n"
        "folder/ [ 0 bytes ] \n"
        "folder/subfolder/ [ 0 bytes ] \n"
        "folder/subfolder/file_in_subfolder.txt [ 8 bytes ] \n"
        "folder/file_in_folder.txt [ 12 bytes ] \n";
    // clang-format on

    int r = TEST_SUCCEEDED;

    DummyFilebuffer* tfb =
        dummyfilebuffer_create(sample_zip, sizeof(sample_zip));
    TEngineVM* vm = tengine_vm_create(empty_dirs);

    ASSERT(tfb != NULL);
    ASSERT(vm != NULL);
    ASSERT(tengine_vm_add_template(vm, "zip", "./templates/zip.bhe") == 0);
    ASSERT(tengine_vm_process_bhe_proc(vm, tfb->fb, "zip", "list_files") == 0);

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    tengine_vm_destroy(vm);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
}
