#include "../tengine/vm.h"
#include "alloc.h"
#include "strbuilder.h"
#include "t_cmd_common.h"
#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

static const char* empty_dirs[] = {NULL};

int TEST(use_struct_of_another_file)(void)
{
    const char* prog = "net#eth a;";
    // clang-format off
    const char* expected = 
        "b+00000000    a: \n"
        "b+00000000       dst: 7f454c460101\n"
        "b+00000006       src: 010000000000\n"
        "b+0000000c      type: 0000\n";
    // clang-format on

    int        r  = TEST_FAILED;
    TEngineVM* vm = tengine_vm_create(empty_dirs);
    if (vm == NULL) {
        return 0;
    }
    if (tengine_vm_add_template(vm, "net", "./templates/net.bhe") != 0) {
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
