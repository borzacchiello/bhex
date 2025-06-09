#include "../tengine/vm.h"
#include "t_cmd_common.h"
#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

static const char* tengine_vm_tests_dirs[] = {"./templates", NULL};

int TEST(const)(void)
{
    const char* prog = "net#eth a";
    // clang-format off
    const char* expected = 
        "b+00000000    a: \n"
        "b+00000000      dst: 7f454c460101\n"
        "b+00000006      src: 010000000000\n"
        "b+0000000c      type: 0000\n";
    // clang-format on

    int        r  = TEST_FAILED;
    TEngineVM* vm = tengine_vm_create(tengine_vm_tests_dirs);
    if (vm == NULL)
        return 0;

    if (tengine_vm_process_string(vm, elf_fb->fb, prog) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);
end:
    tengine_vm_destroy(vm);
    return r;
}
