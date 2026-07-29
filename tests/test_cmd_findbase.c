// Copyright (c) 2022-2026, bageyelet

#include "dummy_filebuffer.h"
#include "t_cmd_common.h"
#include "t.h"

#include <string.h>
#include <util/endian.h>

#include <color.h>

/* The escapes of the colored output, see common/color.c */
#define c_addr "\x1b[0;1;37m"
#define c_off  "\x1b[0m"

#ifndef TEST
#define TEST(name) test_##name
#endif

static DummyFilebuffer* make_findbase_blob(void)
{
    static const u32_t base = 0x08004000u;
    static u8_t        blob[0x400];
    memset(blob, 0, sizeof(blob));

    memcpy(&blob[0x100], "bootloader", strlen("bootloader"));
    memcpy(&blob[0x120], "firmware update", strlen("firmware update"));
    memcpy(&blob[0x150], "diagnostic data", strlen("diagnostic data"));
    memcpy(&blob[0x180], "calibration table", strlen("calibration table"));

    const u32_t ptrs[] = {
        base + 0x100, base + 0x120, base + 0x150, base + 0x180, base + 0x100,
        base + 0x120, base + 0x150, base + 0x180, base + 0x100, base + 0x120,
    };
    for (size_t i = 0; i < sizeof(ptrs) / sizeof(ptrs[0]); ++i)
        write_at_le32(blob, ptrs[i], 0x20 + i * sizeof(u32_t));

    write_at_le32(blob, base + 0x100, 0x80);
    write_at_le32(blob, base + 0x120, 0x84);
    write_at_le32(blob, base + 0x150, 0x88);
    write_at_le32(blob, base + 0x180, 0x8C);
    write_at_le32(blob, base + 0x20, 0xC0);

    write_at_le32(blob, 0x12345678u, 0x200);
    write_at_le32(blob, 0xDEADBEEFu, 0x204);
    write_at_le32(blob, 0x00000001u, 0x208);
    write_at_le32(blob, 0xFFFFFFFFu, 0x20C);

    return dummyfilebuffer_create(blob, sizeof(blob));
}

int TEST(auto_detect_le_32)(void)
{
    const char* expected = "32-bit architecture selected.\n"
                           "Endianness is LE\n"
                           "4 strings indexed\n"
                           "Found 1 base addresses to test\n"
                           "Base address found: 0x08004000.\n";

    DummyFilebuffer* tfb = make_findbase_blob();

    int r = TEST_FAILED;
    if (exec_commands_on("findbase", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(colors)(void)
{
    const char* expected =
        "32-bit architecture selected.\n"
        "Endianness is LE\n"
        "4 strings indexed\n"
        "Found 1 base addresses to test\n"
        "Base address found: " c_addr "0x08004000" c_off ".\n";

    DummyFilebuffer* tfb = make_findbase_blob();

    // the colors are off by default in the tests, as they are whenever the
    // output is not a terminal
    colors_set_enabled(1);

    int r = TEST_FAILED;
    if (exec_commands_on("findbase", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    colors_set_enabled(0);
    dummyfilebuffer_destroy(tfb);
    return r;
}
