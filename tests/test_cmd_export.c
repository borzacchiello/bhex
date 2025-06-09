#include "elf_not_kitty.h"
#include "t_cmd_common.h"
#include "t.h"

#include <string.h>
#include <unistd.h>
#include <alloc.h>
#include <defs.h>

#ifndef TEST
#define TEST(name) test_##name
#endif

static int read_and_unlink_file(const char* path, u8_t** o_data, u64_t* o_size)
{
    int r = 1;

    FILE* f = fopen(path, "rb");
    if (f == NULL)
        goto end;

    fseek(f, 0, SEEK_END);
    long s = ftell(f);
    rewind(f);
    if (s < 0)
        goto end;

    *o_size = s;
    *o_data = bhex_calloc(s);
    if (fread(*o_data, 1, s, f) != (unsigned long)s)
        goto end;
    r = 0;

end:
    if (f)
        fclose(f);
    unlink(path);
    return r;
}

int TEST(small_chunk)(void)
{
    int   r           = TEST_FAILED;
    u8_t* out_content = NULL;
    u64_t out_size    = 0;

    if (exec_commands("s 0; ex /tmp/out.bin 4") != 0)
        goto end;

    if (read_and_unlink_file("/tmp/out.bin", &out_content, &out_size) != 0)
        goto end;

    if (out_size != 4)
        goto end;

    if (memcmp(out_content,
               "\x7f"
               "ELF",
               4) == 0)
        r = TEST_SUCCEEDED;

end:
    if (out_content)
        bhex_free(out_content);
    return r;
}

int TEST(big_chunk)(void)
{
    int   r           = TEST_FAILED;
    u8_t* out_content = NULL;
    u64_t out_size    = 0;

    if (exec_commands("s 0; ex /tmp/out.bin 4096") != 0)
        goto end;

    if (read_and_unlink_file("/tmp/out.bin", &out_content, &out_size) != 0)
        goto end;

    if (out_size != sizeof(elf_not_kitty))
        goto end;

    if (memcmp(out_content, elf_not_kitty, sizeof(elf_not_kitty)) == 0)
        r = TEST_SUCCEEDED;

end:
    if (out_content)
        bhex_free(out_content);
    return r;
}

int TEST(not_zero_off)(void)
{
    int   r           = TEST_FAILED;
    u8_t* out_content = NULL;
    u64_t out_size    = 0;

    if (exec_commands("s 1; ex /tmp/out.bin 3; s 0") != 0)
        goto end;

    if (read_and_unlink_file("/tmp/out.bin", &out_content, &out_size) != 0)
        goto end;

    if (out_size != 3)
        goto end;

    if (memcmp(out_content, "ELF", 3) == 0)
        r = TEST_SUCCEEDED;

end:
    if (out_content)
        bhex_free(out_content);
    return r;
}
