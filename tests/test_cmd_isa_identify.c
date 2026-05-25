// Copyright (c) 2022-2026, bageyelet

#include "dummy_filebuffer.h"
#include "t_cmd_common.h"
#include "t.h"
#include "data/asm_snippets.h"

#include <stdio.h>
#include <string.h>

#ifndef TEST
#define TEST(name) test_##name
#endif

#define ISA_TOPK 3

typedef struct {
    const char* name;
    const u8_t* data;
    size_t      size;
    const char* expected[ISA_TOPK];
} IsaBaseline;

static int extract_value(const char* out, const char* prefix, char* value,
                         size_t value_size)
{
    const char* begin = strstr(out, prefix);
    const char* end;
    size_t      len;

    if (!begin || value_size == 0)
        return 0;

    begin += strlen(prefix);
    end = strchr(begin, '\n');
    if (!end)
        end = begin + strlen(begin);

    len = (size_t)(end - begin);
    if (len >= value_size)
        len = value_size - 1;

    memcpy(value, begin, len);
    value[len] = '\0';
    return 1;
}

static int extract_arch_for_rank(const char* out, int rank, char* value,
                                 size_t value_size)
{
    char        prefix[32];
    char        line[256];
    const char* comma;
    size_t      len;

    if (snprintf(prefix, sizeof(prefix), "  top %d: ", rank) < 0)
        return 0;
    if (!extract_value(out, prefix, line, sizeof(line)))
        return 0;

    comma = strchr(line, ',');
    if (!comma || value_size == 0)
        return 0;

    len = (size_t)(comma - line);
    if (len >= value_size)
        len = value_size - 1;
    memcpy(value, line, len);
    value[len] = '\0';
    return 1;
}

static int run_isa_identify_command(const char* command_name, const u8_t* data,
                                    size_t size, int with_size,
                                    char top[ISA_TOPK][64])
{
    char             cmd[64];
    DummyFilebuffer* tfb = dummyfilebuffer_create(data, size);
    int              ok  = 0;
    int              i;

    if (with_size) {
        if (snprintf(cmd, sizeof(cmd), "%s %zu", command_name, size) < 0)
            goto end;
    } else {
        if (snprintf(cmd, sizeof(cmd), "%s", command_name) < 0)
            goto end;
    }

    if (exec_commands_on(cmd, tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    for (i = 0; i < ISA_TOPK; ++i) {
        if (!extract_arch_for_rank(out, i + 1, top[i], sizeof(top[i]))) {
            bhex_free(out);
            goto end;
        }
    }

    bhex_free(out);
    ok = 1;

end:
    dummyfilebuffer_destroy(tfb);
    return ok;
}

static int check_command_output(const char* command_name)
{
    int  r = TEST_FAILED;
    char top[ISA_TOPK][64];

    if (!run_isa_identify_command(command_name, elf_not_kitty,
                                  sizeof(elf_not_kitty), 1, top))
        goto end;

    if (strcmp(top[0], "unavailable") == 0 &&
        strcmp(top[1], "unavailable") == 0 &&
        strcmp(top[2], "unavailable") == 0)
        goto end;

    r = TEST_SUCCEEDED;

end:
    return r;
}

int TEST(no_size_defaults_to_whole_file)(void)
{
    char top[ISA_TOPK][64];

    if (!run_isa_identify_command("ii", elf_not_kitty, sizeof(elf_not_kitty), 0,
                                  top))
        return TEST_FAILED;

    return (strcmp(top[0], "unavailable") == 0 &&
            strcmp(top[1], "unavailable") == 0 &&
            strcmp(top[2], "unavailable") == 0)
               ? TEST_FAILED
               : TEST_SUCCEEDED;
}

int TEST(invalid_too_many_args)(void) { return exec_commands("ii 1 2") != 0; }

int TEST(invalid_size)(void)
{
    return exec_commands("ii nope") != 0 && exec_commands("ii 0") != 0;
}

int TEST(alias_produces_output)(void) { return check_command_output("ii"); }

int TEST(full_name_produces_output)(void)
{
    return check_command_output("isa_identify");
}

int TEST(help_output)(void)
{
    int r = TEST_FAILED;
    if (exec_commands("ii?") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strstr(out, "isa_identify: identify the ISA") != NULL &&
        strstr(out, "if omitted, use the whole file") != NULL;
    bhex_free(out);

end:
    return r;
}

int TEST(streaming_across_chunks)(void)
{
    enum { REPEAT = 6 };
    u8_t   buffer[sizeof(snippet_x64) * REPEAT];
    char   top[ISA_TOPK][64];
    size_t i;

    for (i = 0; i < REPEAT; ++i) {
        memcpy(buffer + i * sizeof(snippet_x64), snippet_x64,
               sizeof(snippet_x64));
    }

    if (!run_isa_identify_command("ii", buffer, sizeof(buffer), 1, top))
        return TEST_FAILED;

    return strcmp(top[0], "x64") == 0 ? TEST_SUCCEEDED : TEST_FAILED;
}

int TEST(dataset_baseline)(void)
{
    static const IsaBaseline baselines[] = {
        {"x64", snippet_x64, sizeof(snippet_x64), {"x64", "x86", "x86"}},
        {"x86", snippet_x86, sizeof(snippet_x86), {"x86", "x86", "s390x"}},
        {"i8086",
         snippet_i8086,
         sizeof(snippet_i8086),
         {"x86", "x86", "arm32"}},
        {"arm32",
         snippet_arm32,
         sizeof(snippet_arm32),
         {"arm32", "arm32", "sparc"}},
        {"arm32_thumb",
         snippet_arm32_thumb,
         sizeof(snippet_arm32_thumb),
         {"ia64", "x86", "sh4"}},
        {"aarch64",
         snippet_aarch64,
         sizeof(snippet_aarch64),
         {"aarch64", "arm32", "hppa"}},
        {"mips32",
         snippet_mips32,
         sizeof(snippet_mips32),
         {"mips32", "hppa", "x86"}},
        {"mips64",
         snippet_mips64,
         sizeof(snippet_mips64),
         {"mipsel64", "sparc", "sparc64"}},
        {"mipsel32",
         snippet_mipsel32,
         sizeof(snippet_mipsel32),
         {"mipsel32", "mipsel64", "sparc"}},
        {"mipsel64",
         snippet_mipsel64,
         sizeof(snippet_mipsel64),
         {"mipsel64", "ia64", "sparc64"}},
        {"ppc32",
         snippet_ppc32,
         sizeof(snippet_ppc32),
         {"ppc64", "ppc32", "ppc32"}},
        {"ppc64",
         snippet_ppc64,
         sizeof(snippet_ppc64),
         {"ppc64", "ppc32", "ppc32"}},
        {"ppcle32",
         snippet_ppcle32,
         sizeof(snippet_ppcle32),
         {"ppcle64", "aarch64", "alpha"}},
        {"ppcle64",
         snippet_ppcle64,
         sizeof(snippet_ppcle64),
         {"ppcle64", "sparc64", "aarch64"}},
        {"m68k",
         snippet_m68k,
         sizeof(snippet_m68k),
         {"m68k", "sparc64", "sparc"}},
    };

    size_t i;

    for (i = 0; i < sizeof(baselines) / sizeof(baselines[0]); ++i) {
        char top[ISA_TOPK][64];
        int  rank;

        if (!run_isa_identify_command("ii", baselines[i].data,
                                      baselines[i].size, 1, top)) {
            printf("[!] ii failed on sample '%s'\n", baselines[i].name);
            return TEST_FAILED;
        }

        for (rank = 0; rank < ISA_TOPK; ++rank) {
            if (strcmp(top[rank], baselines[i].expected[rank]) != 0) {
                printf("[!] sample '%s' rank %d: expected '%s', got '%s'\n",
                       baselines[i].name, rank + 1, baselines[i].expected[rank],
                       top[rank]);
                return TEST_FAILED;
            }
        }
    }

    return TEST_SUCCEEDED;
}
