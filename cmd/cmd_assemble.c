#ifndef DISABLE_KEYSTONE

#include "cmd_arg_handler.h"
#include "cmd.h"

#include <keystone/keystone.h>
#include <display.h>
#include <string.h>
#include <alloc.h>
#include <log.h>

#define LIST_SET   0
#define INSERT_SET 0
#define SEEK_SET   0

#define X86_64_ARCH      0
#define X86_ARCH         1
#define X86_16_ARCH      2
#define ARM32_ARCH       3
#define ARM64_ARCH       4
#define ARM32_THUMB_ARCH 5
#define ARM64_THUMB_ARCH 6
#define MIPS32_ARCH      7
#define MIPS64_ARCH      8
#define MIPSEL32_ARCH    9
#define MIPSEL64_ARCH    10

#define HINT_STR "[/l/i/s] <arch> 'instr1; instr2; ...'"

typedef struct {
    ks_arch arch;
    ks_mode mode;
} KeystoneArchInfo;

static KeystoneArchInfo map_arch[] = {
    {KS_ARCH_X86, KS_MODE_64},                              // X86_64_ARCH
    {KS_ARCH_X86, KS_MODE_32},                              // X86_ARCH
    {KS_ARCH_X86, KS_MODE_16},                              // X86_16_ARCH
    {KS_ARCH_ARM, KS_MODE_ARM},                             // ARM32_ARCH
    {KS_ARCH_ARM64, KS_MODE_ARM},                           // ARM64_ARCH
    {KS_ARCH_ARM, KS_MODE_THUMB},                           // ARM32_THUMB_ARCH
    {KS_ARCH_ARM64, KS_MODE_THUMB},                         // ARM64_THUMB_ARCH
    {KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN},    // MIPS32_ARCH
    {KS_ARCH_MIPS, KS_MODE_MIPS64 + KS_MODE_BIG_ENDIAN},    // MIPS64_ARCH
    {KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_LITTLE_ENDIAN}, // MIPSEL32_ARCH
    {KS_ARCH_MIPS, KS_MODE_MIPS64 + KS_MODE_LITTLE_ENDIAN}, // MIPSEL64_ARCH
};

static const char* map_arch_names[] = {
    "x64",         // X86_64_ARCH
    "x86",         // X86_ARCH
    "i8086",       // X86_16_ARCH
    "arm32",       // ARM32_ARCH
    "arm64",       // ARM64_ARCH
    "arm32-thumb", // ARM32_THUMB_ARCH
    "arm64-thumb", // ARM64_THUMB_ARCH
    "mips32",      // MIPS32_ARCH
    "mips64",      // MIPS64_ARCH
    "mipsel32",    // MIPSEL32_ARCH
    "mipsel64",    // MIPSEL64_ARCH
};

static void assemblecmd_help(void* obj)
{
    display_printf(
        "\nassemble: assemble code and write it at current offset\n"
        "\n"
        "  as" HINT_STR "\n"
        "     l:  list supported architectures\n"
        "     i:  insert instead of overwrite\n"
        "     s:  seek to the end of the write\n"
        "\n"
        "  arch: the architecture to use\n"
        "  code: assembly code string (e.g., \"inc eax; inc ecx; ret\")\n"
        "\n");
}

static void assemblecmd_dispose(void* obj) {}

static int parse_arch(const char* a, int* out_arch)
{
    size_t i;
    for (i = 0; i < sizeof(map_arch_names) / sizeof(void*); ++i) {
        if (strcmp(map_arch_names[i], a) == 0) {
            *out_arch = i;
            return 1;
        }
    }
    return 0;
}

static int do_assemble(int arch, const char* code_str, u8_t** code,
                       size_t* code_size)
{
    ks_engine* ks;
    ks_err     err;
    err = ks_open(map_arch[arch].arch, map_arch[arch].mode, &ks);
    if (err != KS_ERR_OK) {
        error("unable to assemble with given arch, maybe it is not "
              "included in your keystone version");
        return 0;
    }

    u8_t*  encode;
    size_t size;
    size_t count;
    if (ks_asm(ks, code_str, 0, &encode, &size, &count) != KS_ERR_OK) {
        error("ks_asm() failed & count = %lu, error = %u\n", count,
              ks_errno(ks));
        return 0;
    }

    *code_size = size;
    *code      = bhex_malloc(*code_size);
    memcpy(*code, encode, size);

    ks_free(encode);
    ks_close(ks);
    return 1;
}

static int assemblecmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    int insert      = -1;
    int seek_to_end = -1;
    int list        = -1;
    if (handle_mods(pc, "l|i|s", &list, &insert, &seek_to_end) != 0)
        return COMMAND_INVALID_MOD;

    if (list == LIST_SET) {
        // list the supported architectures
        display_printf("\nSupported architectures:\n");
        size_t i;
        for (i = 0; i < sizeof(map_arch_names) / sizeof(void*); ++i) {
            display_printf("    %s\n", map_arch_names[i]);
        }
        display_printf("\n");
        return COMMAND_OK;
    }

    char* arch_str;
    char* code_str;
    if (handle_args(pc, 2, 2, &arch_str, &code_str) != 0)
        return COMMAND_INVALID_ARG;

    int arch;
    if (!parse_arch(arch_str, &arch))
        return COMMAND_INVALID_ARG;

    u8_t*  code_bytes;
    size_t code_size;
    if (!do_assemble(arch, code_str, &code_bytes, &code_size))
        return COMMAND_INVALID_ARG;

    if (insert != INSERT_SET) {
        if (!fb_write(fb, code_bytes, code_size)) {
            bhex_free(code_bytes);
            return COMMAND_INVALID_ARG;
        }
    } else {
        if (!fb_insert(fb, code_bytes, code_size)) {
            bhex_free(code_bytes);
            return COMMAND_INVALID_ARG;
        }
    }

    if (seek_to_end == SEEK_SET)
        fb_seek(fb, fb->off + code_size);
    return COMMAND_OK;
}

Cmd* assemblecmd_create(void)
{
    Cmd* cmd   = bhex_malloc(sizeof(Cmd));
    cmd->obj   = NULL;
    cmd->name  = "assemble";
    cmd->alias = "as";
    cmd->hint  = HINT_STR;

    cmd->dispose = assemblecmd_dispose;
    cmd->help    = assemblecmd_help;
    cmd->exec    = assemblecmd_exec;
    return cmd;
}

#endif
