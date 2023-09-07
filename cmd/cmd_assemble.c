#ifndef DISABLE_KEYSTONE

#include <keystone/keystone.h>
#include <string.h>

#include "cmd.h"
#include "../alloc.h"
#include "../log.h"

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
    printf("\nassemble: assemble code and write it at current offset\n"
           "\n"
           "  as[/l/i/s] <arch> \"<code>\"\n"
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
        warning("unable to assemble with given arch, maybe it is not "
                "included in your keystone version");
        return 0;
    }

    u8_t*  encode;
    size_t size;
    size_t count;
    if (ks_asm(ks, code_str, 0, &encode, &size, &count) != KS_ERR_OK) {
        warning("ks_asm() failed & count = %lu, error = %u\n", count,
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
    if (pc->cmd_modifiers.size == 1 &&
        strcmp((char*)pc->cmd_modifiers.head->data, "l") == 0) {
        if (pc->args.size != 0)
            return COMMAND_INVALID_MOD;

        // list the supported architectures
        printf("\nSupported architectures:\n");
        size_t i;
        for (i = 0; i < sizeof(map_arch_names) / sizeof(void*); ++i) {
            printf("    %s\n", map_arch_names[i]);
        }
        printf("\n");
        return COMMAND_OK;
    }

    int     overwrite = 1, seek_to_end = 0;
    LLNode* curr = pc->cmd_modifiers.head;
    while (curr) {
        if (strcmp((char*)curr->data, "i") == 0) {
            if (!overwrite)
                return COMMAND_INVALID_MOD;
            overwrite = 0;
        } else if (strcmp((char*)curr->data, "s") == 0) {
            if (seek_to_end)
                return COMMAND_INVALID_MOD;
            seek_to_end = 1;
        } else {
            return COMMAND_UNSUPPORTED_MOD;
        }
        curr = curr->next;
    }

    if (pc->args.size != 2)
        return COMMAND_INVALID_ARG;

    int         arch     = 0;
    const char* arch_str = (const char*)pc->args.head->data;
    if (!parse_arch(arch_str, &arch)) {
        return COMMAND_INVALID_ARG;
    }

    const char* code_str = (const char*)pc->args.head->next->data;

    u8_t*  code_bytes;
    size_t code_size;
    if (!do_assemble(arch, code_str, &code_bytes, &code_size))
        return COMMAND_INVALID_ARG;

    if (overwrite) {
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

    if (seek_to_end)
        fb_seek(fb, fb->off + code_size);
    return COMMAND_OK;
}

Cmd* assemblecmd_create()
{
    Cmd* cmd   = bhex_malloc(sizeof(Cmd));
    cmd->obj   = NULL;
    cmd->name  = "assemble";
    cmd->alias = "as";

    cmd->dispose = assemblecmd_dispose;
    cmd->help    = assemblecmd_help;
    cmd->exec    = assemblecmd_exec;
    return cmd;
}

#endif
