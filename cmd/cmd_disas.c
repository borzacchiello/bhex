#include "cmd_disas.h"

#include "util/byte_to_num.h"
#include "../alloc.h"
#include "../log.h"

#include <capstone/capstone.h>
#include <string.h>
#include <dlfcn.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

#define DEFAULT_DISAS_NBYTES 128

#define X86_64_ARCH      0
#define X86_ARCH         1
#define ARM32_ARCH       2
#define ARM64_ARCH       3
#define ARM32_THUMB_ARCH 4
#define ARM64_THUMB_ARCH 5
#define MIPS32_ARCH      6
#define MIPS64_ARCH      7
#define MIPSEL32_ARCH    8
#define MIPSEL64_ARCH    9

typedef struct {
    void* capstone_handle;

    cs_err (*cs_open)(cs_arch arch, cs_mode mode, csh* handle);
    size_t (*cs_disasm)(csh handle, const uint8_t* code, size_t code_size,
                        uint64_t address, size_t count, cs_insn** insn);
    void (*cs_free)(cs_insn* insn, size_t count);
    cs_err (*cs_close)(csh* handle);
} DisasContext;

typedef struct {
    cs_arch arch;
    cs_mode mode;
} CapstoneArchInfo;

static CapstoneArchInfo map_arch[] = {
    {CS_ARCH_X86, CS_MODE_64},                              // X86_64_ARCH
    {CS_ARCH_X86, CS_MODE_32},                              // X86_ARCH
    {CS_ARCH_ARM, CS_MODE_ARM},                             // ARM32_ARCH
    {CS_ARCH_ARM64, CS_MODE_ARM},                           // ARM64_ARCH
    {CS_ARCH_ARM, CS_MODE_THUMB},                           // ARM32_THUMB_ARCH
    {CS_ARCH_ARM64, CS_MODE_THUMB},                         // ARM64_THUMB_ARCH
    {CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN},    // MIPS32_ARCH
    {CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN},    // MIPS64_ARCH
    {CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN}, // MIPSEL32_ARCH
    {CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN}, // MIPSEL64_ARCH
};

static const char* map_arch_names[] = {
    "x64",         // X86_64_ARCH
    "x86",         // X86_ARCH
    "arm32",       // ARM32_ARCH
    "arm64",       // ARM64_ARCH
    "arm32-thumb", // ARM32_THUMB_ARCH
    "arm64-thumb", // ARM64_THUMB_ARCH
    "mips32",      // MIPS32_ARCH
    "mips64",      // MIPS64_ARCH
    "mipsel32",    // MIPSEL32_ARCH
    "mipsel64",    // MIPSEL64_ARCH
};

static void disascmd_help(void* obj)
{
    printf("\ndisas: disassemble code at current offset\n"
           "\n"
           "  ds[/l] <arch> [<nbytes>]\n"
           "     l:  list supported architectures\n"
           "\n"
           "  arch:   the architecture to use\n"
           "  nbytes: the number of bytes to disassemble, default value: %d\n"
           "\n",
           DEFAULT_DISAS_NBYTES);
}

static void disascmd_dispose(void* obj)
{
    DisasContext* ctx = (DisasContext*)obj;

    if (ctx->capstone_handle)
        dlclose(ctx->capstone_handle);
    free(ctx);
}

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

static void do_disas(DisasContext* ctx, int arch, u64_t addr, const u8_t* code,
                     size_t code_size)
{
    csh      handle;
    cs_insn* insn;
    size_t   count;

    if (ctx->cs_open(map_arch[arch].arch, map_arch[arch].mode, &handle) !=
        CS_ERR_OK) {
        warning("unable to disassemble with given arch, maybe it is not "
                "included in your capstone version");
        return;
    }

    count = ctx->cs_disasm(handle, code, code_size - 1, addr, 0, &insn);
    if (count > 0) {
        size_t j;
        for (j = 0; j < count; j++) {
            printf("0x%llx:\t%s\t\t%s\n", (u64_t)insn[j].address,
                   insn[j].mnemonic, insn[j].op_str);
        }

        ctx->cs_free(insn, count);
    } else
        printf("invalid\n");

    ctx->cs_close(&handle);
}

static int disascmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    DisasContext* ctx = (DisasContext*)obj;
    if (!ctx->capstone_handle) {
        warning("unable to find libcapstone, you cannot use the command");
        return COMMAND_OK;
    }

    if (pc->cmd_modifiers.size > 1)
        return COMMAND_UNSUPPORTED_MOD;

    if (pc->cmd_modifiers.size == 1 &&
        strcmp((char*)pc->cmd_modifiers.head->data, "l") == 0) {
        if (pc->args.size != 0)
            return COMMAND_INVALID_ARG;

        // list the supported architectures
        printf("\nSupported architectures:\n");
        size_t i;
        for (i = 0; i < sizeof(map_arch_names) / sizeof(void*); ++i) {
            printf("    %s\n", map_arch_names[i]);
        }
        printf("\n");
        return COMMAND_OK;
    }

    if (pc->args.size != 1 && pc->args.size != 2)
        return COMMAND_INVALID_ARG;

    int         arch  = 0;
    u64_t       size  = 0;
    const u8_t* bytes = NULL;

    const char* arch_str = (const char*)pc->args.head->data;
    if (!parse_arch(arch_str, &arch)) {
        return COMMAND_INVALID_ARG;
    }

    if (pc->args.size == 2) {
        const char* size_str = (const char*)pc->args.head->next->data;
        if (!str_to_uint64(size_str, &size))
            return COMMAND_INVALID_ARG;
    } else {
        size = min(DEFAULT_DISAS_NBYTES, fb->size - fb->off);
    }

    bytes = fb_read(fb, size);
    if (!bytes)
        return COMMAND_INVALID_ARG;
    do_disas(ctx, arch, fb->off, bytes, size);
    return COMMAND_OK;
}

Cmd* disascmd_create()
{
    Cmd*          cmd = bhex_malloc(sizeof(Cmd));
    DisasContext* ctx = bhex_calloc(sizeof(DisasContext));

    cmd->obj   = ctx;
    cmd->name  = "disas";
    cmd->alias = "ds";

    cmd->dispose = disascmd_dispose;
    cmd->help    = disascmd_help;
    cmd->exec    = disascmd_exec;

    void* capstone_handle = dlopen("libcapstone.so", RTLD_NOW);
    if (!capstone_handle) {
        // capstone not found, "disas" command won't work
        return cmd;
    }
    ctx->capstone_handle = capstone_handle;
    ctx->cs_open         = dlsym(capstone_handle, "cs_open");
    ctx->cs_close        = dlsym(capstone_handle, "cs_close");
    ctx->cs_disasm       = dlsym(capstone_handle, "cs_disasm");
    ctx->cs_free         = dlsym(capstone_handle, "cs_free");
    return cmd;
}
