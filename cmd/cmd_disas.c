#ifndef DISABLE_CAPSTONE

#include "cmd_disas.h"

#include "util/byte_to_num.h"
#include "util/byte_to_str.h"
#include "../alloc.h"
#include "../log.h"

#include <capstone/capstone.h>
#include <string.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

#define DEFAULT_DISAS_OPCODES 8

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
    cs_arch arch;
    cs_mode mode;
} CapstoneArchInfo;

static CapstoneArchInfo map_arch[] = {
    {CS_ARCH_X86, CS_MODE_64},                              // X86_64_ARCH
    {CS_ARCH_X86, CS_MODE_32},                              // X86_ARCH
    {CS_ARCH_X86, CS_MODE_16},                              // X86_16_ARCH
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

static void disascmd_help(void* obj)
{
    printf("\ndisas: disassemble code at current offset\n"
           "\n"
           "  ds[/l] <arch> [<nbytes>]\n"
           "     l:  list supported architectures\n"
           "\n"
           "  arch:   the architecture to use\n"
           "  nbytes: the number of opcodes to disassemble, default value: %d\n"
           "\n",
           DEFAULT_DISAS_OPCODES);
}

static void disascmd_dispose(void* obj) {}

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

static const char* bytes_str(const cs_insn* insn, size_t max_size)
{
    static char disas[16 * 3 + 1];

    if (max_size >= sizeof(disas) || max_size < 3)
        panic("invalid max_size");

    size_t i = 0, off = 0;
    while (off < insn->size) {
        if (i + 3 >= max_size - 2 && off != insn->size - 1) {
            disas[i]     = '.';
            disas[i + 1] = '.';
            disas[i + 2] = '.';
            i += 3;
            break;
        }
        disas[i + 2] = ' ';
        disas[i + 1] = nibble_to_hex_char(insn->bytes[off] & 0xF);
        disas[i]     = nibble_to_hex_char((insn->bytes[off] >> 4) & 0xF);

        off += 1;
        i += 3;
    }
    for (; i < max_size; ++i)
        disas[i] = ' ';
    disas[max_size] = 0;

    return disas;
}

static void do_disas(int arch, u64_t addr, const u8_t* code, size_t code_size,
                     u64_t nopcodes)
{
    csh      handle;
    cs_insn* insn;
    size_t   count;

    if (cs_open(map_arch[arch].arch, map_arch[arch].mode, &handle) !=
        CS_ERR_OK) {
        error("unable to disassemble with given arch, maybe it is not "
              "included in your capstone version");
        return;
    }

    count = cs_disasm(handle, code, code_size - 1, addr, 0, &insn);
    if (count > 0) {
        puts("");
        size_t j;
        for (j = 0; j < min(count, nopcodes); j++) {
            printf("0x%08llx: %s %s\t\t%s\n", (u64_t)insn[j].address,
                   bytes_str(&insn[j], 21), insn[j].mnemonic, insn[j].op_str);
        }
        puts("");
        cs_free(insn, count);
    } else
        printf("invalid\n");

    cs_close(&handle);
}

static int disascmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
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

    int         arch     = 0;
    u64_t       nopcodes = 0;
    const u8_t* bytes    = NULL;

    const char* arch_str = (const char*)pc->args.head->data;
    if (!parse_arch(arch_str, &arch)) {
        return COMMAND_INVALID_ARG;
    }

    if (pc->args.size == 2) {
        const char* size_str = (const char*)pc->args.head->next->data;
        if (!str_to_uint64(size_str, &nopcodes))
            return COMMAND_INVALID_ARG;
    } else {
        nopcodes = DEFAULT_DISAS_OPCODES;
    }

    // we are assuming that no opcodes has more than 10 bytes
    u64_t size = min(nopcodes * 10, fb->size - fb->off);
    bytes      = fb_read(fb, size);
    if (!bytes)
        return COMMAND_INVALID_ARG;
    do_disas(arch, fb->off, bytes, size, nopcodes);
    return COMMAND_OK;
}

Cmd* disascmd_create(void)
{
    Cmd* cmd   = bhex_malloc(sizeof(Cmd));
    cmd->obj   = NULL;
    cmd->name  = "disas";
    cmd->alias = "ds";

    cmd->dispose = disascmd_dispose;
    cmd->help    = disascmd_help;
    cmd->exec    = disascmd_exec;
    return cmd;
}

#endif
