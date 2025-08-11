#include "cmd_export.h"
#include "cmd.h"

#include <util/byte_to_num.h>
#include <display.h>
#include <alloc.h>
#include <log.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

#define HINT_STR " <ofile> [<size>]"

static void exportcmd_dispose(void* obj) { return; }

static void exportcmd_help(void* obj)
{
    display_printf(
        "export: write <size> bytes of the file starting from current "
        "offset to <ofile>\n"
        "\n"
        "  ex" HINT_STR "\n"
        "\n"
        "  ofile: output file\n"
        "  size:  number of bytes to export (if omitted, all the remaining bytes)\n");
}

static int exportcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    if (pc->args.size != 1 && pc->args.size != 2)
        return COMMAND_INVALID_ARG;
    if (pc->cmd_modifiers.size != 0)
        return COMMAND_UNSUPPORTED_MOD;

    u64_t       size     = fb->size - fb->off;
    const char* ofile    = (const char*)pc->args.head->data;
    if (pc->args.size == 2) {
        const char* size_str = (const char*)pc->args.head->next->data;
        if (!str_to_uint64(size_str, &size))
            return COMMAND_INVALID_ARG;
    }

    if (size == 0)
        return COMMAND_INVALID_ARG;

    FILE* f = fopen(ofile, "w");
    if (f == NULL)
        return COMMAND_INVALID_ARG;

    while (size != 0) {
        u64_t       chunk_size = min(size, fb_block_size);
        const u8_t* data       = fb_read(fb, chunk_size);
        if (data == NULL) {
            fclose(f);
            return COMMAND_INTERNAL_ERROR;
        }

        if (fwrite(data, 1, chunk_size, f) != chunk_size) {
            fclose(f);
            return COMMAND_INTERNAL_ERROR;
        }

        size -= chunk_size;
    }

    fclose(f);
    return COMMAND_OK;
}

Cmd* exportcmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "export";
    cmd->alias = "ex";
    cmd->hint  = HINT_STR;

    cmd->dispose = exportcmd_dispose;
    cmd->help    = exportcmd_help;
    cmd->exec    = exportcmd_exec;

    return cmd;
}
