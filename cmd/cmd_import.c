#include "cmd_arg_handler.h"
#include "cmd_import.h"
#include "cmd.h"
#include "defs.h"
#include "filebuffer.h"

#include <sys/_types/_seek_set.h>
#include <util/byte_to_num.h>
#include <display.h>
#include <alloc.h>
#include <log.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

#define WRITE_TYPE_OVERWRITE 0
#define WRITE_TYPE_INSERT    1

#define HINT_STR "[/{ovw,i}] <file> [<size> <offset>]"

static void importcmd_dispose(void* obj) { return; }

static void importcmd_help(void* obj)
{
    display_printf(
        "\nimport: import the content of <file> at current offset\n"
        "\n"
        "  im" HINT_STR "\n"
        "     i:   insert in current file (default)\n"
        "     ovw: overwrite current file\n"
        "\n"
        "  file:   input file\n"
        "  size:   number of bytes to import (if omitted or zero, import "
        "the whole file)\n"
        "  offset: starting offset of the imported file (if "
        "omitted, import from offset 0)\n\n");
}

static int read_file(const char* fname, u32_t off, u32_t size, u8_t** o_data,
                     u32_t* o_size)
{
    int r = 1;

    FILE* f = fopen(fname, "rb");
    if (f == NULL) {
        warning("invalid filename %s", fname);
        goto end;
    }

    if (fseek(f, 0, SEEK_END) != 0)
        goto end;
    long s = ftell(f);
    rewind(f);
    if (s < 0)
        goto end;

    u64_t fsize = s;

    if (off >= fsize) {
        warning("offset (%u) is bigger than filesize (%llu)", off, fsize);
        goto end;
    }
    if (size == 0)
        size = fsize - off;
    if (fsize - off < size) {
        warning("size (%u) is bigger than remaining bytes after offset (%llu)",
                size, fsize - off);
        goto end;
    }

    if (fseek(f, off, SEEK_SET) != 0)
        goto end;

    *o_size = size;
    *o_data = bhex_calloc(size);
    if (fread(*o_data, 1, size, f) != (unsigned long)size)
        goto end;
    r = 0;

end:
    if (f)
        fclose(f);
    return r;
}

static int importcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    int write_type = WRITE_TYPE_INSERT;
    if (handle_mods(pc, "ovw,i", &write_type) != 0)
        return COMMAND_INVALID_ARG;

    char* infile     = NULL;
    char* size_str   = NULL;
    char* offset_str = NULL;
    if (handle_args(pc, 3, 1, &infile, &size_str, &offset_str) != 0)
        return COMMAND_INVALID_ARG;

    u32_t size   = 0;
    u32_t offset = 0;
    if (size_str) {
        if (!str_to_uint32(size_str, &size)) {
            warning("invalid number '%s'", size_str);
            return COMMAND_INVALID_ARG;
        }
    }
    if (offset_str) {
        if (!str_to_uint32(offset_str, &offset)) {
            warning("invalid number '%s'", offset_str);
            return COMMAND_INVALID_ARG;
        }
    }

    u8_t* data      = NULL;
    u32_t data_size = 0;
    if (read_file(infile, offset, size, &data, &data_size) != 0)
        return COMMAND_INVALID_ARG;

    int result = COMMAND_OK;
    if (write_type == WRITE_TYPE_INSERT) {
        if (!fb_insert(fb, data, data_size))
            result = COMMAND_FILE_WRITE_ERROR;
    } else if (write_type == WRITE_TYPE_OVERWRITE) {
        if (!fb_write(fb, data, data_size))
            result = COMMAND_FILE_WRITE_ERROR;
    } else
        panic("invalid write_type");
    return result;
}

Cmd* importcmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "import";
    cmd->alias = "im";
    cmd->hint  = HINT_STR;

    cmd->dispose = importcmd_dispose;
    cmd->help    = importcmd_help;
    cmd->exec    = importcmd_exec;

    return cmd;
}
