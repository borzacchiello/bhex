#include "cmd_diff.h"
#include "cmd_arg_handler.h"

#include <util/print.h>
#include <display.h>
#include <string.h>
#include <stdio.h>
#include <alloc.h>
#include <defs.h>

#define HINT_STR "[/p/w] <file>"

#define min(x, y)       ((x) < (y) ? (x) : (y))
#define highlight_begin display_printf("\x1b[31;49;1m")
#define highlight_end   display_printf("\x1b[0m")

static void diffcmd_dispose(void* obj) {}

static void diffcmd_help(void* obj)
{
    display_printf("\ndiff: prints the differences with another file\n"
                   "\n"
                   "  df" HINT_STR "\n"
                   "     p:  print different bytes\n"
                   "     w:  wide print (rows are 16 bytes)\n"
                   "\n"
                   "  file: path to the file to compare\n\n");
}

static void print_diffs(FileBuffer* self, FileBuffer* other, int print_diffs,
                        int wide)
{
    fb_seek(self, 0);
    fb_seek(other, 0);

    if (print_diffs) {
        if (!wide) {
            display_printf("\n"
                           "            "
                           "00 01 02 03 04 05 06 07"
                           "  "
                           "00 01 02 03 04 05 06 07\n"
                           "            "
                           "-----------------------"
                           "  "
                           "-----------------------\n");
        } else {
            display_printf("\n"
                           "            "
                           "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
                           "  "
                           "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
                           "            "
                           "-----------------------------------------------"
                           "  "
                           "-----------------------------------------------\n");
        }
    }

    u64_t     ndiffs      = 0;
    u64_t     addr        = 0;
    const int linelen     = wide ? 16 : 8;
    int       was_skipped = 0;
    while (1) {
        if (addr >= self->size || addr >= other->size)
            break;

        u64_t size =
            min(min(fb_block_size, self->size - addr), other->size - addr);
        const u8_t* self_block  = fb_read(self, size);
        const u8_t* other_block = fb_read(other, size);

        u64_t off = 0;
        while (1) {
            if (off >= size)
                break;
            u64_t nbytes = min(linelen, size - off);
            if (memcmp(&self_block[off], &other_block[off], nbytes) == 0) {
                was_skipped = 1;
                off += nbytes;
                continue;
            }

            for (u64_t i = 0; i < nbytes; ++i)
                if (self_block[off + i] != other_block[off + i])
                    ndiffs++;

            if (print_diffs) {
                if (was_skipped)
                    display_printf("     *\n");
                display_printf("%010llx  ", (u64_t)(addr + off));
                for (u64_t i = 0; i < linelen; ++i) {
                    if (i >= nbytes) {
                        display_printf("   ");
                        continue;
                    }
                    if (self_block[off + i] != other_block[off + i])
                        highlight_begin;
                    display_printf("%02X", self_block[off + i]);
                    if (self_block[off + i] != other_block[off + i])
                        highlight_end;
                    display_printf(" ");
                }
                display_printf(" ");
                for (u64_t i = 0; i < nbytes; ++i) {
                    if (self_block[off + i] != other_block[off + i])
                        highlight_begin;
                    display_printf("%02X", other_block[off + i]);
                    if (self_block[off + i] != other_block[off + i])
                        highlight_end;
                    display_printf(" ");
                }
                display_printf("\n");
                was_skipped = 0;
            }
            off += nbytes;
        }
        addr += size;
        fb_seek(self, addr);
        fb_seek(other, addr);
    }
    if (print_diffs) {
        if (was_skipped)
            display_printf("     *\n");
    }

    display_printf("\n");
    if (addr < self->size)
        display_printf("current file is bigger\n");
    if (addr < other->size)
        display_printf("other file is bigger\n");
    if (self->size == other->size)
        display_printf("the files have the same size\n");

    if (ndiffs != 0) {
        display_printf("common size is different [ difference %.03lf%% ]\n\n",
                       (double)ndiffs / (double)min(self->size, other->size) *
                           100);
    } else {
        display_printf("common size is identical\n");
    }
}

static int diffcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    if (pc->args.size != 1)
        return COMMAND_UNSUPPORTED_ARG;

    int print_bytes = -1;
    int wide        = -1;
    if (handle_mods(pc, "p|w", &print_bytes, &wide) != 0)
        return COMMAND_INVALID_MOD;

    print_bytes = print_bytes == 0;
    wide        = wide == 0;

    const char* other    = (const char*)pc->args.head->data;
    FileBuffer* other_fb = filebuffer_create(other, 1);
    if (other_fb == NULL)
        return COMMAND_INVALID_ARG;

    u64_t soff = fb->off;
    print_diffs(fb, other_fb, print_bytes, wide);
    fb_seek(fb, soff);

    filebuffer_destroy(other_fb);
    return COMMAND_OK;
}

Cmd* diffcmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "diff";
    cmd->alias = "df";
    cmd->hint  = HINT_STR;

    cmd->dispose = diffcmd_dispose;
    cmd->help    = diffcmd_help;
    cmd->exec    = diffcmd_exec;

    return cmd;
}
