// Copyright (c) 2022-2026, bageyelet

#include "cmd_diff.h"
#include "cmd_arg_handler.h"

#include <util/print.h>
#include <display.h>
#include <string.h>
#include <alloc.h>
#include <defs.h>
#include <log.h>

#define HINT_STR "[/p/w/n] <file>"

#define min(x, y) ((x) < (y) ? (x) : (y))

/* SGR sequences marking the differing bytes. With `n` no escape at all is
 * emitted, so that the output can be piped and parsed as plain text. */
#define HL_COLOR "\x1b[31;49;1m"
#define HL_END   "\x1b[0m"

static void diffcmd_dispose(void* obj) {}

static void diffcmd_help(void* obj)
{
    display_printf("diff: prints the differences with another file\n"
                   "\n"
                   "  df" HINT_STR "\n"
                   "     p:  print different bytes\n"
                   "     w:  wide print (rows are 16 bytes)\n"
                   "     n:  do not use colors\n"
                   "\n"
                   "  file: path to the file to compare\n");
}

static void print_diffs(FileBuffer* self, FileBuffer* other, int print_diffs,
                        int wide, int no_colors)
{
    const char* hl_begin = no_colors ? "" : HL_COLOR;
    const char* hl_end   = no_colors ? "" : HL_END;

    fb_seek(self, 0);
    fb_seek(other, 0);

    if (print_diffs) {
        if (!wide) {
            display_printf("            "
                           "00 01 02 03 04 05 06 07"
                           "  "
                           "00 01 02 03 04 05 06 07\n"
                           "            "
                           "-----------------------"
                           "  "
                           "-----------------------\n");
        } else {
            display_printf("            "
                           "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
                           "  "
                           "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
                           "            "
                           "-----------------------------------------------"
                           "  "
                           "-----------------------------------------------\n");
        }
    }

    u64_t       ndiffs      = 0;
    u64_t       addr        = 0;
    const u64_t linelen     = wide ? 16 : 8;
    int         was_skipped = 0;
    while (1) {
        if (addr >= self->size || addr >= other->size)
            break;

        u64_t size =
            min(min(fb_block_size, self->size - addr), other->size - addr);
        const u8_t* self_block  = fb_read(self, size);
        const u8_t* other_block = fb_read(other, size);
        if (self_block == NULL || other_block == NULL) {
            // one of the two files shrank under us
            error("unable to read the files at offset %llu", addr);
            break;
        }

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
                display_printf("%010llx  ",
                               (u64_t)(addr + off) + self->base_addr);
                for (u64_t i = 0; i < linelen; ++i) {
                    if (i >= nbytes) {
                        display_printf("   ");
                        continue;
                    }
                    if (self_block[off + i] != other_block[off + i])
                        display_printf("%s", hl_begin);
                    display_printf("%02X", self_block[off + i]);
                    if (self_block[off + i] != other_block[off + i])
                        display_printf("%s", hl_end);
                    display_printf(" ");
                }
                display_printf(" ");
                for (u64_t i = 0; i < nbytes; ++i) {
                    if (self_block[off + i] != other_block[off + i])
                        display_printf("%s", hl_begin);
                    display_printf("%02X", other_block[off + i]);
                    if (self_block[off + i] != other_block[off + i])
                        display_printf("%s", hl_end);
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
        display_printf("\n");
    }

    if (addr < self->size)
        display_printf("current file is bigger\n");
    if (addr < other->size)
        display_printf("other file is bigger\n");
    if (self->size == other->size)
        display_printf("the files have the same size\n");

    if (ndiffs != 0) {
        display_printf("common size is different [ difference %.03lf%% ]\n",
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
    int no_colors   = -1;
    if (handle_mods(pc, "p|w|n", &print_bytes, &wide, &no_colors) != 0)
        return COMMAND_INVALID_MOD;

    print_bytes = print_bytes == 0;
    wide        = wide == 0;
    no_colors   = no_colors == 0;

    const char* other    = (const char*)pc->args.head->data;
    FileBuffer* other_fb = filebuffer_create(other, 1);
    if (other_fb == NULL)
        return COMMAND_INVALID_ARG;

    u64_t soff = fb->off;
    print_diffs(fb, other_fb, print_bytes, wide, no_colors);
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
