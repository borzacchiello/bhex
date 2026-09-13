// Copyright (c) 2022-2026, bageyelet

#include "cmd_diff.h"
#include "cmd_arg_handler.h"

#include <util/print.h>
#include <display.h>
#include <color.h>
#include <string.h>
#include <alloc.h>
#include <defs.h>
#include <log.h>

#define HINT_STR "[/p/w/n/c] <file>"

#define min(x, y) ((x) < (y) ? (x) : (y))

static void diffcmd_dispose(void* obj) {}

static void diffcmd_help(void* obj)
{
    display_printf(
        "diff: prints the differences with another file\n"
        "\n"
        "  df" HINT_STR "\n"
        "     p:  print different bytes\n"
        "     w:  wide print (rows are 16 bytes)\n"
        "     n:  do not use colors\n"
        "     c:  print the differences as a bhex command script that\n"
        "         turns the current file into the other one, instead of\n"
        "         the report. Replay it with '-s':\n"
        "             bhex -2nc \"df/c new.bin\" old.bin > patch.bhx\n"
        "             bhex -2nwbs old.bin < patch.bhx\n"
        "\n"
        "  file: path to the file to compare\n");
}

static void print_diffs(FileBuffer* self, FileBuffer* other, int print_diffs,
                        int wide, int no_colors)
{
    /* With `n` (or with the colors globally disabled) no escape at all is
     * emitted, so that the output can be piped and parsed as plain text. */
    const char* hl_begin = no_colors ? "" : color_str(COLOR_HIGHLIGHT);
    const char* hl_end   = no_colors ? "" : color_str(COLOR_RESET);

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

// Bytes per emitted write. A run of differing bytes is cut into chunks of
// this size so that no line of the script grows unreasonably long, and so that
// an append stays below the limit of a single insert (fb_block_size)
#define SCRIPT_CHUNK 256

// `data` is supplied by the caller rather than read here: fb_read() hands back
// one shared buffer per FileBuffer, so reading again would invalidate the block
// the caller is still walking
static void print_script_write(const u8_t* data, u64_t off, u64_t size,
                               int insert)
{
    // raw file offsets, since the script is replayed on a file with no base
    display_printf("s 0x%llx\n", off);
    display_printf(insert ? "w/i/x \"" : "w/x \"");
    for (u64_t i = 0; i < size; ++i)
        display_printf(i == 0 ? "%02x" : " %02x", data[i]);
    display_printf("\"\n");
}

// Emits the commands that turn `self` into `other`: an overwrite for every run
// of differing bytes of the common part, then the append or the truncation the
// difference in size calls for, then the commit
static void print_diff_script(FileBuffer* self, FileBuffer* other)
{
    const u64_t common = min(self->size, other->size);

    u64_t addr      = 0;
    u64_t run_begin = 0;
    int   in_run    = 0;
    while (addr < common) {
        u64_t size = min(fb_block_size, common - addr);

        fb_seek(self, addr);
        fb_seek(other, addr);
        const u8_t* self_block  = fb_read(self, size);
        const u8_t* other_block = fb_read(other, size);
        if (self_block == NULL || other_block == NULL) {
            error("unable to read the files at offset %llu", addr);
            return;
        }

        for (u64_t i = 0; i < size; ++i) {
            int differs = self_block[i] != other_block[i];
            if (differs && !in_run) {
                run_begin = addr + i;
                in_run    = 1;
            }
            // a run is flushed when the bytes agree again, when it reaches the
            // chunk size, or at the end of the block, whose buffer is about to
            // be handed back to another read
            if (in_run &&
                (!differs || addr + i + 1 - run_begin >= SCRIPT_CHUNK ||
                 i == size - 1)) {
                u64_t end = differs ? addr + i + 1 : addr + i;
                print_script_write(other_block + (run_begin - addr), run_begin,
                                   end - run_begin, 0);
                in_run = 0;
            }
        }
        addr += size;
    }

    if (other->size > self->size) {
        // the other file is longer: append what it has past the common part
        u64_t off = self->size;
        while (off < other->size) {
            u64_t       size = min(SCRIPT_CHUNK, other->size - off);
            const u8_t* data = fb_read_at(other, off, size);
            if (data == NULL) {
                error("unable to read the other file at offset %llu", off);
                return;
            }
            print_script_write(data, off, size, 1);
            off += size;
        }
    } else if (other->size < self->size) {
        // ... or shorter: drop everything past its end
        display_printf("s 0x%llx\n", other->size);
        display_printf("d\n");
    }

    display_printf("c\n");
}

static int diffcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    if (pc->args.size != 1)
        return COMMAND_UNSUPPORTED_ARG;

    int print_bytes = -1;
    int wide        = -1;
    int no_colors   = -1;
    int script      = -1;
    if (handle_mods(pc, "p|w|n|c", &print_bytes, &wide, &no_colors, &script) !=
        0)
        return COMMAND_INVALID_MOD;

    print_bytes = print_bytes == 0;
    wide        = wide == 0;
    no_colors   = no_colors == 0;
    script      = script == 0;

    const char* other    = (const char*)pc->args.head->data;
    FileBuffer* other_fb = filebuffer_create(other, 1);
    if (other_fb == NULL)
        return COMMAND_INVALID_ARG;

    u64_t soff = fb->off;
    if (script)
        print_diff_script(fb, other_fb);
    else
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
