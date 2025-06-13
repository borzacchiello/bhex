#include "cmd_diff.h"

#include <util/print.h>
#include <display.h>
#include <string.h>
#include <stdio.h>
#include <alloc.h>
#include <defs.h>

#define HINT_STR "[/p] <file>"

#define min(x, y)  ((x) < (y) ? (x) : (y))
#define bold_begin display_printf("\033[1m")
#define bold_end   display_printf("\033[22m")

static void diffcmd_dispose(void* obj) {}

static void diffcmd_help(void* obj)
{
    display_printf("\ndiff: prints the differences with another file\n"
                   "\n"
                   "  df" HINT_STR "\n"
                   "     p:  print different bytes\n"
                   "\n"
                   "  file: path to the file to compare\n\n");
}

static void print_diff(FileBuffer* self, FileBuffer* other, u64_t start,
                       u64_t end)
{
    u64_t self_rst  = self->off;
    u64_t other_rst = other->off;

    u64_t addr = start;
    while (addr < end) {
        fb_seek(self, addr);
        fb_seek(other, addr);
        u64_t n = min(16, end - addr);

        print_hex(fb_read(self, n), n, 0, 0, 0, addr);
        bold_begin;
        print_hex(fb_read(other, n), n, 0, 0, 0, addr);
        bold_end;

        addr += n;
    }
    display_printf(" ...\n");

    // restore the read block buffer
    fb_seek(self, self_rst);
    fb_seek(other, other_rst);
    u64_t size =
        min(min(fb_block_size, self->size - self_rst), other->size - other_rst);
    fb_read(self, size);
    fb_read(other, size);
}

static void print_diffs(FileBuffer* self, FileBuffer* other, int print_diffs)
{
    fb_seek(self, 0);
    fb_seek(other, 0);

    if (print_diffs)
        display_printf("\n");

    u64_t ndiffs     = 0;
    u64_t off        = 0;
    u64_t start_diff = 0;
    u64_t end_diff   = 0;
    while (1) {
        if (off >= self->size || off >= other->size)
            break;

        u64_t size =
            min(min(fb_block_size, self->size - off), other->size - off);
        const u8_t* self_block  = fb_read(self, size);
        const u8_t* other_block = fb_read(other, size);
        for (u32_t i = 0; i < size; ++i) {
            if (self_block[i] == other_block[i]) {
                if (end_diff != start_diff && print_diffs) {
                    print_diff(self, other, start_diff, end_diff);
                }

                end_diff = start_diff = 0;
            } else {
                if (start_diff == 0)
                    end_diff = start_diff = off;
                end_diff++;
                ndiffs++;
            }
            off++;
        }

        fb_seek(self, off);
        fb_seek(other, off);
    }

    if (end_diff != start_diff && print_diffs)
        print_diff(self, other, start_diff, end_diff);

    display_printf("\n");
    if (off < self->size)
        display_printf("current file is bigger\n");
    if (off < other->size)
        display_printf("other file is bigger\n");

    display_printf("%.03lf%% of current file is different\n\n",
                   (double)ndiffs / (double)min(self->size, other->size) * 100);
}

static int diffcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    if (pc->args.size != 1)
        return COMMAND_UNSUPPORTED_ARG;
    if (pc->cmd_modifiers.size > 1)
        return COMMAND_UNSUPPORTED_MOD;

    int print_bytes = 0;
    if (pc->cmd_modifiers.size == 1 &&
        strcmp((char*)pc->cmd_modifiers.head->data, "p") == 0)
        print_bytes = 1;

    const char* other    = (const char*)pc->args.head->data;
    FileBuffer* other_fb = filebuffer_create(other, 1);
    if (other_fb == NULL)
        return COMMAND_INVALID_ARG;

    u64_t soff = fb->off;
    print_diffs(fb, other_fb, print_bytes);
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
