#include "cmd_strings.h"
#include <util/byte_to_num.h>

#include <string.h>

#include <alloc.h>
#include <log.h>

#define min(x, y) ((x) < (y) ? (x) : (y))

static void stringscmd_dispose(void* obj) { return; }

static void stringscmd_help(void* obj)
{
    printf("\n"
           "enumerate the strings in the file (i.e., sequences of printable "
           "ascii characters)\n"
           "\n"
           "  str[/n] [<num>]\n"
           "     n: look for null-terminated strings\n"
           "\n"
           "  num: minimum length (default: 3)\n"
           "\n");
}

static int is_printable_ascii(u8_t v) { return v >= 0x20 && v <= 0x7e; }

static void print_strings(FileBuffer* fb, size_t min_length,
                          int null_terminated)
{
    u64_t orig_off = fb->off;
    fb_seek(fb, 0);

    u64_t       buf_size = min(fb_block_size, fb->size - fb->off);
    const u8_t* buf      = fb_read(fb, buf_size);

    u8_t*  app          = bhex_malloc(min_length);
    size_t app_capacity = min_length;

    u64_t addr = 0;
    while (addr < fb->size) {
        if (!is_printable_ascii(buf[addr % buf_size])) {
            addr += 1;
            if (addr % buf_size == 0) {
                fb_seek(fb, addr);
                buf_size = min(fb_block_size, fb->size - fb->off);
                buf      = fb_read(fb, buf_size);
            }
            continue;
        }

        u64_t begin_addr = addr;
        u32_t app_off    = 0;
        while (addr < fb->size && is_printable_ascii(buf[addr % buf_size])) {
            if (app_off == app_capacity - 1) {
                app = bhex_realloc(app, app_capacity * 2);
                app_capacity *= 2;
            }
            app[app_off++] = buf[addr % buf_size];

            addr += 1;
            if (addr % buf_size == 0) {
                fb_seek(fb, addr);
                buf_size = min(fb_block_size, fb->size - fb->off);
                buf      = fb_read(fb, buf_size);
            }
        }
        if (app_off >= min_length) {
            if (!null_terminated ||
                (null_terminated && buf[addr % buf_size] == 0)) {
                app[app_off] = 0;
                printf(" 0x%07llX @ %s\n", begin_addr, (char*)app);
            }
        }
    }

    bhex_free(app);
    fb_seek(fb, orig_off);
}

static int stringscmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    if (pc->cmd_modifiers.size > 1)
        return COMMAND_UNSUPPORTED_MOD;
    if (pc->args.size > 1)
        return COMMAND_UNSUPPORTED_ARG;

    int null_terminated = 0;
    if (pc->cmd_modifiers.size == 1) {
        char* m = (char*)pc->cmd_modifiers.head->data;
        if (strcmp(m, "n") == 0)
            null_terminated = 1;
        else
            return COMMAND_UNSUPPORTED_MOD;
    }

    size_t min_length = 3;
    if (pc->args.size == 1) {
        char* arg = (char*)pc->args.head->data;
        u32_t s;
        if (!str_to_uint32(arg, &s) || s == 0)
            return COMMAND_INVALID_ARG;
        if (s >= 4096) {
            error("the minimum length is greater than the max value (4096)");
            return COMMAND_INVALID_ARG;
        }
        min_length = s;
    }

    print_strings(fb, min_length, null_terminated);
    return COMMAND_OK;
}

Cmd* stringscmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "strings";
    cmd->alias = "str";

    cmd->dispose = stringscmd_dispose;
    cmd->help    = stringscmd_help;
    cmd->exec    = stringscmd_exec;

    return cmd;
}
