#include "cmd_arg_handler.h"
#include "cmd_commit.h"
#include "filebuffer.h"
#include "defs.h"
#include "ll.h"

#include <display.h>
#include <alloc.h>

#define min(x, y)          ((x) < (y) ? (x) : (y))
#define HINT_STR           "[/l]"
#define LIST_SET           0
#define MOD_TYPE_OVERWRITE 1
#define MOD_TYPE_INSERT    2
#define MOD_TYPE_DELETE    3

static void commitcmd_dispose(void* obj) { return; }

static void commitcmd_help(void* obj)
{
    display_printf("commit: commit all writes to file\n"
                   "\n"
                   "  c" HINT_STR "\n"
                   "     l: list uncommited changes\n");
}

static void print_overwrite(FileBuffer* fb, Modification* mod, u32_t nmod)
{
    display_printf(" ~ overwrite @ 0x%07llx [ %lu ]\n", mod->off, mod->size);

    const uint8_t* data;
    u64_t          off = fb->off;
    fb_seek(fb, mod->off);

    display_printf("      ");
    u32_t n = min(mod->size, 8);
    data    = fb_read_ex(fb, n, nmod + 1);
    for (u32_t i = 0; i < n; ++i)
        display_printf("%02x ", data[i]);
    if (n != mod->size)
        display_printf("... ");
    display_printf("-> ");
    data = fb_read_ex(fb, n, nmod);
    for (u32_t i = 0; i < n; ++i)
        display_printf("%02x ", data[i]);
    if (n != mod->size)
        display_printf("... ");
    display_printf("\n");

    fb_seek(fb, off);
}

static void print_insert(FileBuffer* fb, Modification* mod, u32_t nmod)
{
    display_printf(" ~ insert    @ 0x%07llx [ %lu ]\n", mod->off, mod->size);

    display_printf("      ");
    u32_t n = min(mod->size, 8);
    for (u32_t i = 0; i < n; ++i)
        display_printf("%02x ", mod->data[i]);
    if (n != mod->size)
        display_printf("... ");
    display_printf("\n");
}

static void print_delete(FileBuffer* fb, Modification* mod, u32_t nmod)
{
    display_printf(" ~ delete    @ 0x%07llx [ %lu ]\n", mod->off, mod->size);

    const uint8_t* data;
    u64_t          off = fb->off;
    fb_seek(fb, mod->off);

    display_printf("      ");
    u32_t n = min(mod->size, 8);
    data    = fb_read_ex(fb, n, nmod + 1);
    for (u32_t i = 0; i < n; ++i)
        display_printf("%02x ", data[i]);
    if (n != mod->size)
        display_printf("... ");
    display_printf("\n");

    fb_seek(fb, off);
}

static int commitcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    if (handle_args(pc, 0, 0) != 0)
        return COMMAND_INVALID_ARG;

    int list = -1;
    if (handle_mods(pc, "l", &list) != 0)
        return COMMAND_INVALID_MOD;

    if (list == LIST_SET) {
        if (fb->modifications.size)
            display_printf("\n");

        u32_t   nmod = 0;
        ll_node_t* node = fb->modifications.head;
        while (node != NULL) {
            Modification* mod = (Modification*)node->data;
            switch (mod->type) {
                case MOD_TYPE_OVERWRITE:
                    print_overwrite(fb, mod, nmod);
                    break;
                case MOD_TYPE_INSERT:
                    print_insert(fb, mod, nmod);
                    break;
                case MOD_TYPE_DELETE:
                    print_delete(fb, mod, nmod);
                    break;
            }
            node = node->next;
            nmod++;
        }
        if (fb->modifications.size)
            display_printf("\n");
        return COMMAND_OK;
    }

    fb_commit(fb);
    return COMMAND_OK;
}

Cmd* commitcmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "commit";
    cmd->alias = "c";
    cmd->hint  = HINT_STR;

    cmd->dispose = commitcmd_dispose;
    cmd->help    = commitcmd_help;
    cmd->exec    = commitcmd_exec;

    return cmd;
}
