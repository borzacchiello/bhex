#include "cmd.h"
#include "cmd_arg_handler.h"
#include "defs.h"
#include "filebuffer.h"
#include "ll.h"
#include "cmd_commit.h"

#include <display.h>
#include <alloc.h>

#define LIST_SET 0

#define MOD_TYPE_OVERWRITE 1
#define MOD_TYPE_INSERT    2
#define MOD_TYPE_DELETE    3

#define HINT_STR "/l"

static void commitcmd_dispose(void* obj) { return; }

static void commitcmd_help(void* obj)
{
    display_printf("\ncommit: commit all writes to file\n"
                   "\n"
                   "  c" HINT_STR "\n"
                   "     l:  list uncommited changes\n"
                   "\n");
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
        LLNode* node = fb->modifications.head;
        while (node != NULL) {
            Modification* mod = (Modification*)node->data;
            switch (mod->type) {
                case MOD_TYPE_OVERWRITE: {
                    display_printf(" > overwrite @ 0x%llx -> 0x%llx\n",
                                   mod->off, mod->end);
                    break;
                }
                case MOD_TYPE_INSERT:
                    display_printf(" > insert    @ 0x%llx [ %lu ]\n", mod->off,
                                   mod->size);
                    break;
                case MOD_TYPE_DELETE:
                    display_printf(" > delete    @ 0x%llx [ %lu ]\n", mod->off,
                                   mod->size);
                    break;
            }
            node = node->next;
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
