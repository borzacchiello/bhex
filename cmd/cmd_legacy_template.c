#include "cmd_legacy_template.h"

#include <string.h>

#include "templates/template.h"
#include "../alloc.h"
#include "../log.h"

static void legacy_templatecmd_dispose(void* obj) { return; }

static void legacy_templatecmd_help(void* obj)
{
    printf("\nlegaty_template: parse a struct template at current offset\n"
           "\n  WARNING: legacy command, it will be removed\n"
           "\n"
           "  lt[/l/{le,be}] <template_name>\n"
           "     l:  list available templates\n"
           "     le: interpret numbers as little-endian (default)\n"
           "     be: interpret numbers as big-endian\n"
           "\n"
           "  template_name: the name of the template to use\n"
           "\n");
}

static int legacy_templatecmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    if (pc->cmd_modifiers.size > 1)
        return COMMAND_UNSUPPORTED_MOD;

    if (pc->cmd_modifiers.size == 1 &&
        strcmp((char*)pc->cmd_modifiers.head->data, "l") == 0) {
        if (pc->args.size != 0)
            return COMMAND_INVALID_ARG;

        // list the templates
        printf("\nAvailable templates:\n");
        size_t i;
        for (i = 0; i < sizeof(templates) / sizeof(Template); ++i) {
            Template* t = &templates[i];
            printf("    %s\n", t->name);
        }
        printf("\n");
        return COMMAND_OK;
    }

    int le = 1;
    if (pc->cmd_modifiers.size == 1) {
        char* mod = (char*)pc->cmd_modifiers.head->data;
        if (strcmp(mod, "le") == 0) {
            le = 1;
        } else if (strcmp(mod, "be") == 0) {
            le = 0;
        } else {
            return COMMAND_UNSUPPORTED_MOD;
        }
    }

    if (pc->args.size != 1)
        return COMMAND_INVALID_ARG;

    int template_found = 0;

    char*  tname = (char*)pc->args.head->data;
    size_t i;
    for (i = 0; i < sizeof(templates) / sizeof(Template); ++i) {
        Template* t = &templates[i];
        if (strcmp(tname, t->name) == 0) {
            if (t->get_size() > fb->size - fb->off) {
                error("not enough data to apply the template");
                return COMMAND_INVALID_ARG;
            }
            template_found = 1;
            printf("\n");
            t->pretty_print(fb_read(fb, t->get_size()), t->get_size(), le);
            printf("\n");
            break;
        }
    }

    if (!template_found) {
        error("template not found");
        return COMMAND_INVALID_ARG;
    }
    return COMMAND_OK;
}

Cmd* legacy_templatecmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "legacy_template";
    cmd->alias = "lt";

    cmd->dispose = legacy_templatecmd_dispose;
    cmd->help    = legacy_templatecmd_help;
    cmd->exec    = legacy_templatecmd_exec;

    return cmd;
}
