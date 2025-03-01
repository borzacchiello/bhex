#include "cmd_arg_handler.h"
#include "ll.h"

#include <stdarg.h>
#include <string.h>
#include <log.h>

#include <stdio.h>

#define MAX_MODS_FMT 128
#define GROUP_DELIM  "|"
#define EL_DELIM     ","

// FIXME: this file is a mess

static int is_valid_mod(const char* mod, const char* modsfmt)
{
    char   tmp[MAX_MODS_FMT] = {0};
    size_t fmtl              = strlen(modsfmt);
    if (fmtl > sizeof(tmp) - 1)
        panic("invalid modsfmt: too long [%llu]", fmtl);
    memcpy(tmp, modsfmt, fmtl);

    char *group_state, *el_state;
    char *group, *el;

    group = strtok_r(tmp, GROUP_DELIM, &group_state);
    while (group != NULL) {
        el = strtok_r(group, EL_DELIM, &el_state);
        while (el != NULL) {
            if (strcmp(el, mod) == 0)
                return 0;
            el = strtok_r(NULL, EL_DELIM, &el_state);
        }
        group = strtok_r(NULL, GROUP_DELIM, &group_state);
    }
    return 1;
}

int handle_mods(ParsedCommand* pcmd, const char* modsfmt, ...)
{
    LLNode* mod = pcmd->cmd_modifiers.head;
    while (mod != NULL) {
        if (is_valid_mod((const char*)mod->data, modsfmt) != 0)
            return 1;
        mod = mod->next;
    }

    char   tmp[MAX_MODS_FMT] = {0};
    size_t fmtl              = strlen(modsfmt);
    if (fmtl > sizeof(tmp) - 1)
        panic("invalid modsfmt: too long [%llu]", fmtl);
    memcpy(tmp, modsfmt, fmtl);

    va_list ap;
    va_start(ap, modsfmt);

    char *group_state, *el_state;
    char *group, *el;

    group = strtok_r(tmp, GROUP_DELIM, &group_state);
    while (group != NULL) {
        int* vptr    = va_arg(ap, int*);
        int  was_set = 0;
        int  idx     = 0;
        el           = strtok_r(group, EL_DELIM, &el_state);
        while (el != NULL) {
            LLNode* mod = pcmd->cmd_modifiers.head;
            while (mod != NULL) {
                if (strcmp((const char*)mod->data, el) == 0) {
                    if (was_set) {
                        // duplicate element in group
                        va_end(ap);
                        return 1;
                    }
                    was_set = 1;
                    *vptr   = idx;
                }
                mod = mod->next;
            }
            if (*vptr)
                break;
            idx += 1;
            el = strtok_r(NULL, EL_DELIM, &el_state);
        }
        group = strtok_r(NULL, GROUP_DELIM, &group_state);
    }

    va_end(ap);
    return 0;
}

int handle_args(ParsedCommand* pcmd, u32_t max, u32_t required, ...)
{
    if (pcmd->args.size < required || pcmd->args.size > max)
        return 1;

    va_list ap;
    va_start(ap, required);
    LLNode* arg = pcmd->args.head;
    while (arg != NULL) {
        char** vptr = va_arg(ap, char**);
        *vptr       = (char*)arg->data;
        arg         = arg->next;
    }

    va_end(ap);
    return 0;
}
