#include "cmd_search.h"

#include <string.h>

#include "util/str.h"
#include "../alloc.h"
#include "../log.h"

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))

#define DATA_TYPE_UNSET  0
#define DATA_TYPE_STRING 1
#define DATA_TYPE_HEX    2

#define SEEK_TO_MATCH_UNSET 0
#define SEEK_TO_MATCH_SET   1

static void searchcmd_dispose(void* obj) { return; }

static void searchcmd_help(void* obj)
{
    printf("\nsearch: search a string or a sequence of bytes in the file\n"
           "\n"
           "  s[/{x, s}/sk] <data>\n"
           "     x:  data is an hex string\n"
           "     s:  data is a string (default)\n"
           "     sk: seek to first match\n"
           "\n"
           "  data: either a string or an hex string\n"
           "\n");
}

static void search(FileBuffer* fb, const uint8_t* data, size_t size,
                   int seek_to_match)
{
    u64_t orig_off = fb->off;
    fb_seek(fb, 0);

    size_t buf_off  = 0;
    size_t buf_size = max(size * 2, fb_block_size * 2);
    u8_t*  buf      = bhex_malloc(buf_size);

    memcpy(buf, fb_read(fb, min(buf_size / 2, fb->size)),
           min(buf_size / 2, fb->size));

    u64_t addr = 0;
    while (addr + size <= fb->size) {
        u64_t begin_addr = addr;

        int    eq = 1;
        size_t j  = 0;
        for (j = 0; j < size; ++j) {
            size_t curr_off = (buf_off + j) % buf_size;
            if (curr_off == 0 && fb->off != addr + j) {
                fb_seek(fb, addr + j);
                memcpy(buf, fb_read(fb, min(buf_size / 2, fb->size - fb->off)),
                       min(buf_size / 2, fb->size - fb->off));
            } else if (curr_off == buf_size / 2 && fb->off != addr + j) {
                fb_seek(fb, addr + j);
                memcpy(buf + buf_size / 2,
                       fb_read(fb, min(buf_size / 2, fb->size - fb->off)),
                       min(buf_size / 2, fb->size - fb->off));
            }

            eq = data[j] == buf[curr_off];
            if (!eq)
                break;
        }
        if (eq) {
            printf(" >> Match @ 0x%07llX\n", begin_addr);
            if (seek_to_match)
                orig_off = begin_addr;
        }

        addr += 1;
        buf_off += 1;
    }

    bhex_free(buf);
    fb_seek(fb, orig_off);
}

static int searchcmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    int     data_type     = DATA_TYPE_UNSET;
    int     seek_to_match = SEEK_TO_MATCH_UNSET;
    LLNode* curr          = pc->cmd_modifiers.head;
    while (curr) {
        if (strcmp((char*)curr->data, "s") == 0) {
            if (data_type != DATA_TYPE_UNSET)
                return COMMAND_INVALID_MODE;
            data_type = DATA_TYPE_STRING;
        } else if (strcmp((char*)curr->data, "x") == 0) {
            if (data_type != DATA_TYPE_UNSET)
                return COMMAND_INVALID_MODE;
            data_type = DATA_TYPE_HEX;
        } else if (strcmp((char*)curr->data, "sk") == 0) {
            if (seek_to_match != SEEK_TO_MATCH_UNSET)
                return COMMAND_INVALID_MODE;
            seek_to_match = SEEK_TO_MATCH_SET;
        }
        curr = curr->next;
    }

    if (data_type == DATA_TYPE_UNSET)
        data_type = DATA_TYPE_STRING;

    if (pc->args.size != 1)
        return COMMAND_INVALID_ARG;

    u8_t*  data      = NULL;
    size_t data_size = 0;
    char*  data_str  = (char*)pc->args.head->data;
    switch (data_type) {
        case DATA_TYPE_STRING:
            if (!unescape_ascii_string(data_str, &data, &data_size))
                return COMMAND_INVALID_ARG;
            break;
        case DATA_TYPE_HEX:
            if (!hex_to_bytes(data_str, &data, &data_size))
                return COMMAND_INVALID_ARG;
            break;
    }

    search(fb, data, data_size, seek_to_match == SEEK_TO_MATCH_SET);
    bhex_free(data);
    return COMMAND_OK;
}

Cmd* searchcmd_create()
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "search";
    cmd->alias = "src";

    cmd->dispose = searchcmd_dispose;
    cmd->help    = searchcmd_help;
    cmd->exec    = searchcmd_exec;

    return cmd;
}
