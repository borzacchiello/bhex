#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "filebuffer.h"
#include "alloc.h"
#include "log.h"

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))

int fb_seek(FileBuffer* fb, u64_t off)
{
    if (off >= fb->size)
        return 1;

    fb->off         = off;
    fb->block_dirty = 1;
    return 0;
}

FileBuffer* filebuffer_create(const char* path)
{
    FileBuffer* fb    = bhex_malloc(sizeof(FileBuffer));
    fb->path          = bhex_strdup(path);
    fb->readonly      = 0;
    fb->modifications = ll_create();
    fb->block_dirty   = 1;

    // Try to open the file in "read/write" mode
    FILE* f = fopen(path, "rb+");
    if (f == NULL && (errno == EACCES || errno == EROFS)) {
        warning("cannot open with write permission, opening in read-only mode");
        fb->readonly = 1;
        f            = fopen(path, "rb");
    }
    if (f == NULL) {
        warning("cannot open the file");
        bhex_free(fb->path);
        bhex_free(fb);
        return NULL;
    }
    fb->file = f;

    if (fseek(fb->file, 0, SEEK_END) < 0)
        panic("fseek failed");

    long filelen = ftell(fb->file);
    if (filelen < 0)
        panic("ftell failed");
    fb->size = filelen;

    if (fb_seek(fb, 0) != 0)
        panic("fseek failed");
    return fb;
}

static void delete_modification(uptr_t o)
{
    Modification* mod = (Modification*)o;
    bhex_free(mod->data);
    bhex_free(mod);
}

int fb_add_modification(FileBuffer* fb, u8_t* data, size_t size)
{
    if (fb->readonly)
        warning("the file was opened in read-only mode, thus you cannot commit "
                "this modification");

    if (fb->off + size > fb->size)
        return 0;

    Modification* mod = bhex_malloc(sizeof(Modification));
    mod->data         = data;
    mod->off          = fb->off;
    mod->size         = size;

    ll_add(&fb->modifications, (uptr_t)mod);
    fb->block_dirty = 1;
    return 1;
}

int fb_remove_last_modification(FileBuffer* fb)
{
    LLNode* n = ll_pop(&fb->modifications);
    if (!n)
        return 0;

    delete_modification(n->data);
    bhex_free(n);
    fb->block_dirty = 1;
    return 1;
}

void fb_commit_modifications(FileBuffer* fb)
{
    if (fb->readonly) {
        warning("cannot commit, the file was opened in read-only mode");
        return;
    }

    u64_t origin_off = fb->off;

    ll_invert(&fb->modifications);

    LLNode* curr = fb->modifications.head;
    while (curr) {
        Modification* mod = (Modification*)curr->data;
        if (fseek(fb->file, mod->off, SEEK_SET) < 0)
            panic("fseek failed");
        if (fwrite(mod->data, 1, mod->size, fb->file) != mod->size)
            panic("fwrite failed");
        curr = curr->next;
    }
    ll_clear(&fb->modifications, delete_modification);

    fb_seek(fb, origin_off);
}

static int overlaps(u64_t startA, u64_t endA, u64_t startB, u64_t endB)
{
    // Check if [startA, endA) overlaps with [startB, endB)
    return startA <= endB && endA > startB;
}

static void fb_read_internal(FileBuffer* fb)
{
    static u8_t  tmp_block[fb_block_size];
    static s8_t  block_map[fb_block_size];
    static u32_t block_map_nset;

    memset(block_map, 0, sizeof(block_map));
    block_map_nset = 0;

    u64_t  seek_off = fb->off;
    size_t size     = min(fb_block_size, fb->size - seek_off);

    LLNode* curr = fb->modifications.head;
    while (curr) {
        Modification* mod = (Modification*)curr->data;
        if (overlaps(mod->off, mod->off + mod->size, seek_off,
                     seek_off + size)) {
            // The modification overlaps
            u64_t start = max(mod->off, seek_off);
            u64_t end   = min(mod->off + mod->size, seek_off + size);
            u64_t off;
            for (off = start; off < end; ++off) {
                if (block_map[off - seek_off])
                    continue;
                fb->block[off - seek_off] = mod->data[off - mod->off];
                block_map[off - seek_off] = 1;
                block_map_nset += 1;
            }
        }
        if (block_map_nset == fb_block_size)
            break;

        curr = curr->next;
    }

    if (block_map_nset == fb_block_size)
        return;

    // We have to read the file
    if (fseek(fb->file, seek_off, SEEK_SET) < 0)
        panic("fseek failed");
    if (fread(tmp_block, 1, fb_block_size, fb->file) !=
        min(fb_block_size, fb->size - seek_off)) {
        panic("unable to read bytes in fb_read_internal, off=%llu", seek_off);
    }
    u64_t i;
    for (i = 0; i < fb_block_size; ++i) {
        if (block_map[i])
            continue;
        fb->block[i] = tmp_block[i];
    }
}

const u8_t* fb_read(FileBuffer* fb, size_t size)
{
    if (size > fb_block_size) {
        // FIXME: this case could be useful, maybe implement it using a dynamic
        //        buffer
        warning("You cannot read more than %lu bytes", size);
        return NULL;
    }
    if (size + fb->off > fb->size) {
        warning("Too many bytes to read: %lu", size);
        return NULL;
    }

    if (fb->block_dirty)
        fb_read_internal(fb);
    fb->block_dirty = 0;
    return (const u8_t*)fb->block;
}

void filebuffer_destroy(FileBuffer* fb)
{
    fclose(fb->file);
    ll_clear(&fb->modifications, delete_modification);

    bhex_free(fb->path);
    bhex_free(fb);
}
