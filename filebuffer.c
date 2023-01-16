#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "filebuffer.h"
#include "alloc.h"
#include "log.h"

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))

int fb_seek(FileBuffer* fb, uint64_t off)
{
    if (off >= fb->size)
        return 1;

    if (fseek(fb->file, off, SEEK_SET) < 0)
        panic("fseek failed");
    if (fread(fb->block, 1, fb_block_size, fb->file) !=
        min(fb_block_size, fb->size - off)) {
        warning("unable to read bytes in fb_seek, off=%llu", off);
        return 1;
    }
    fb->off = off;
    return 0;
}

FileBuffer* filebuffer_create(const char* path)
{
    FileBuffer* fb        = bhex_malloc(sizeof(FileBuffer));
    fb->path              = bhex_strdup(path);
    fb->readonly          = 0;
    fb->modifications     = ll_create();
    fb->big_read          = NULL;
    fb->big_read_capacity = 0;

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

static void delete_modification(uintptr_t o)
{
    Modification* mod = (Modification*)o;
    bhex_free(mod->data);
    bhex_free(mod);
}

int fb_add_modification(FileBuffer* fb, uint8_t* data, size_t size)
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

    ll_add(&fb->modifications, (uintptr_t)mod);
    return 1;
}

int fb_remove_last_modification(FileBuffer* fb)
{
    LLNode* n = ll_pop(&fb->modifications);
    if (!n)
        return 0;

    delete_modification(n->data);
    bhex_free(n);
    return 1;
}

static int overlaps(uint64_t startA, uint64_t endA, uint64_t startB,
                    uint64_t endB)
{
    // Check if [startA, endA) overlaps with [startB, endB)
    return startA <= endB && endA > startB;
}

static void apply_modifications(FileBuffer* fb, uint8_t* data, size_t size)
{
    ll_invert(&fb->modifications);

    LLNode* curr = fb->modifications.head;
    while (curr) {
        Modification* mod = (Modification*)curr->data;
        if (overlaps(mod->off, mod->off + mod->size, fb->off, fb->off + size)) {
            // The modification overlaps
            uint64_t start = max(mod->off, fb->off);
            uint64_t end   = min(mod->off + mod->size, fb->off + size);
            uint64_t off;
            for (off = start; off < end; ++off) {
                data[off - fb->off] = mod->data[off - mod->off];
            }
        }
        curr = curr->next;
    }

    ll_invert(&fb->modifications);
}

void fb_commit_modifications(FileBuffer* fb)
{
    if (fb->readonly) {
        warning("cannot commit, the file was opened in read-only mode");
        return;
    }

    uint64_t origin_off = fb->off;

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

const uint8_t* fb_read(FileBuffer* fb, size_t size)
{
    if (size + fb->off > fb->size)
        // Not enough data
        return NULL;

    if (size <= fb_block_size && fb->modifications.size == 0)
        return fb->block;

    // Alloc or re-alloc big_read if needed
    if (fb->big_read == NULL) {
        fb->big_read          = bhex_malloc(size);
        fb->big_read_capacity = size;
    } else if (size > fb->big_read_capacity) {
        fb->big_read          = bhex_realloc(fb->big_read, size);
        fb->big_read_capacity = size;
    }

    memcpy(fb->big_read, fb->block, min(fb_block_size, size));
    if (size > fb_block_size) {
        fseek(fb->file, fb->off + fb_block_size, SEEK_SET);
        if (fread(fb->big_read + fb_block_size, 1, size - fb_block_size,
                  fb->file) < size - fb_block_size)
            warning("unable to read all data");
        fseek(fb->file, fb->off, SEEK_SET);
    }

    if (fb->modifications.size != 0)
        apply_modifications(fb, fb->big_read, size);
    return fb->big_read;
}

void filebuffer_destroy(FileBuffer* fb)
{
    fclose(fb->file);
    ll_clear(&fb->modifications, delete_modification);

    bhex_free(fb->big_read);
    bhex_free(fb->path);
    bhex_free(fb);
}
