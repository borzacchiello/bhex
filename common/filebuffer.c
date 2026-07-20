// Copyright (c) 2022-2026, bageyelet

#include "filebuffer.h"

#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <defs.h>

#include <alloc.h>
#include <log.h>
#include <pthread.h>

#define MOD_TYPE_OVERWRITE 1
#define MOD_TYPE_INSERT    2
#define MOD_TYPE_DELETE    3

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))

static void fb_lock(FileBuffer* fb)
{
    if (pthread_mutex_lock(&fb->lock) != 0)
        panic("pthread_mutex_lock failed");
}

static void fb_unlock(FileBuffer* fb)
{
    if (pthread_mutex_unlock(&fb->lock) != 0)
        panic("pthread_mutex_unlock failed");
}

// Invalidate the read cache. Must be called by every operation that changes
// the file contents/structure (write/insert/delete/undo/commit/reload). It is
// intentionally NOT called on a plain seek: the cache is keyed on absolute file
// offsets, so seeking within an already-loaded window stays a cache hit.
static void fb_invalidate_cache(FileBuffer* fb) { fb->cache_valid = 0; }

static int was_file_modified(const char* path, time_t prev_time,
                             time_t* new_time)
{
    struct stat file_stat;
    int         err = stat(path, &file_stat);
    if (err != 0)
        panic("unable to stat file %s", path);

    *new_time = file_stat.st_mtime;
    return file_stat.st_mtime != prev_time;
}

static int fb_reload(FileBuffer* fb)
{
    fb_invalidate_cache(fb);
    fb_undo_all(fb);

    if (fseek(fb->file, 0, SEEK_END) < 0) {
        error("fb_reload(): fseek failed");
        return 0;
    }

    long filelen = ftell(fb->file);
    if (filelen < 0) {
        error("fb_reload(): ftell failed");
        return 0;
    }
    fb->size = filelen;

    was_file_modified(fb->path, 0, &fb->mod_time);
    return 1;
}

static void fb_modified_check(FileBuffer* fb)
{
    // This function checks whether the file was modified.
    // If so it reloads it deleting all the modifications

    time_t new_time;
    if (was_file_modified(fb->path, fb->mod_time, &new_time)) {
        warning("the file was modified outside bhex, reloading it loosing all "
                "the uncommitted modifications (sorry)");
        fb->version += 1 + fb->modifications.size;
        if (!fb_reload(fb))
            panic("unable to reload the file");
        fb->mod_time = new_time;
    }
}

int fb_seek(FileBuffer* fb, u64_t off)
{
    int r = 1;
    fb_lock(fb);
    if (off <= fb->size) {
        fb->off         = off;
        fb->block_dirty = 1;
        r               = 0;
    }
    fb_unlock(fb);
    return r;
}

FileBuffer* filebuffer_create(const char* path, int readonly)
{
    FileBuffer* fb    = bhex_malloc(sizeof(FileBuffer));
    fb->path          = bhex_strdup(path);
    fb->readonly      = readonly;
    fb->modifications = ll_create();
    fb->block_dirty   = 1;
    fb->cache_valid   = 0;
    fb->version       = 0;
    fb->search_index  = bhex_calloc(sizeof(SearchIndex));
    fb->off           = 0;
    fb->base_addr     = 0;
    memset(fb->block, 0, sizeof(fb->block));
    memset(fb->tmp_block, 0, sizeof(fb->tmp_block));

    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) != 0)
        panic("pthread_mutexattr_init failed");
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) != 0)
        panic("pthread_mutexattr_settype failed");
    if (pthread_mutex_init(&fb->lock, &attr) != 0)
        panic("pthread_mutex_init failed");
    if (pthread_mutexattr_destroy(&attr) != 0)
        panic("pthread_mutexattr_destroy failed");

    FILE* f = NULL;
    if (!readonly) {
        f = fopen(path, "rb+");
        if (f == NULL && (errno == EACCES || errno == EROFS)) {
            error(
                "cannot open with write permission, opening in read-only mode");
            fb->readonly = 1;
            f            = fopen(path, "rb");
        }
    } else {
        f = fopen(path, "rb");
    }
    if (f == NULL) {
        error("cannot open the file");
        pthread_mutex_destroy(&fb->lock);
        bhex_free(fb->search_index);
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

    was_file_modified(fb->path, 0, &fb->mod_time);
    return fb;
}

static void delete_modification(uptr_t o)
{
    Modification* mod = (Modification*)o;
    bhex_free(mod->data);
    bhex_free(mod);
}

int fb_write(FileBuffer* fb, u8_t* data, size_t size)
{
    int r = 0;
    fb_lock(fb);
    fb_invalidate_cache(fb);
    fb_modified_check(fb);
    if (fb->readonly)
        warning("the file was opened in read-only mode, you cannot commit this "
                "modification");

    if (fb->off + size > fb->size) {
        error("not enough space to write the data");
        goto end;
    }

    Modification* mod = bhex_malloc(sizeof(Modification));
    mod->type         = MOD_TYPE_OVERWRITE;
    mod->chain_n      = 0;
    mod->data         = data;
    mod->off          = fb->off;
    mod->end          = fb->off + size;
    mod->size         = size;

    ll_add(&fb->modifications, (uptr_t)mod);
    fb->block_dirty = 1;
    fb->version += 1;
    r = 1;

end:
    fb_unlock(fb);
    return r;
}

int fb_insert(FileBuffer* fb, u8_t* data, size_t size)
{
    int r = 0;
    fb_lock(fb);
    fb_invalidate_cache(fb);
    fb_modified_check(fb);
    if (fb->readonly)
        warning("the file was opened in read-only mode, you cannot commit this "
                "modification");

    if (size > fb_block_size) {
        error("cannot insert more than %lu bytes", fb_block_size);
        goto end;
    }

    Modification* mod = bhex_malloc(sizeof(Modification));
    mod->type         = MOD_TYPE_INSERT;
    mod->chain_n      = 0;
    mod->data         = data;
    mod->off          = fb->off;
    mod->size         = size;
    mod->end          = fb->size + mod->size;

    ll_add(&fb->modifications, (uptr_t)mod);
    fb->size += size;
    fb->block_dirty = 1;
    fb->version += 1;
    r = 1;

end:
    fb_unlock(fb);
    return r;
}

int fb_delete(FileBuffer* fb, size_t size)
{
    int r = 0;
    fb_lock(fb);
    fb_invalidate_cache(fb);
    fb_modified_check(fb);
    if (fb->readonly)
        warning("the file was opened in read-only mode, you cannot commit this "
                "modification");

    if (fb->size - fb->off < size) {
        error("not enough data to delete");
        goto end;
    }

    u32_t num_blocks = 0;
    while (size > fb_block_size) {
        Modification* mod = bhex_malloc(sizeof(Modification));
        mod->type         = MOD_TYPE_DELETE;
        mod->chain_n      = 0;
        mod->data         = NULL;
        mod->off          = fb->off;
        mod->end          = fb->size;
        mod->size         = fb_block_size;
        ll_add(&fb->modifications, (uptr_t)mod);

        fb->size -= fb_block_size;
        size -= fb_block_size;
        num_blocks += 1;
        fb->version += 1;
    }
    Modification* mod = bhex_malloc(sizeof(Modification));
    mod->type         = MOD_TYPE_DELETE;
    mod->chain_n      = num_blocks;
    mod->data         = NULL;
    mod->off          = fb->off;
    mod->end          = fb->size;
    mod->size         = size;
    ll_add(&fb->modifications, (uptr_t)mod);

    fb->size -= size;
    fb->block_dirty = 1;
    fb->version += 1;
    r = 1;

end:
    fb_unlock(fb);
    return r;
}

int fb_undo_last(FileBuffer* fb)
{
    int r = 0;
    fb_lock(fb);
    fb_invalidate_cache(fb);

    ll_node_t* n = ll_pop(&fb->modifications);
    if (!n)
        goto end;

    Modification* mod = (Modification*)n->data;
    if (mod->type == MOD_TYPE_INSERT) {
        fb->size -= mod->size;
        if (fb->off >= fb->size)
            fb_seek(fb, 0);
    } else if (mod->type == MOD_TYPE_DELETE) {
        fb->size += mod->size;
    }

    while (mod->chain_n-- > 0)
        // This is the case for a "splitted" delete
        fb_undo_last(fb);

    delete_modification(n->data);
    bhex_free(n);
    fb->block_dirty = 1;
    fb->version -= 1;
    r = 1;

end:
    fb_unlock(fb);
    return r;
}

void fb_undo_all(FileBuffer* fb)
{
    fb_lock(fb);
    while (fb_undo_last(fb))
        ;
    fb_unlock(fb);
}

static int commit_write(FileBuffer* fb, Modification* mod)
{
    if (mod->type != MOD_TYPE_OVERWRITE)
        panic("commit_write(): invalid type %d", mod->type);

    if (fseek(fb->file, mod->off, SEEK_SET) < 0) {
        error("commit_write(): fseek failed");
        return 0;
    }
    if (fwrite(mod->data, 1, mod->size, fb->file) != mod->size) {
        error("commit_write(): fwrite failed");
        return 0;
    }
    return 1;
}

static int commit_insert(FileBuffer* fb, Modification* mod)
{
    if (mod->type != MOD_TYPE_INSERT)
        panic("commit_insert(): invalid type %d", mod->type);

    if (fseek(fb->file, 0, SEEK_END) < 0) {
        error("commit_insert(): fseek failed");
        return 0;
    }
    if (fwrite(mod->data, 1, mod->size, fb->file) != mod->size) {
        error("commit_insert(): fwrite failed");
        return 0;
    }
    ssize_t fsize = ftell(fb->file);
    if (fsize < 0) {
        error("commit_insert(): ftell failed");
        return 0;
    }

    s64_t off =
        max((s64_t)mod->off, (s64_t)(fsize - fb_block_size - mod->size));
    s64_t size = min(fb_block_size, fsize - off - mod->size);
    while (1) {
        if (size == 0)
            break;
        if (fseek(fb->file, off, SEEK_SET) < 0) {
            error("commit_insert(): fseek failed [off: %llu]", off);
            return 0;
        }
        if (fread(fb->tmp_block, 1, size, fb->file) != size) {
            error("commit_insert(): fread failed");
            return 0;
        }
        if (fseek(fb->file, off + mod->size, SEEK_SET) < 0) {
            error("commit_insert(): fseek failed [off: %llu]", off + mod->size);
            return 0;
        }
        if (fwrite(fb->tmp_block, 1, size, fb->file) != size) {
            error("commit_insert(): fwrite failed");
            return 0;
        }

        s64_t n_off = max((s64_t)mod->off, off - fb_block_size);
        if (off == n_off)
            break;
        size = off - n_off;
        off  = n_off;
    }

    if (fseek(fb->file, mod->off, SEEK_SET) < 0) {
        error("commit_insert(): fseek failed [off: %llu]", mod->off);
        return 0;
    }
    if (fwrite(mod->data, 1, mod->size, fb->file) != mod->size) {
        error("commit_insert(): fwrite failed");
        return 0;
    }

    return 1;
}

static int commit_delete(FileBuffer* fb, Modification* mod)
{
    if (mod->type != MOD_TYPE_DELETE)
        panic("commit_delete(): invalid type %d", mod->type);

    if (fseek(fb->file, 0, SEEK_END) < 0) {
        error("commit_delete(): fseek failed");
        return 0;
    }
    ssize_t fsize = ftell(fb->file);
    if (fsize < 0) {
        error("commit_delete(): ftell failed");
        return 0;
    }

    s64_t off  = mod->off + mod->size;
    s64_t size = min(fb_block_size, fsize - off);
    while (1) {
        if (fseek(fb->file, off, SEEK_SET) < 0) {
            error("commit_delete(): fseek failed [off: %llu]", off);
            return 0;
        }
        if (fread(fb->tmp_block, 1, size, fb->file) != size) {
            error("commit_delete(): fread failed");
            return 0;
        }
        if (fseek(fb->file, off - mod->size, SEEK_SET) < 0) {
            error("commit_delete(): fseek failed [off: %llu]", off - mod->size);
            return 0;
        }
        if (fwrite(fb->tmp_block, 1, size, fb->file) != size) {
            error("commit_delete(): fwrite failed");
            return 0;
        }

        s64_t n_off = off + size;
        if (n_off >= fsize)
            break;
        off  = n_off;
        size = min(fb_block_size, fsize - off);
    }

    if (ftruncate(fileno(fb->file), fsize - mod->size) < 0) {
        error("commit_delete(): ftruncate failed");
        return 0;
    }
    return 1;
}

void fb_commit(FileBuffer* fb)
{
    fb_lock(fb);
    fb_invalidate_cache(fb);
    fb_modified_check(fb);
    if (fb->readonly) {
        error("cannot commit, the file was opened in read-only mode");
        fb_unlock(fb);
        return;
    }

    u64_t origin_off = fb->off;

    ll_invert(&fb->modifications);

    int        r;
    ll_node_t* curr = fb->modifications.head;
    while (curr) {
        Modification* mod = (Modification*)curr->data;
        switch (mod->type) {
            case MOD_TYPE_OVERWRITE:
                r = commit_write(fb, mod);
                break;
            case MOD_TYPE_INSERT:
                r = commit_insert(fb, mod);
                break;
            case MOD_TYPE_DELETE:
                r = commit_delete(fb, mod);
                break;
            default:
                panic("unknown modification type: %d", mod->type);
                break;
        }
        if (!r)
            break;
        curr = curr->next;
    }
    if (!r) {
        error("something went wrong while committing the file. Probably the "
              "output file is broken. I'll try to reload it");
        fb->version += 1 + fb->modifications.size;
        if (!fb_reload(fb))
            panic("unable to reload the file");
        fb_unlock(fb);
        return;
    }

    ll_clear(&fb->modifications, delete_modification);

    fflush(fb->file);
    fb_seek(fb, origin_off);
    was_file_modified(fb->path, 0, &fb->mod_time);
    fb_unlock(fb);
}

static int overlaps(u64_t startA, u64_t endA, u64_t startB, u64_t endB)
{
    // Check if [startA, endA) overlaps with [startB, endB)
    return startA <= endB && endA > startB;
}

static int fb_read_internal(FileBuffer* fb, u64_t addr, u64_t fsize, u64_t idx,
                            int nmod, s8_t* block_map)
{
    size_t size = min(fb_block_size - idx, fsize - addr);

    int        n    = 0;
    ll_node_t* curr = fb->modifications.head;
    while (curr && n < nmod) {
        curr = curr->next;
        n += 1;
    }
    if (n != nmod)
        panic("fb_read_internal(): invalid value of nmod");

    while (curr) {
        Modification* mod = (Modification*)curr->data;
        if (overlaps(mod->off, mod->end, addr, addr + size)) {
            // The modification overlaps
            u64_t start = max(mod->off, addr);
            u64_t end   = min(mod->end, addr + size);
            u64_t off;
            for (off = start; off < end; ++off) {
                if (block_map[off - addr + idx])
                    continue;

                if (mod->type == MOD_TYPE_OVERWRITE) {
                    // Modify the block according to the modification
                    fb->block[off - addr + idx] = mod->data[off - mod->off];
                    block_map[off - addr + idx] = 1;
                } else if (mod->type == MOD_TYPE_INSERT) {
                    if (off < mod->off + mod->size) {
                        // Get the data from the insertion
                        fb->block[off - addr + idx] = mod->data[off - mod->off];
                        block_map[off - addr + idx] = 1;
                    } else {
                        // To get the data past the insertion, read starting
                        // from the *next* modification with a shift equal to
                        // the size of the insertion
                        u64_t n_addr = off - mod->size;
                        u64_t n_size = fsize - mod->size;
                        u64_t n_idx  = off - addr + idx;
                        fb_read_internal(fb, n_addr, n_size, n_idx, n + 1,
                                         block_map);
                        u64_t i;
                        for (i = n_idx; i < size; ++i)
                            block_map[i] = 1;
                        break;
                    }
                } else if (mod->type == MOD_TYPE_DELETE) {
                    // Get the data by reading with a shift equal to the number
                    // of bytes deleted
                    u64_t n_addr = off + mod->size;
                    u64_t n_size = fsize + mod->size;
                    u64_t n_idx  = off - addr + idx;
                    fb_read_internal(fb, n_addr, n_size, n_idx, n + 1,
                                     block_map);
                    u64_t i;
                    for (i = n_idx; i < size; ++i)
                        block_map[i] = 1;
                    break;
                }
            }
        }
        if (size == 0)
            break;

        curr = curr->next;
        n += 1;
    }

    u64_t i;
    int   should_read = 0;
    for (i = 0; i < size; ++i) {
        if (i + idx >= fsize)
            break;
        if (!block_map[i + idx]) {
            should_read = 1;
            break;
        }
    }
    if (size == 0 || !should_read)
        return 1;

    // We have to read the file
    if (fseek(fb->file, addr, SEEK_SET) < 0) {
        error("fseek failed @ 0x%llx", addr);
        return 0;
    }
    size_t read_size = fread(fb->tmp_block, 1, size, fb->file);
    for (i = 0; i < read_size; ++i) {
        if (block_map[i + idx])
            continue;
        fb->block[i + idx] = fb->tmp_block[i];
        block_map[i + idx] = 1;
    }
    return 1;
}

static size_t fb_get_effective_size(FileBuffer* fb, u32_t mod_idx)
{
    size_t fsize = fb->size;
    if (mod_idx != 0) {
        fb->block_dirty = 1;
        u32_t      nmod = 0;
        ll_node_t* curr = fb->modifications.head;
        while (curr && nmod < mod_idx) {
            Modification* mod = (Modification*)curr->data;
            switch (mod->type) {
                case MOD_TYPE_DELETE:
                    fsize += mod->size;
                    break;
                case MOD_TYPE_INSERT:
                    fsize -= mod->size;
                    break;
            }
            curr = curr->next;
            nmod += 1;
        }
    }
    return fsize;
}

const u8_t* fb_read_ex(FileBuffer* fb, size_t size, u32_t mod_idx)
{
    const u8_t* result = NULL;
    fb_lock(fb);

    if (mod_idx > fb->modifications.size)
        goto end;

    if (size > fb_block_size) {
        // FIXME: this case could be useful, maybe implement it using a dynamic
        //        buffer
        error("you cannot read more than %lu bytes", fb_block_size);
        goto end;
    }

    // Fast path: the requested range is already in `block` and nothing has
    // changed since it was loaded. This avoids a stat() + fseek() + fread() per
    // read, which is the dominant cost when a template reads many small fields.
    // External-modification detection still happens on every cache miss (i.e.
    // at least once per loaded window), preserving the best-effort guarantee.
    if (mod_idx == 0 && fb->cache_valid && fb->cache_version == fb->version &&
        fb->off >= fb->cache_off &&
        fb->off + size <= fb->cache_off + fb->cache_len) {
        result = (const u8_t*)fb->block + (fb->off - fb->cache_off);
        goto end;
    }

    fb_modified_check(fb);

    size_t fsize = fb_get_effective_size(fb, mod_idx);
    if (size + fb->off > fsize) {
        error("too many bytes to read: %lu", size);
        goto end;
    }

    s8_t block_map[fb_block_size] = {0};
    if (!fb_read_internal(fb, fb->off, fsize, 0, mod_idx, block_map)) {
        error("something went wrong while reading the file. Reloading it");
        fb->version += 1 + fb->modifications.size;
        if (!fb_reload(fb))
            panic("unable to reload the file");
    }
    fb->block_dirty = 0;
    if (mod_idx == 0) {
        // Record the loaded window so subsequent reads can hit the fast path.
        fb->cache_valid   = 1;
        fb->cache_off     = fb->off;
        fb->cache_len     = min(fb_block_size, fsize - fb->off);
        fb->cache_version = fb->version;
    } else {
        // The block now holds an alternative (modification-shifted) view; it no
        // longer reflects the committed file, so the normal cache is invalid.
        fb->cache_valid = 0;
    }
    result = (const u8_t*)fb->block;

end:
    fb_unlock(fb);
    return result;
}

const u8_t* fb_read(FileBuffer* fb, size_t size)
{
    return fb_read_ex(fb, size, 0);
}

u8_t* fb_read_alloc_ex(FileBuffer* fb, u64_t off, size_t size, u32_t mod_idx)
{
    u8_t* result = NULL;
    fb_lock(fb);

    if (mod_idx > fb->modifications.size)
        goto end;

    fb_modified_check(fb);
    size_t fsize = fb_get_effective_size(fb, mod_idx);
    if (off > fsize || size > fsize - off) {
        error("too many bytes to read: %lu", size);
        goto end;
    }

    if (size == 0) {
        result = bhex_calloc(1);
        goto end;
    }

    result         = bhex_malloc(size);
    u64_t orig_off = fb->off;
    u64_t copied   = 0;
    while (copied < size) {
        size_t chunk = min((u64_t)fb_block_size, size - copied);
        fb_seek(fb, off + copied);
        const u8_t* block = fb_read_ex(fb, chunk, mod_idx);
        if (block == NULL) {
            bhex_free(result);
            result = NULL;
            break;
        }
        memcpy(result + copied, block, chunk);
        copied += chunk;
    }
    fb_seek(fb, orig_off);

end:
    fb_unlock(fb);
    return result;
}

u8_t* fb_read_alloc(FileBuffer* fb, u64_t off, size_t size)
{
    return fb_read_alloc_ex(fb, off, size, 0);
}

void filebuffer_destroy(FileBuffer* fb)
{
    fclose(fb->file);
    ll_clear(&fb->modifications, delete_modification);

    pthread_mutex_destroy(&fb->lock);
    bhex_free(fb->search_index);
    bhex_free(fb->path);
    bhex_free(fb);
}

void fb_reader_init(FbReader* reader, FileBuffer* fb)
{
    reader->fb = fb;
    reader->fd = -1;

    fb_lock(fb);
    int has_mods = fb->modifications.size != 0;
    fb_unlock(fb);

    // With pending modifications the on-disk bytes do not match the logical
    // view, so we must go through the (locked) modification-aware read path.
    if (!has_mods)
        reader->fd = open(fb->path, O_RDONLY);
}

void fb_reader_deinit(FbReader* reader)
{
    if (reader->fd >= 0) {
        close(reader->fd);
        reader->fd = -1;
    }
}

int fb_reader_read(FbReader* reader, u64_t off, u8_t* out, size_t size)
{
    if (reader->fd >= 0) {
        // A modification may have been added since init (e.g. by a search
        // callback). The check is a brief uncontended lock, negligible next
        // to the pread() it guards; if it trips, demote the reader to the
        // locked modification-aware path for the rest of its lifetime.
        fb_lock(reader->fb);
        int has_mods = reader->fb->modifications.size != 0;
        fb_unlock(reader->fb);
        if (has_mods)
            fb_reader_deinit(reader);
    }

    if (reader->fd >= 0) {
        size_t done = 0;
        while (done < size) {
            ssize_t n =
                pread(reader->fd, out + done, size - done, (off_t)(off + done));
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                return 0;
            done += (size_t)n;
        }
        return 1;
    }

    u8_t* chunk = fb_read_alloc(reader->fb, off, size);
    if (chunk == NULL)
        return 0;
    memcpy(out, chunk, size);
    bhex_free(chunk);
    return 1;
}

static inline BlockInfo* get_block_at(SearchIndex* ctx, u64_t addr)
{
    u64_t off = addr / ctx->block_size;
    if (off >= fb_index_size)
        panic("invalid address");
    return &ctx->blocks[off];
}

typedef struct {
    FileBuffer*    fb;
    const u8_t*    data;
    size_t         data_size;
    u64_t          start;
    u64_t          end;
    fb_search_cb_t cb;
    void*          user_data;
    volatile int*  stop;
} SearchTask;

static void* search_worker(void* arg)
{
    SearchTask* task = (SearchTask*)arg;

    FbReader reader;
    fb_reader_init(&reader, task->fb);

    u8_t data_min = task->data[0];
    u8_t data_max = task->data[0];
    for (size_t i = 1; i < task->data_size; ++i) {
        if (task->data[i] < data_min)
            data_min = task->data[i];
        if (task->data[i] > data_max)
            data_max = task->data[i];
    }

    size_t buf_size = max(task->data_size * 2, fb_block_size * 2);
    u8_t*  buf      = bhex_malloc(buf_size);
    size_t buf_off  = 0;
    size_t buf_end  = 0;

    SearchIndex* ctx  = task->fb->search_index;
    u64_t        addr = task->start;

    while (addr + task->data_size <= task->end && !*task->stop) {
        if (ctx->has_index) {
            BlockInfo* binfo = get_block_at(ctx, addr);
            if (!(binfo->min <= data_min && data_max <= binfo->max)) {
                addr = (addr / ctx->block_size) * ctx->block_size +
                       ctx->block_size;
                buf_off = 0;
                buf_end = 0;
                continue;
            }
        }

        if (buf_off + task->data_size > buf_end) {
            size_t to_read = min((u64_t)buf_size, task->end - addr);
            if (!fb_reader_read(&reader, addr, buf, to_read))
                break;
            buf_off = 0;
            buf_end = to_read;
        }

        int match = 1;
        for (size_t j = 0; j < task->data_size; ++j) {
            if (task->data[j] != buf[buf_off + j]) {
                match = 0;
                break;
            }
        }

        if (match) {
            fb_lock(task->fb);
            if (!task->cb(task->fb, addr, task->data, task->data_size,
                          task->user_data))
                *task->stop = 1;
            fb_unlock(task->fb);
        }

        addr += 1;
        buf_off += 1;
    }

    bhex_free(buf);
    fb_reader_deinit(&reader);
    return NULL;
}

static void split_work(size_t total, int parts, int idx, size_t* begin,
                       size_t* end)
{
    size_t base = total / (size_t)parts;
    size_t rem  = total % (size_t)parts;

    *begin = (size_t)idx * base + min((size_t)idx, rem);
    *end   = *begin + base + ((size_t)idx < rem ? 1 : 0);
}

typedef struct {
    FileBuffer* fb;
    u64_t       block_size;
    u64_t       file_size;
    int         block_begin; // inclusive
    int         block_end;   // exclusive
    BlockInfo*  blocks;
} IndexTask;

// Computes the [min, max] byte value for a disjoint range of index blocks.
// Block 'b' covers the file range [b * block_size, min((b+1) * block_size,
// file_size)); this is provably equivalent to the sequential block assignment
// (including the trailing block that absorbs the remainder of the file).
static void* index_worker(void* arg)
{
    IndexTask* task = (IndexTask*)arg;

    FbReader reader;
    fb_reader_init(&reader, task->fb);
    u8_t* buf = bhex_malloc(fb_block_size);

    for (int b = task->block_begin; b < task->block_end; ++b) {
        u8_t  bmin  = 255;
        u8_t  bmax  = 0;
        u64_t start = (u64_t)b * task->block_size;
        if (start < task->file_size) {
            u64_t end  = min(start + task->block_size, task->file_size);
            u64_t addr = start;
            while (addr < end) {
                size_t chunk = min((u64_t)fb_block_size, end - addr);
                if (!fb_reader_read(&reader, addr, buf, chunk))
                    break;
                for (size_t i = 0; i < chunk; ++i) {
                    if (buf[i] < bmin)
                        bmin = buf[i];
                    if (buf[i] > bmax)
                        bmax = buf[i];
                }
                addr += chunk;
            }
        }
        task->blocks[b].min = bmin;
        task->blocks[b].max = bmax;
    }

    bhex_free(buf);
    fb_reader_deinit(&reader);
    return NULL;
}

static void populate_index(FileBuffer* fb, int nthreads)
{
    SearchIndex* ctx = fb->search_index;

    fb_lock(fb);
    if (ctx->has_index && (ctx->version == fb->version)) {
        fb_unlock(fb);
        return;
    }

    ctx->version = fb->version;
    if (fb->size < fb_index_size * 8) {
        // if the file size is not big enough, it makes
        // no sense to keep the index
        ctx->has_index = 0;
        fb_unlock(fb);
        return;
    }
    ctx->has_index  = 1;
    ctx->block_size = fb->size / fb_index_size + 1;
    u64_t file_size = fb->size;
    // Release the lock before spawning workers: fb_read_alloc() locks the
    // (recursive) mutex itself, so holding it here would deadlock the workers.
    fb_unlock(fb);

    if (nthreads < 1)
        nthreads = 1;
    // No point in spawning more workers than there are blocks to index.
    else if (nthreads > fb_index_size)
        nthreads = fb_index_size;

    if (nthreads == 1) {
        IndexTask task = {
            .fb          = fb,
            .block_size  = ctx->block_size,
            .file_size   = file_size,
            .block_begin = 0,
            .block_end   = fb_index_size,
            .blocks      = ctx->blocks,
        };
        index_worker(&task);
        return;
    }

    pthread_t* threads = bhex_malloc(sizeof(pthread_t) * (size_t)nthreads);
    IndexTask* tasks   = bhex_malloc(sizeof(IndexTask) * (size_t)nthreads);

    for (int t = 0; t < nthreads; ++t) {
        size_t begin, end;
        split_work(fb_index_size, nthreads, t, &begin, &end);

        tasks[t].fb          = fb;
        tasks[t].block_size  = ctx->block_size;
        tasks[t].file_size   = file_size;
        tasks[t].block_begin = (int)begin;
        tasks[t].block_end   = (int)end;
        tasks[t].blocks      = ctx->blocks;

        if (pthread_create(&threads[t], NULL, index_worker, &tasks[t]) != 0)
            panic("pthread_create failed");
    }

    for (int t = 0; t < nthreads; ++t)
        pthread_join(threads[t], NULL);

    bhex_free(threads);
    bhex_free(tasks);
}

__attribute__((unused)) static void print_block_info(FileBuffer* fb)
{
    SearchIndex* ctx = fb->search_index;
    populate_index(fb, 1);
    if (!ctx->has_index) {
        warning("file is too short, no blocks info");
        return;
    }

    size_t i;
    for (i = 0; i < fb_index_size; ++i) {
        BlockInfo* binfo    = &ctx->blocks[i];
        u64_t      min_addr = i * ctx->block_size;
        u64_t      max_addr = i == fb_index_size - 1
                                  ? (fb->size - 1)
                                  : (min_addr + ctx->block_size - 1);
        info(" 0x%08llx - 0x%08llx : [min %3u, max %3u]\n", min_addr, max_addr,
             binfo->min, binfo->max);
    }
}

void fb_search(FileBuffer* fb, const u8_t* data, size_t size, fb_search_cb_t cb,
               void* user_data, int nthreads)
{
    if (size == 0)
        return;

    if (nthreads < 1)
        nthreads = 1;

    populate_index(fb, nthreads);

    fb_lock(fb);
    u64_t orig_off  = fb->off;
    u64_t file_size = fb->size;
    fb_unlock(fb);

    if (file_size < size)
        return;

    // Number of candidate start positions to scan.
    u64_t total = file_size - size + 1;
    if ((u64_t)nthreads > total)
        nthreads = (int)total;

    volatile int stop    = 0;
    pthread_t*   threads = bhex_malloc(sizeof(pthread_t) * (size_t)nthreads);
    SearchTask*  tasks   = bhex_malloc(sizeof(SearchTask) * (size_t)nthreads);

    for (int t = 0; t < nthreads; ++t) {
        size_t begin, end;
        split_work(total, nthreads, t, &begin, &end);
        // Extend the range so a pattern straddling the split is still found.
        end += (size - 1);

        tasks[t].fb        = fb;
        tasks[t].data      = data;
        tasks[t].data_size = size;
        tasks[t].start     = (u64_t)begin;
        tasks[t].end       = (u64_t)end;
        tasks[t].cb        = cb;
        tasks[t].user_data = user_data;
        tasks[t].stop      = &stop;
    }

    if (nthreads == 1) {
        // Run in the calling thread: matches are reported in ascending order.
        search_worker(&tasks[0]);
    } else {
        for (int t = 0; t < nthreads; ++t)
            if (pthread_create(&threads[t], NULL, search_worker, &tasks[t]) !=
                0)
                panic("pthread_create failed");
        for (int t = 0; t < nthreads; ++t)
            pthread_join(threads[t], NULL);
    }

    bhex_free(threads);
    bhex_free(tasks);
    fb_seek(fb, orig_off);
}
