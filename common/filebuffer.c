#include "defs.h"
#include <filebuffer.h>

#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <alloc.h>
#include <log.h>

#define MOD_TYPE_OVERWRITE 1
#define MOD_TYPE_INSERT    2
#define MOD_TYPE_DELETE    3

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))

static u8_t tmp_block[fb_block_size];

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
    if (off > fb->size)
        return 1;

    fb->off         = off;
    fb->block_dirty = 1;
    return 0;
}

FileBuffer* filebuffer_create(const char* path, int readonly)
{
    FileBuffer* fb    = bhex_malloc(sizeof(FileBuffer));
    fb->path          = bhex_strdup(path);
    fb->readonly      = readonly;
    fb->modifications = ll_create();
    fb->block_dirty   = 1;
    fb->version       = 0;
    fb->search_index  = bhex_calloc(sizeof(SearchIndex));

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
    fb_modified_check(fb);
    if (fb->readonly)
        warning("the file was opened in read-only mode, you cannot commit this "
                "modification");

    if (fb->off + size > fb->size) {
        error("not enough space to write the data");
        return 0;
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
    return 1;
}

int fb_insert(FileBuffer* fb, u8_t* data, size_t size)
{
    fb_modified_check(fb);
    if (fb->readonly)
        warning("the file was opened in read-only mode, you cannot commit this "
                "modification");

    if (size > fb_block_size) {
        error("cannot insert more than %lu bytes", fb_block_size);
        return 0;
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
    return 1;
}

int fb_delete(FileBuffer* fb, size_t size)
{
    fb_modified_check(fb);
    if (fb->readonly)
        warning("the file was opened in read-only mode, you cannot commit this "
                "modification");

    if (fb->size - fb->off < size) {
        error("not enough data to delete");
        return 0;
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
    return 1;
}

int fb_undo_last(FileBuffer* fb)
{
    ll_node_t* n = ll_pop(&fb->modifications);
    if (!n)
        return 0;

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
    return 1;
}

void fb_undo_all(FileBuffer* fb)
{
    while (fb_undo_last(fb))
        ;
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
        if (fread(tmp_block, 1, size, fb->file) != size) {
            error("commit_insert(): fread failed");
            return 0;
        }
        if (fseek(fb->file, off + mod->size, SEEK_SET) < 0) {
            error("commit_insert(): fseek failed [off: %llu]", off + mod->size);
            return 0;
        }
        if (fwrite(tmp_block, 1, size, fb->file) != size) {
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
        if (fread(tmp_block, 1, size, fb->file) != size) {
            error("commit_delete(): fread failed");
            return 0;
        }
        if (fseek(fb->file, off - mod->size, SEEK_SET) < 0) {
            error("commit_delete(): fseek failed [off: %llu]", off - mod->size);
            return 0;
        }
        if (fwrite(tmp_block, 1, size, fb->file) != size) {
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
    fb_modified_check(fb);
    if (fb->readonly) {
        error("cannot commit, the file was opened in read-only mode");
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
        return;
    }

    ll_clear(&fb->modifications, delete_modification);

    fflush(fb->file);
    fb_seek(fb, origin_off);
    was_file_modified(fb->path, 0, &fb->mod_time);
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
    size_t read_size = fread(tmp_block, 1, size, fb->file);
    for (i = 0; i < read_size; ++i) {
        if (block_map[i + idx])
            continue;
        fb->block[i + idx] = tmp_block[i];
        block_map[i + idx] = 1;
    }
    return 1;
}

const u8_t* fb_read_ex(FileBuffer* fb, size_t size, u32_t mod_idx)
{
    if (mod_idx > fb->modifications.size)
        return NULL;

    fb_modified_check(fb);
    if (size > fb_block_size) {
        // FIXME: this case could be useful, maybe implement it using a dynamic
        //        buffer
        error("you cannot read more than %lu bytes", fb_block_size);
        return NULL;
    }

    size_t fsize = fb->size;
    if (mod_idx != 0) {
        fb->block_dirty = 1;
        // we should adjust fsize according to the skipped modifications
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

    if (size + fb->off > fsize) {
        error("too many bytes to read: %lu", size);
        return NULL;
    }

    if (fb->block_dirty) {
        s8_t block_map[fb_block_size] = {0};
        if (!fb_read_internal(fb, fb->off, fsize, 0, mod_idx, block_map)) {
            error("something went wrong while reading the file. Reloading it");
            fb->version += 1 + fb->modifications.size;
            if (!fb_reload(fb))
                panic("unable to reload the file");
        }
    }
    if (mod_idx == 0)
        fb->block_dirty = 0;
    return (const u8_t*)fb->block;
}

const u8_t* fb_read(FileBuffer* fb, size_t size)
{
    return fb_read_ex(fb, size, 0);
}

void filebuffer_destroy(FileBuffer* fb)
{
    fclose(fb->file);
    ll_clear(&fb->modifications, delete_modification);

    bhex_free(fb->search_index);
    bhex_free(fb->path);
    bhex_free(fb);
}

static void populate_index(FileBuffer* fb)
{
#define is_within_block(block_n, block_off, block_size)                        \
    ((((block_n) < fb_index_size - 1) && ((block_off) < (block_size))) ||      \
     ((block_n) == fb_index_size - 1))

    SearchIndex* ctx = fb->search_index;
    if (ctx->has_index && (ctx->version == fb->version))
        return;

    ctx->version = fb->version;
    if (fb->size < fb_index_size * 8) {
        // if the file size is not big enough, it makes
        // no sense to keep the index
        ctx->has_index = 0;
        return;
    }
    ctx->has_index = 1;

    u64_t orig_off = fb->off;
    fb_seek(fb, 0);

    u32_t block_n      = 0;
    u32_t block_off    = 0;
    ctx->blocks[0].min = 255;
    ctx->blocks[0].max = 0;
    ctx->block_size    = fb->size / fb_index_size + 1;

    u64_t addr = 0;
    while (addr < fb->size) {
        fb_seek(fb, addr);
        const u8_t* block = fb_read(fb, min(fb_block_size, fb->size - fb->off));
        u32_t       i;
        for (i = 0; i < min(fb_block_size, fb->size - fb->off); i++) {
            if (!is_within_block(block_n, block_off, ctx->block_size)) {
                block_n += 1;
                block_off = 0;

                ctx->blocks[block_n].min = 255;
                ctx->blocks[block_n].max = 0;
            }
            if (block[i] < ctx->blocks[block_n].min)
                ctx->blocks[block_n].min = block[i];
            if (block[i] > ctx->blocks[block_n].max)
                ctx->blocks[block_n].max = block[i];
            block_off += 1;
        }
        addr += min(fb_block_size, fb->size - fb->off);
    }
    fb_seek(fb, orig_off);
}

__attribute__((unused)) static void print_block_info(FileBuffer* fb)
{
    SearchIndex* ctx = fb->search_index;
    populate_index(fb);
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

static inline BlockInfo* get_block_at(SearchIndex* ctx, u64_t addr)
{
    u64_t off = addr / ctx->block_size;
    if (off >= fb_index_size)
        panic("invalid address");
    return &ctx->blocks[off];
}

void fb_search(FileBuffer* fb, const u8_t* data, size_t size, fb_search_cb_t cb,
               void* user_data)
{
    if (size == 0)
        return;
    populate_index(fb);

    u64_t orig_off = fb->off;
    fb_seek(fb, 0);

    size_t buf_off  = 0;
    size_t buf_size = max(size * 2, fb_block_size * 2);
    u8_t*  buf      = bhex_malloc(buf_size);

    memcpy(buf, fb_read(fb, min(buf_size / 2, fb->size)),
           min(buf_size / 2, fb->size));

    u8_t   data_min = data[0];
    u8_t   data_max = data[0];
    size_t i;
    for (i = 1; i < size; ++i) {
        if (data[i] < data_min)
            data_min = data[i];
        if (data[i] > data_max)
            data_max = data[i];
    }

    SearchIndex* ctx  = fb->search_index;
    u64_t        addr = 0;
    while (addr + size <= fb->size) {
        if (ctx->has_index) {
            BlockInfo* binfo = get_block_at(ctx, addr);
            if (!(binfo->min <= data_min && data_max <= binfo->max)) {
                // skip a block
                addr = (addr / ctx->block_size) * ctx->block_size +
                       ctx->block_size;
                buf_off = 0;
                continue;
            }
        }
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
        if (eq && !cb(fb, begin_addr, data, size, user_data))
            break;

        addr += 1;
        buf_off += 1;
    }

    bhex_free(buf);
    fb_seek(fb, orig_off);
}
