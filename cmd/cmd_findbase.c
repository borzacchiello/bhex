// Copyright (c) 2022-2026, bageyelet
// Based on Binbloom by Quarkslab (https://github.com/quarkslab/binbloom)
/*
   Copyright 2020 G. Heilles
   Copyright 2020 Quarkslab

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "cmd_findbase.h"

#include "cmd.h"
#include "cmd_arg_handler.h"

#include <alloc.h>
#include <display.h>
#include <dlist.h>
#include <filebuffer.h>
#include <log.h>
#include <util/endian.h>
#include <util/math.h>

#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HINT_STR "[/{32,64}/{le,be}]"

#define FINDBASE_MIN_STRING_LEN         8
#define FINDBASE_ARRAY_MIN_ITEMS        10
#define FINDBASE_PAGE_SIZE              0x1000ull
#define FINDBASE_PAGE_MASK              (FINDBASE_PAGE_SIZE - 1)
#define FINDBASE_MAX_CANDIDATES         30
#define FINDBASE_SCAN_CHUNK             (256 * 1024ull)
#define FINDBASE_MEMORY_REGION_MIN_SIZE 1024ull

#define min(x, y) ((x) < (y) ? (x) : (y))

typedef enum {
    FINDBASE_ARCH_32 = 32,
    FINDBASE_ARCH_64 = 64,
} FindbaseArch;

typedef enum {
    FINDBASE_ENDIAN_UNKNOWN = 0,
    FINDBASE_ENDIAN_LE,
    FINDBASE_ENDIAN_BE,
} FindbaseEndian;

typedef enum {
    FINDBASE_POI_STRING = 0,
    FINDBASE_POI_ARRAY,
} FindbasePoiType;

typedef struct {
    u64_t           offset;
    u32_t           count;
    FindbasePoiType type;
} FindbasePoi;

typedef DList PoiVec;

typedef struct FindbaseAddrNode {
    int                      votes;
    int                      leaf;
    struct FindbaseAddrNode* subs[256];
} FindbaseAddrNode;

typedef struct {
    u64_t address;
    int   votes;
    u64_t score;
    u32_t pointer_count;
    u32_t array_score;
    int   has_valid_array;
} FindbaseCandidate;

typedef DList CandidateVec;
typedef DList IndexVec;

typedef struct {
    u64_t address;
    int   votes;
} CandidateLeaf;

typedef DList CandidateLeafVec;

typedef struct {
    FileBuffer*  fb;
    u64_t        file_size;
    u64_t        start;
    u64_t        end;
    FindbaseArch arch;
    u32_t*       hist_le;
    u32_t*       hist_be;
} EndianTask;

typedef enum {
    FINDBASE_REGION_UNKNOWN = 0,
    FINDBASE_REGION_CODE,
    FINDBASE_REGION_INIT_DATA,
    FINDBASE_REGION_UNINIT_DATA,
} FindbaseRegionType;

typedef struct {
    size_t count;
    u8_t*  block_types;
} FindbaseMemMap;

typedef struct {
    FileBuffer*           fb;
    u64_t                 file_size;
    u64_t                 start;
    u64_t                 end;
    FindbaseArch          arch;
    FindbaseEndian        endian;
    const FindbaseMemMap* memmap;
    CandidateVec*         candidates;
    size_t                candidate_count;
    u32_t*                local_counts;
} PointerCountTask;

static int findbase_pointer_size(FindbaseArch arch)
{
    return arch == FINDBASE_ARCH_64 ? 8 : 4;
}

static u64_t findbase_max_address(FindbaseArch arch)
{
    return arch == FINDBASE_ARCH_64 ? ~(u64_t)0 : 0xFFFFFFFFull;
}

static const char* findbase_endian_to_string(FindbaseEndian endian)
{
    switch (endian) {
        case FINDBASE_ENDIAN_LE:
            return "LE";
        case FINDBASE_ENDIAN_BE:
            return "BE";
        default:
            return "unknown";
    }
}

static int is_printable_ascii_byte(u8_t v) { return v >= 0x20 && v <= 0x7E; }

static int is_ascii_ptr_byte(u8_t v) { return v >= 0x20 && v <= 0x7F; }

static int is_ascii_ptr(u64_t value, FindbaseArch arch)
{
    int n = findbase_pointer_size(arch);
    for (int i = 0; i < n; ++i) {
        if (!is_ascii_ptr_byte((u8_t)(value & 0xFF)))
            return 0;
        value >>= 8;
    }
    return 1;
}

static u64_t read_ptr(const u8_t* data, size_t offset, FindbaseArch arch,
                      FindbaseEndian endian)
{
    if (arch == FINDBASE_ARCH_64) {
        return endian == FINDBASE_ENDIAN_BE ? read_at_be64(data, offset)
                                            : read_at_le64(data, offset);
    }
    return endian == FINDBASE_ENDIAN_BE ? read_at_be32(data, offset)
                                        : read_at_le32(data, offset);
}

static int findbase_array_delta_within_page(u64_t value, u64_t prev)
{
    int diff = (int)(value - prev);
    if (diff < 0)
        diff = -diff;
    return diff <= (int)FINDBASE_PAGE_SIZE;
}

static int base_can_fit_file(u64_t base, u64_t size, FindbaseArch arch)
{
    if (size == 0)
        return 0;
    return base <= findbase_max_address(arch) - (size - 1);
}

static int default_thread_count(size_t work_units)
{
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 1)
        ncpu = 1;
    if (work_units > 0 && (size_t)ncpu > work_units)
        ncpu = (long)work_units;
    if (ncpu < 1)
        ncpu = 1;
    return (int)ncpu;
}

static void split_work(size_t total, int parts, int idx, size_t* begin,
                       size_t* end)
{
    size_t base = total / (size_t)parts;
    size_t rem  = total % (size_t)parts;

    *begin = (size_t)idx * base + min((size_t)idx, rem);
    *end   = *begin + base + ((size_t)idx < rem ? 1 : 0);
}

static FindbasePoi* findbase_poi_new(u64_t offset, u32_t count,
                                     FindbasePoiType type)
{
    FindbasePoi* poi = bhex_malloc(sizeof(FindbasePoi));
    poi->offset      = offset;
    poi->count       = count;
    poi->type        = type;
    return poi;
}

static FindbaseCandidate* findbase_candidate_new(u64_t address, int votes)
{
    FindbaseCandidate* candidate = bhex_calloc(sizeof(FindbaseCandidate));
    candidate->address           = address;
    candidate->votes             = votes;
    candidate->array_score       = 1;
    return candidate;
}

static CandidateLeaf* candidate_leaf_new(u64_t address, int votes)
{
    CandidateLeaf* leaf = bhex_malloc(sizeof(CandidateLeaf));
    leaf->address       = address;
    leaf->votes         = votes;
    return leaf;
}

static size_t* findbase_index_new(size_t value)
{
    size_t* index = bhex_malloc(sizeof(size_t));
    *index        = value;
    return index;
}

static u64_t* findbase_u64_new(u64_t value)
{
    u64_t* item = bhex_malloc(sizeof(u64_t));
    *item       = value;
    return item;
}

static void dlist_deinit_free_items(DList* list)
{
    DList_foreach(list, bhex_free);
    DList_deinit(list);
}

static void findbase_memmap_init(FindbaseMemMap* memmap)
{
    memmap->count       = 0;
    memmap->block_types = NULL;
}

static void findbase_memmap_deinit(FindbaseMemMap* memmap)
{
    bhex_free(memmap->block_types);
    memmap->count       = 0;
    memmap->block_types = NULL;
}

static double findbase_calc_entropy(FileBuffer* fb, u64_t addr, u64_t size)
{
    u32_t counts[256] = {0};
    u64_t curr        = addr;
    u64_t end         = addr + size;

    while (curr < end) {
        size_t chunk = min((u64_t)fb_block_size, end - curr);
        u8_t*  buf   = fb_read_alloc(fb, curr, chunk);
        if (buf == NULL)
            return 0.0;

        for (size_t i = 0; i < chunk; ++i)
            counts[buf[i]] += 1;
        bhex_free(buf);
        curr += chunk;
    }

    double entropy = 0.0;
    for (size_t i = 0; i < 256; ++i) {
        double px = (double)counts[i] / (double)size;
        if (px > 0.0)
            entropy += -px * log2(px);
    }
    if (entropy < 0.0)
        entropy = 0.0;
    return entropy / 8.0;
}

static void findbase_analyze_memory(FileBuffer* fb, u64_t file_size,
                                    FindbaseMemMap* memmap)
{
    size_t nsections = (size_t)(file_size / FINDBASE_MEMORY_REGION_MIN_SIZE);
    if (nsections == 0)
        return;

    memmap->count       = nsections;
    memmap->block_types = bhex_calloc(sizeof(u8_t) * nsections);
    if (memmap->block_types == NULL)
        panic("unable to allocate findbase memory map");

    for (size_t i = 0; i < nsections; ++i) {
        u64_t  off = (u64_t)i * FINDBASE_MEMORY_REGION_MIN_SIZE;
        size_t chunk =
            (size_t)min(FINDBASE_MEMORY_REGION_MIN_SIZE, file_size - off);
        double ent = findbase_calc_entropy(fb, off, chunk);

        if (ent >= 0.0f && ent < 0.05f)
            memmap->block_types[i] = FINDBASE_REGION_UNINIT_DATA;
        else if (ent >= 0.05f && ent < 0.6f)
            memmap->block_types[i] = FINDBASE_REGION_INIT_DATA;
        else if (ent >= 0.6f && ent < 0.9f)
            memmap->block_types[i] = FINDBASE_REGION_CODE;
        else
            memmap->block_types[i] = FINDBASE_REGION_UNKNOWN;
    }
}

static FindbaseRegionType findbase_memory_get_type(const FindbaseMemMap* memmap,
                                                   u64_t                 offset)
{
    size_t idx;

    if (memmap == NULL || memmap->block_types == NULL)
        return FINDBASE_REGION_UNKNOWN;

    idx = (size_t)(offset / FINDBASE_MEMORY_REGION_MIN_SIZE);
    if (idx >= memmap->count)
        return FINDBASE_REGION_UNKNOWN;
    return (FindbaseRegionType)memmap->block_types[idx];
}

static FindbaseAddrNode* addrtree_node_alloc(void)
{
    FindbaseAddrNode* node = bhex_calloc(sizeof(FindbaseAddrNode));
    node->leaf             = 1;
    node->votes            = 1;
    return node;
}

static void addrtree_node_free(FindbaseAddrNode* node)
{
    if (node == NULL)
        return;
    if (!node->leaf) {
        for (int i = 0; i < 256; ++i) {
            if (node->subs[i] != NULL)
                addrtree_node_free(node->subs[i]);
        }
    }
    bhex_free(node);
}

static void addrtree_register_address(FindbaseAddrNode* root, u64_t address)
{
    FindbaseAddrNode* node = root;
    for (int shift = 56; shift >= 0; shift -= 8) {
        u8_t b = (address >> shift) & 0xFF;
        if (node->subs[b] != NULL) {
            node = node->subs[b];
            if (node->leaf)
                node->votes += 1;
        } else {
            node->subs[b] = addrtree_node_alloc();
            node->leaf    = 0;
            node          = node->subs[b];
        }
    }
}

static void addrtree_browse_into(FindbaseAddrNode* node, CandidateLeafVec* out,
                                 u64_t base)
{
    if (node->leaf) {
        if (node->votes > 0)
            DList_add(out, candidate_leaf_new(base, node->votes));
        return;
    }

    for (int i = 0; i < 256; ++i) {
        if (node->subs[i] != NULL)
            addrtree_browse_into(node->subs[i], out, (base << 8) | (u64_t)i);
    }
}

static int poi_matches_target(const PoiVec* pois, u64_t rel_offset)
{
    for (size_t i = 0; i < pois->size; ++i) {
        const FindbasePoi* poi = pois->data[i];
        if ((poi->type == FINDBASE_POI_STRING ||
             poi->type == FINDBASE_POI_ARRAY) &&
            poi->offset == rel_offset) {
            return 1;
        }
    }
    return 0;
}

static int dlist_contains_u64(const DList* values, u64_t value)
{
    for (size_t i = 0; i < values->size; ++i) {
        if (*(u64_t*)values->data[i] == value)
            return 1;
    }
    return 0;
}

static void* detect_endianness_worker(void* arg)
{
    EndianTask* task     = (EndianTask*)arg;
    int         ptr_size = findbase_pointer_size(task->arch);

    u64_t pos = task->start;
    while (pos < task->end) {
        size_t starts_this_chunk =
            min((u64_t)FINDBASE_SCAN_CHUNK, task->end - pos);
        size_t read_size = starts_this_chunk + (size_t)ptr_size - 1;
        if (pos + read_size > task->file_size)
            read_size = (size_t)(task->file_size - pos);

        u8_t* buf = fb_read_alloc(task->fb, pos, read_size);
        if (buf == NULL)
            return NULL;

        for (size_t i = 0;
             i < starts_this_chunk && i + (size_t)ptr_size <= read_size; ++i) {
            u64_t le = read_ptr(buf, i, task->arch, FINDBASE_ENDIAN_LE);
            u64_t be = read_ptr(buf, i, task->arch, FINDBASE_ENDIAN_BE);

            if (le != 0 && (le % 4ull) == 0) {
                u32_t idx =
                    (u32_t)((le >> (task->arch == FINDBASE_ARCH_64 ? 48 : 16)) &
                            0xFFFFu);
                task->hist_le[idx] += 1;
            }
            if (be != 0 && (be % 4ull) == 0) {
                u32_t idx =
                    (u32_t)((be >> (task->arch == FINDBASE_ARCH_64 ? 48 : 16)) &
                            0xFFFFu);
                task->hist_be[idx] += 1;
            }
        }

        bhex_free(buf);
        pos += starts_this_chunk;
    }

    return NULL;
}

static FindbaseEndian detect_endianness_mt(FileBuffer* fb, u64_t file_size,
                                           FindbaseArch arch)
{
    int ptr_size = findbase_pointer_size(arch);
    if (file_size < (u64_t)ptr_size)
        return FINDBASE_ENDIAN_UNKNOWN;

    size_t scan_limit = (size_t)(file_size - (u64_t)ptr_size);
    int    nthreads   = default_thread_count(scan_limit);

    pthread_t*  threads = bhex_calloc(sizeof(pthread_t) * (size_t)nthreads);
    EndianTask* tasks   = bhex_calloc(sizeof(EndianTask) * (size_t)nthreads);
    if (threads == NULL || tasks == NULL)
        panic("unable to allocate endianness worker state");

    for (int i = 0; i < nthreads; ++i) {
        size_t begin, end;
        split_work(scan_limit, nthreads, i, &begin, &end);

        tasks[i].fb        = fb;
        tasks[i].file_size = file_size;
        tasks[i].start     = begin;
        tasks[i].end       = end;
        tasks[i].arch      = arch;
        tasks[i].hist_le   = bhex_calloc(sizeof(u32_t) * 65536ull);
        tasks[i].hist_be   = bhex_calloc(sizeof(u32_t) * 65536ull);

        if (pthread_create(&threads[i], NULL, detect_endianness_worker,
                           &tasks[i]) != 0) {
            panic("pthread_create failed");
        }
    }

    u32_t* hist_le = bhex_calloc(sizeof(u32_t) * 65536ull);
    u32_t* hist_be = bhex_calloc(sizeof(u32_t) * 65536ull);
    if (hist_le == NULL || hist_be == NULL)
        panic("unable to allocate endianness histogram");

    for (int i = 0; i < nthreads; ++i) {
        pthread_join(threads[i], NULL);
        for (size_t j = 0; j < 65536ull; ++j) {
            hist_le[j] += tasks[i].hist_le[j];
            hist_be[j] += tasks[i].hist_be[j];
        }
        bhex_free(tasks[i].hist_le);
        bhex_free(tasks[i].hist_be);
    }

    u32_t max_le = 0;
    u32_t max_be = 0;
    for (size_t j = 0; j < 65536ull; ++j) {
        if (hist_le[j] > max_le)
            max_le = hist_le[j];
        if (hist_be[j] > max_be)
            max_be = hist_be[j];
    }

    bhex_free(hist_le);
    bhex_free(hist_be);
    bhex_free(tasks);
    bhex_free(threads);

    if (max_le == 0 && max_be == 0)
        return FINDBASE_ENDIAN_UNKNOWN;
    return max_be > max_le ? FINDBASE_ENDIAN_BE : FINDBASE_ENDIAN_LE;
}

static void index_strings(FileBuffer* fb, u64_t file_size, PoiVec* pois,
                          size_t* out_strings)
{
    *out_strings = 0;

    int   in_string = 0;
    u64_t str_start = 0;
    u32_t str_len   = 0;
    u64_t pos       = 0;

    while (pos < file_size) {
        size_t chunk = min((u64_t)FINDBASE_SCAN_CHUNK, file_size - pos);
        u8_t*  buf   = fb_read_alloc(fb, pos, chunk);
        if (buf == NULL)
            return;

        for (size_t i = 0; i < chunk; ++i) {
            if (is_printable_ascii_byte(buf[i])) {
                if (!in_string) {
                    in_string = 1;
                    str_start = pos + i;
                    str_len   = 1;
                } else {
                    str_len += 1;
                }
            } else if (in_string) {
                if (str_len >= FINDBASE_MIN_STRING_LEN) {
                    DList_add(pois, findbase_poi_new(str_start, str_len,
                                                     FINDBASE_POI_STRING));
                    *out_strings += 1;
                }
                in_string = 0;
                str_len   = 0;
            }
        }

        bhex_free(buf);
        pos += chunk;
    }

    if (in_string && str_len >= FINDBASE_MIN_STRING_LEN) {
        DList_add(pois,
                  findbase_poi_new(str_start, str_len, FINDBASE_POI_STRING));
        *out_strings += 1;
    }
}

static void index_arrays(FileBuffer* fb, u64_t file_size, FindbaseArch arch,
                         FindbaseEndian endian, PoiVec* pois,
                         size_t* out_arrays)
{
    *out_arrays          = 0;
    int         ptr_size = findbase_pointer_size(arch);
    const u64_t max_ptr  = findbase_max_address(arch);

    if (file_size < (u64_t)ptr_size)
        return;

    int   in_array = 0;
    u64_t start    = 0;
    u32_t count    = 0;
    u64_t prev     = 0;
    u64_t pos      = 0;

    while (pos < file_size - (u64_t)ptr_size) {
        u64_t  remaining = file_size - pos;
        size_t chunk     = min((u64_t)FINDBASE_SCAN_CHUNK, remaining);
        chunk -= chunk % (size_t)ptr_size;
        if (chunk == 0)
            break;

        u8_t* buf = fb_read_alloc(fb, pos, chunk);
        if (buf == NULL)
            return;

        for (size_t i = 0; i + (size_t)ptr_size <= chunk;
             i += (size_t)ptr_size) {
            u64_t value    = read_ptr(buf, i, arch, endian);
            int   is_valid = value != 0 && value != max_ptr;

            if (!in_array) {
                if (is_valid) {
                    in_array = 1;
                    start    = pos + i;
                    count    = 0;
                }
                prev = value;
                continue;
            }

            if (findbase_array_delta_within_page(value, prev)) {
                count += 1;
            } else {
                if (count > 8) {
                    DList_add(pois, findbase_poi_new(start, count,
                                                     FINDBASE_POI_ARRAY));
                    *out_arrays += 1;
                }

                if (is_valid) {
                    start = pos + i;
                    count = 0;
                } else {
                    in_array = 0;
                    count    = 0;
                }
            }
            prev = value;
        }

        bhex_free(buf);
        pos += chunk;
    }
}

static void build_candidate_tree(FileBuffer* fb, u64_t file_size, PoiVec* pois,
                                 FindbaseArch arch, FindbaseEndian endian,
                                 FindbaseAddrNode* tree)
{
    int      ptr_size    = findbase_pointer_size(arch);
    u64_t    pos         = 0;
    int      want_string = 0;
    IndexVec buckets[FINDBASE_PAGE_SIZE];

    for (size_t i = 0; i < FINDBASE_PAGE_SIZE; ++i)
        DList_init(&buckets[i]);

    for (size_t i = 0; i < pois->size; ++i) {
        FindbasePoi* poi = pois->data[i];
        if (poi->type == FINDBASE_POI_STRING) {
            want_string = 1;
            break;
        }
    }

    for (size_t i = 0; i < pois->size; ++i) {
        FindbasePoi* poi = pois->data[i];
        if (want_string && poi->type != FINDBASE_POI_STRING)
            continue;
        if (!want_string && poi->type != FINDBASE_POI_ARRAY)
            continue;
        DList_add(&buckets[poi->offset & FINDBASE_PAGE_MASK],
                  findbase_index_new(i));
    }

    while (pos < file_size - (u64_t)ptr_size) {
        u64_t  remaining = file_size - pos;
        size_t chunk     = min((u64_t)FINDBASE_SCAN_CHUNK, remaining);
        chunk -= chunk % (size_t)ptr_size;
        if (chunk == 0)
            break;

        u8_t* buf = fb_read_alloc(fb, pos, chunk);
        if (buf == NULL)
            break;

        for (size_t i = 0; i + (size_t)ptr_size <= chunk;
             i += (size_t)ptr_size) {
            u64_t value = read_ptr(buf, i, arch, endian);
            if (is_ascii_ptr(value, arch))
                continue;

            IndexVec* bucket = &buckets[value & FINDBASE_PAGE_MASK];
            for (size_t j = 0; j < bucket->size; ++j) {
                size_t       poi_index = *(size_t*)bucket->data[j];
                FindbasePoi* poi       = pois->data[poi_index];
                if (value < poi->offset)
                    continue;

                u64_t base = value - poi->offset;
                if (!base_can_fit_file(base, file_size, arch))
                    continue;

                addrtree_register_address(tree, base);
            }
        }

        bhex_free(buf);
        pos += chunk;
    }

    for (size_t i = 0; i < FINDBASE_PAGE_SIZE; ++i)
        dlist_deinit_free_items(&buckets[i]);
}

static void collect_candidates_from_tree(FindbaseAddrNode* root,
                                         CandidateVec*     out)
{
    CandidateLeafVec leaves;
    DList_init(&leaves);
    addrtree_browse_into(root, &leaves, 0);

    for (size_t i = 0; i < leaves.size; ++i) {
        CandidateLeaf* leaf = leaves.data[i];
        DList_add(out, findbase_candidate_new(leaf->address, leaf->votes));
    }

    dlist_deinit_free_items(&leaves);
}

static u32_t count_valid_array_targets(const u8_t* data, size_t size,
                                       FindbaseArch arch, FindbaseEndian endian,
                                       u64_t base, const FindbasePoi* array_poi,
                                       const PoiVec* pois)
{
    int   ptr_size = findbase_pointer_size(arch);
    DList seen;
    DList_init(&seen);
    size_t limit = min((u64_t)array_poi->count, size / (size_t)ptr_size);

    for (size_t i = 0; i < limit; ++i) {
        u64_t value = read_ptr(data, i * (size_t)ptr_size, arch, endian);
        if (value < base)
            continue;

        u64_t rel = value - base;
        if (poi_matches_target(pois, rel) && !dlist_contains_u64(&seen, value))
            DList_add(&seen, findbase_u64_new(value));
    }

    u32_t count = seen.size == 0 ? 1u : (u32_t)seen.size;
    dlist_deinit_free_items(&seen);
    return count;
}

static void score_candidate_arrays(FileBuffer* fb, u64_t file_size,
                                   FindbaseArch arch, FindbaseEndian endian,
                                   const PoiVec* pois, CandidateVec* candidates,
                                   size_t candidate_count)
{
    int ptr_size = findbase_pointer_size(arch);

    for (size_t i = 0; i < candidate_count; ++i) {
        FindbaseCandidate* candidate   = candidates->data[i];
        u32_t              array_score = 1;
        int                valid_array = 0;

        for (size_t j = 0; j < pois->size; ++j) {
            const FindbasePoi* poi = pois->data[j];
            if (poi->type != FINDBASE_POI_ARRAY)
                continue;

            u64_t bytes64 = (u64_t)poi->count * (u64_t)ptr_size;
            if (poi->offset >= file_size)
                continue;
            bytes64 = min(bytes64, file_size - poi->offset);
            if (bytes64 == 0)
                continue;

            u8_t* buf = fb_read_alloc(fb, poi->offset, (size_t)bytes64);
            if (buf == NULL)
                continue;

            u32_t valid_targets =
                count_valid_array_targets(buf, (size_t)bytes64, arch, endian,
                                          candidate->address, poi, pois);
            if (poi->count >= FINDBASE_ARRAY_MIN_ITEMS &&
                valid_targets >= (poi->count / 3)) {
                valid_array = 1;
            }
            array_score += valid_targets;
            bhex_free(buf);
        }

        candidate->array_score     = array_score;
        candidate->has_valid_array = valid_array;
    }
}

static void* pointer_count_worker(void* arg)
{
    PointerCountTask* task     = (PointerCountTask*)arg;
    int               ptr_size = findbase_pointer_size(task->arch);
    u64_t             pos      = task->start;

    while (pos < task->end) {
        u64_t  remaining = task->end - pos;
        size_t chunk     = min((u64_t)FINDBASE_SCAN_CHUNK, remaining);
        chunk -= chunk % (size_t)ptr_size;
        if (chunk == 0)
            break;

        u8_t* buf = fb_read_alloc(task->fb, pos, chunk);
        if (buf == NULL)
            return NULL;

        for (size_t i = 0; i + (size_t)ptr_size <= chunk;
             i += (size_t)ptr_size) {
            u64_t value = read_ptr(buf, i, task->arch, task->endian);
            if (findbase_memory_get_type(task->memmap, pos + i) ==
                FINDBASE_REGION_CODE) {
                continue;
            }

            for (size_t j = 0; j < task->candidate_count; ++j) {
                FindbaseCandidate* candidate = task->candidates->data[j];
                u64_t              base      = candidate->address;
                if (value >= base && value < base + task->file_size &&
                    value != 0) {
                    FindbaseRegionType mem_type =
                        findbase_memory_get_type(task->memmap, value - base);
                    if (mem_type != FINDBASE_REGION_UNKNOWN &&
                        mem_type != FINDBASE_REGION_UNINIT_DATA) {
                        task->local_counts[j] += 1;
                    }
                }
            }
        }

        bhex_free(buf);
        pos += chunk;
    }

    return NULL;
}

static void
score_candidate_pointers_mt(FileBuffer* fb, u64_t file_size, FindbaseArch arch,
                            FindbaseEndian endian, const FindbaseMemMap* memmap,
                            CandidateVec* candidates, size_t candidate_count)
{
    if (candidate_count == 0)
        return;

    int    ptr_size   = findbase_pointer_size(arch);
    size_t slot_count = 0;
    if (file_size > (u64_t)ptr_size)
        slot_count = (size_t)((file_size - (u64_t)ptr_size) / (u64_t)ptr_size);
    if (slot_count == 0)
        return;
    int nthreads = default_thread_count(slot_count);

    pthread_t* threads = bhex_calloc(sizeof(pthread_t) * (size_t)nthreads);
    PointerCountTask* tasks =
        bhex_calloc(sizeof(PointerCountTask) * (size_t)nthreads);

    for (int i = 0; i < nthreads; ++i) {
        size_t begin_slot, end_slot;
        split_work(slot_count, nthreads, i, &begin_slot, &end_slot);

        tasks[i].fb              = fb;
        tasks[i].file_size       = file_size;
        tasks[i].start           = (u64_t)begin_slot * (u64_t)ptr_size;
        tasks[i].end             = (u64_t)end_slot * (u64_t)ptr_size;
        tasks[i].arch            = arch;
        tasks[i].endian          = endian;
        tasks[i].memmap          = memmap;
        tasks[i].candidates      = candidates;
        tasks[i].candidate_count = candidate_count;
        tasks[i].local_counts    = bhex_calloc(sizeof(u32_t) * candidate_count);

        if (pthread_create(&threads[i], NULL, pointer_count_worker,
                           &tasks[i]) != 0)
            panic("pthread_create failed");
    }

    for (int i = 0; i < nthreads; ++i) {
        pthread_join(threads[i], NULL);
        for (size_t j = 0; j < candidate_count; ++j) {
            FindbaseCandidate* candidate = candidates->data[j];
            candidate->pointer_count += tasks[i].local_counts[j];
        }
        bhex_free(tasks[i].local_counts);
    }

    bhex_free(tasks);
    bhex_free(threads);
}

static int candidate_compare_votes_desc(const void* a, const void* b)
{
    const FindbaseCandidate* c1 = *(FindbaseCandidate* const*)a;
    const FindbaseCandidate* c2 = *(FindbaseCandidate* const*)b;

    if (c1->votes != c2->votes)
        return c2->votes - c1->votes;
    if (c1->address < c2->address)
        return -1;
    if (c1->address > c2->address)
        return 1;
    return 0;
}

static int candidate_compare_score_desc(const void* a, const void* b)
{
    const FindbaseCandidate* c1 = *(FindbaseCandidate* const*)a;
    const FindbaseCandidate* c2 = *(FindbaseCandidate* const*)b;

    if (c1->score < c2->score)
        return 1;
    if (c1->score > c2->score)
        return -1;
    if (c1->votes != c2->votes)
        return c2->votes - c1->votes;
    if (c1->address < c2->address)
        return -1;
    if (c1->address > c2->address)
        return 1;
    return 0;
}

static size_t count_candidates_with_min_votes(CandidateVec* candidates,
                                              size_t limit, int min_votes)
{
    size_t count = 0;

    for (size_t i = 0; i < limit; ++i) {
        FindbaseCandidate* candidate = candidates->data[i];
        if (candidate->votes >= min_votes)
            count += 1;
    }
    return count;
}

static size_t select_kept_candidates(CandidateVec* candidates,
                                     size_t        eligible_count)
{
    if (eligible_count <= FINDBASE_MAX_CANDIDATES)
        return eligible_count;

    int max_votes = ((FindbaseCandidate*)candidates->data[0])->votes;
    for (int votes = max_votes; votes >= 0; --votes) {
        size_t kept =
            count_candidates_with_min_votes(candidates, eligible_count, votes);
        if (kept >= FINDBASE_MAX_CANDIDATES)
            return kept;
    }

    return eligible_count;
}

static void compute_scores(FileBuffer* fb, u64_t file_size, FindbaseArch arch,
                           FindbaseEndian endian, const FindbaseMemMap* memmap,
                           const PoiVec* pois, CandidateVec* candidates,
                           size_t candidate_count)
{
    score_candidate_arrays(fb, file_size, arch, endian, pois, candidates,
                           candidate_count);
    score_candidate_pointers_mt(fb, file_size, arch, endian, memmap, candidates,
                                candidate_count);

    for (size_t i = 0; i < candidate_count; ++i) {
        FindbaseCandidate* candidate = candidates->data[i];
        candidate->score             = (u64_t)candidate->pointer_count *
                           (u64_t)candidate->votes *
                           (u64_t)candidate->array_score;
    }
}

static void print_result(FindbaseArch arch, CandidateVec* candidates,
                         size_t candidate_count, u64_t top_vote_address)
{
    size_t valid_array_matches = 0;
    size_t valid_array_index   = 0;
    for (size_t i = 0; i < candidate_count; ++i) {
        FindbaseCandidate* candidate = candidates->data[i];
        if (candidate->has_valid_array) {
            valid_array_matches += 1;
            valid_array_index = i;
        }
    }

    FindbaseCandidate* first        = candidates->data[0];
    u64_t              best_address = first->address;
    int                best_score   = first->score > 0;

    if (valid_array_matches == 1) {
        best_address =
            ((FindbaseCandidate*)candidates->data[valid_array_index])->address;
        if (arch == FINDBASE_ARCH_64)
            display_printf("[i] Base address found (valid array): 0x%016llx.\n",
                           (unsigned long long)best_address);
        else
            display_printf("[i] Base address found (valid array): 0x%08llx.\n",
                           (unsigned long long)(best_address & 0xFFFFFFFFull));
    } else if (best_score && top_vote_address == best_address) {
        if (arch == FINDBASE_ARCH_64)
            display_printf("[i] Base address found: 0x%016llx.\n",
                           (unsigned long long)best_address);
        else
            display_printf("[i] Base address found: 0x%08llx.\n",
                           (unsigned long long)(best_address & 0xFFFFFFFFull));
    } else {
        best_address = top_vote_address;
        for (size_t i = 0; i < candidate_count; ++i) {
            FindbaseCandidate* candidate = candidates->data[i];
            if (candidate->score > 0) {
                best_address = candidate->address;
                break;
            }
        }

        if (arch == FINDBASE_ARCH_64)
            display_printf(
                "[i] Base address seems to be 0x%016llx (not sure).\n",
                (unsigned long long)best_address);
        else
            display_printf(
                "[i] Base address seems to be 0x%08llx (not sure).\n",
                (unsigned long long)(best_address & 0xFFFFFFFFull));
    }

    if (candidate_count > 1) {
        u64_t ref_score = ((FindbaseCandidate*)candidates->data[0])->score;
        display_printf(" More base addresses to consider (just in case):\n");
        for (size_t i = 0; i < candidate_count; ++i) {
            FindbaseCandidate* candidate = candidates->data[i];
            if (candidate->address == best_address || candidate->score == 0)
                continue;

            float ratio = ref_score == 0
                              ? 0.0f
                              : (float)candidate->score / (float)ref_score;
            if (arch == FINDBASE_ARCH_64)
                display_printf("  0x%016llx (%.02f)\n",
                               (unsigned long long)candidate->address, ratio);
            else
                display_printf(
                    "  0x%08llx (%.02f)\n",
                    (unsigned long long)(candidate->address & 0xFFFFFFFFull),
                    ratio);
        }
    }
}

static void findbasecmd_help(void* obj)
{
    (void)obj;
    display_printf(
        "findbase: guess the base address of a raw firmware blob using "
        "binbloom heuristics\n"
        "\n"
        "  fba" HINT_STR "\n"
        "     32: assume a 32-bit blob (default)\n"
        "     64: assume a 64-bit blob\n"
        "     le: force little-endian decoding\n"
        "     be: force big-endian decoding\n");
}

static void findbasecmd_dispose(void* obj) { (void)obj; }

static int findbasecmd_exec(void* obj, FileBuffer* fb, ParsedCommand* pc)
{
    (void)obj;

    int arch_mod   = -1;
    int endian_mod = -1;
    if (handle_mods(pc, "32,64|le,be", &arch_mod, &endian_mod) != COMMAND_OK)
        return COMMAND_INVALID_MOD;
    if (pc->args.size != 0)
        return COMMAND_UNSUPPORTED_ARG;

    FindbaseArch   arch   = arch_mod == 1 ? FINDBASE_ARCH_64 : FINDBASE_ARCH_32;
    FindbaseEndian endian = FINDBASE_ENDIAN_UNKNOWN;
    if (endian_mod == 0)
        endian = FINDBASE_ENDIAN_LE;
    else if (endian_mod == 1)
        endian = FINDBASE_ENDIAN_BE;

    display_printf("[i] %d-bit architecture selected.\n", (int)arch);

    if (fb->size < (u64_t)findbase_pointer_size(arch)) {
        error("input file must be at least %d bytes",
              findbase_pointer_size(arch));
        return COMMAND_SILENT_ERROR;
    }

    if (endian == FINDBASE_ENDIAN_UNKNOWN)
        endian = detect_endianness_mt(fb, fb->size, arch);
    if (endian == FINDBASE_ENDIAN_UNKNOWN) {
        error("unable to detect the blob endianness");
        return COMMAND_SILENT_ERROR;
    }

    display_printf("[i] Endianness is %s\n", findbase_endian_to_string(endian));

    PoiVec pois;
    DList_init(&pois);
    size_t string_count = 0;
    size_t array_count  = 0;
    index_strings(fb, fb->size, &pois, &string_count);
    index_arrays(fb, fb->size, arch, endian, &pois, &array_count);

    display_printf("[i] %llu strings indexed\n",
                   (unsigned long long)string_count);

    if (string_count == 0 && array_count == 0) {
        dlist_deinit_free_items(&pois);
        error("no useful points of interest found in the blob");
        return COMMAND_SILENT_ERROR;
    }

    FindbaseAddrNode* tree = addrtree_node_alloc();
    tree->votes            = 0;
    build_candidate_tree(fb, fb->size, &pois, arch, endian, tree);

    CandidateVec candidates;
    DList_init(&candidates);
    collect_candidates_from_tree(tree, &candidates);
    addrtree_node_free(tree);

    if (candidates.size == 0) {
        dlist_deinit_free_items(&candidates);
        dlist_deinit_free_items(&pois);
        error("no base address candidates found");
        return COMMAND_SILENT_ERROR;
    }

    qsort(candidates.data, candidates.size, sizeof(void*),
          candidate_compare_votes_desc);

    size_t total_candidates = candidates.size;
    size_t eligible_count   = candidates.size;
    int    top_votes        = ((FindbaseCandidate*)candidates.data[0])->votes;
    if (top_votes > 1) {
        eligible_count = 0;
        while (eligible_count < candidates.size) {
            FindbaseCandidate* candidate = candidates.data[eligible_count];
            if (candidate->votes <= 1)
                break;
            eligible_count += 1;
        }
    }
    size_t kept_candidates =
        select_kept_candidates(&candidates, eligible_count);

    display_printf("[i] Found %llu base addresses to test\n",
                   (unsigned long long)total_candidates);

    FindbaseMemMap memmap;
    findbase_memmap_init(&memmap);
    findbase_analyze_memory(fb, fb->size, &memmap);

    u64_t top_vote_address = ((FindbaseCandidate*)candidates.data[0])->address;
    compute_scores(fb, fb->size, arch, endian, &memmap, &pois, &candidates,
                   kept_candidates);
    qsort(candidates.data, kept_candidates, sizeof(void*),
          candidate_compare_score_desc);

    print_result(arch, &candidates, kept_candidates, top_vote_address);
    findbase_memmap_deinit(&memmap);

    dlist_deinit_free_items(&candidates);
    dlist_deinit_free_items(&pois);
    return COMMAND_OK;
}

Cmd* findbasecmd_create(void)
{
    Cmd* cmd = bhex_malloc(sizeof(Cmd));

    cmd->obj   = NULL;
    cmd->name  = "findbase";
    cmd->alias = "fba";
    cmd->hint  = HINT_STR;

    cmd->dispose = findbasecmd_dispose;
    cmd->help    = findbasecmd_help;
    cmd->exec    = findbasecmd_exec;

    return cmd;
}
