// Copyright (c) 2022-2026, bageyelet
/*
 * The bundled model was trained using this project:
 *   https://github.com/kairis/isadetect
 *   isadetect - "ML-based ISA detection
                (architecture and endianness of binary code/sequences)"
 *   Copyright (c) 2019, Sami Kairajarvi <sami.kairajarvi@gmail.com>
 */

#include "isadetect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NEED_BYTES(nbytes)                                                     \
    do {                                                                       \
        if (i + (nbytes) > size)                                               \
            return 0;                                                          \
    } while (0)

typedef size_t (*isadetect_match_fn)(const uint8_t* data, size_t size,
                                     size_t i);

typedef struct isadetect_tree {
    uint32_t node_count;
    uint32_t leaf_count;
    int32_t* left;
    int32_t* right;
    int16_t* feature;
    double*  threshold;
    int32_t* leaf_index;
    float*   leaf_probs;
} isadetect_tree_t;

struct isadetect_model {
    uint32_t          num_features;
    uint32_t          num_classes;
    uint32_t          num_trees;
    int32_t*          classes;
    isadetect_tree_t* trees;
};

typedef struct isadetect_arch_info {
    int         label;
    const char* architecture;
    const char* endianness;
    int         wordsize;
} isadetect_arch_info_t;

static const uint8_t ISADETECT_MAGIC[8] = {'I', 'S', 'A', 'D',
                                           'R', 'F', '0', '1'};

static const isadetect_arch_info_t ISADETECT_ARCHES[] = {
    {1, "alpha", "little", 64},  {2, "amd64", "little", 64},
    {3, "arm", "little", 64},    {4, "arm", "little", 32},
    {5, "armhf", "little", 32},  {6, "hppa", "big", 32},
    {7, "i386", "little", 32},   {8, "ia64", "little", 64},
    {9, "m68k", "big", 32},      {10, "mips", "big", 32},
    {11, "mips", "little", 64},  {12, "mips", "little", 32},
    {13, "powerpc", "big", 32},  {14, "powerpcspe", "big", 32},
    {15, "powerpc", "big", 64},  {16, "powerpc", "little", 64},
    {17, "riscv", "little", 64}, {18, "s390", "big", 32},
    {19, "s390x", "big", 64},    {20, "sh4", "little", 32},
    {21, "sparc", "big", 32},    {22, "sparc", "big", 64},
    {23, "x32", "little", 32},
};

static const isadetect_arch_info_t* isadetect_lookup_arch(int label)
{
    size_t idx;
    for (idx = 0; idx < sizeof(ISADETECT_ARCHES) / sizeof(ISADETECT_ARCHES[0]);
         ++idx) {
        if (ISADETECT_ARCHES[idx].label == label) {
            return &ISADETECT_ARCHES[idx];
        }
    }
    return NULL;
}

int isadetect_describe_label(int label, const char** architecture,
                             const char** endianness, int* wordsize)
{
    const isadetect_arch_info_t* info = isadetect_lookup_arch(label);

    if (info == NULL) {
        return ISADETECT_ERR_INVALID_INPUT;
    }
    if (architecture != NULL) {
        *architecture = info->architecture;
    }
    if (endianness != NULL) {
        *endianness = info->endianness;
    }
    if (wordsize != NULL) {
        *wordsize = info->wordsize;
    }
    return ISADETECT_OK;
}

static int isadetect_read_exact(FILE* fp, void* buffer, size_t size)
{
    return fread(buffer, 1u, size, fp) == size ? ISADETECT_OK
                                               : ISADETECT_ERR_IO;
}

static int isadetect_read_u32_le(FILE* fp, uint32_t* value)
{
    uint8_t b[4];
    if (isadetect_read_exact(fp, b, sizeof(b)) != ISADETECT_OK) {
        return ISADETECT_ERR_IO;
    }
    *value = ((uint32_t)b[0]) | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
             ((uint32_t)b[3] << 24);
    return ISADETECT_OK;
}

static int isadetect_read_i16_array_le(FILE* fp, int16_t* values, size_t count)
{
    size_t idx;
    for (idx = 0; idx < count; ++idx) {
        uint8_t  b[2];
        uint16_t raw;
        if (isadetect_read_exact(fp, b, sizeof(b)) != ISADETECT_OK) {
            return ISADETECT_ERR_IO;
        }
        raw         = (uint16_t)(((uint16_t)b[0]) | ((uint16_t)b[1] << 8));
        values[idx] = (int16_t)raw;
    }
    return ISADETECT_OK;
}

static int isadetect_read_i32_array_le(FILE* fp, int32_t* values, size_t count)
{
    size_t idx;
    for (idx = 0; idx < count; ++idx) {
        uint32_t raw;
        int      rc = isadetect_read_u32_le(fp, &raw);
        if (rc != ISADETECT_OK) {
            return rc;
        }
        values[idx] = (int32_t)raw;
    }
    return ISADETECT_OK;
}

static int isadetect_read_float_array_le(FILE* fp, float* values, size_t count)
{
    size_t idx;
    for (idx = 0; idx < count; ++idx) {
        uint32_t raw;
        int      rc = isadetect_read_u32_le(fp, &raw);
        if (rc != ISADETECT_OK) {
            return rc;
        }
        memcpy(&values[idx], &raw, sizeof(raw));
    }
    return ISADETECT_OK;
}

static int isadetect_read_double_array_le(FILE* fp, double* values,
                                          size_t count)
{
    size_t idx;
    for (idx = 0; idx < count; ++idx) {
        uint8_t  b[8];
        uint64_t raw;
        if (isadetect_read_exact(fp, b, sizeof(b)) != ISADETECT_OK) {
            return ISADETECT_ERR_IO;
        }
        raw = ((uint64_t)b[0]) | ((uint64_t)b[1] << 8) |
              ((uint64_t)b[2] << 16) | ((uint64_t)b[3] << 24) |
              ((uint64_t)b[4] << 32) | ((uint64_t)b[5] << 40) |
              ((uint64_t)b[6] << 48) | ((uint64_t)b[7] << 56);
        memcpy(&values[idx], &raw, sizeof(raw));
    }
    return ISADETECT_OK;
}

static void isadetect_free_tree(isadetect_tree_t* tree)
{
    if (tree == NULL) {
        return;
    }
    free(tree->left);
    free(tree->right);
    free(tree->feature);
    free(tree->threshold);
    free(tree->leaf_index);
    free(tree->leaf_probs);
    memset(tree, 0, sizeof(*tree));
}

void isadetect_model_free(isadetect_model_t* model)
{
    size_t idx;
    if (model == NULL) {
        return;
    }
    if (model->trees != NULL) {
        for (idx = 0; idx < model->num_trees; ++idx) {
            isadetect_free_tree(&model->trees[idx]);
        }
    }
    free(model->trees);
    free(model->classes);
    free(model);
}

int isadetect_model_load(isadetect_model_t** out_model, const char* path)
{
    FILE*              fp    = NULL;
    isadetect_model_t* model = NULL;
    uint8_t            magic[8];
    uint32_t           idx;
    int                rc = ISADETECT_OK;

    if (out_model == NULL || path == NULL) {
        return ISADETECT_ERR_INVALID_INPUT;
    }
    *out_model = NULL;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return ISADETECT_ERR_IO;
    }

    if (isadetect_read_exact(fp, magic, sizeof(magic)) != ISADETECT_OK ||
        memcmp(magic, ISADETECT_MAGIC, sizeof(magic)) != 0) {
        rc = ISADETECT_ERR_FORMAT;
        goto cleanup;
    }

    model = (isadetect_model_t*)calloc(1u, sizeof(*model));
    if (model == NULL) {
        rc = ISADETECT_ERR_NOMEM;
        goto cleanup;
    }

    rc = isadetect_read_u32_le(fp, &model->num_features);
    if (rc != ISADETECT_OK)
        goto cleanup;
    rc = isadetect_read_u32_le(fp, &model->num_classes);
    if (rc != ISADETECT_OK)
        goto cleanup;
    rc = isadetect_read_u32_le(fp, &model->num_trees);
    if (rc != ISADETECT_OK)
        goto cleanup;

    if (model->num_features != ISADETECT_NUM_FEATURES ||
        model->num_classes != ISADETECT_NUM_CLASSES || model->num_trees == 0u) {
        rc = ISADETECT_ERR_UNSUPPORTED;
        goto cleanup;
    }

    model->classes =
        (int32_t*)calloc(model->num_classes, sizeof(*model->classes));
    model->trees =
        (isadetect_tree_t*)calloc(model->num_trees, sizeof(*model->trees));
    if (model->classes == NULL || model->trees == NULL) {
        rc = ISADETECT_ERR_NOMEM;
        goto cleanup;
    }

    rc = isadetect_read_i32_array_le(fp, model->classes, model->num_classes);
    if (rc != ISADETECT_OK)
        goto cleanup;

    for (idx = 0; idx < model->num_trees; ++idx) {
        isadetect_tree_t* tree = &model->trees[idx];
        size_t            node_count;
        size_t            leaf_prob_count;

        rc = isadetect_read_u32_le(fp, &tree->node_count);
        if (rc != ISADETECT_OK)
            goto cleanup;
        rc = isadetect_read_u32_le(fp, &tree->leaf_count);
        if (rc != ISADETECT_OK)
            goto cleanup;
        if (tree->node_count == 0u || tree->leaf_count == 0u) {
            rc = ISADETECT_ERR_FORMAT;
            goto cleanup;
        }

        node_count      = (size_t)tree->node_count;
        leaf_prob_count = (size_t)tree->leaf_count * (size_t)model->num_classes;

        tree->left      = (int32_t*)calloc(node_count, sizeof(*tree->left));
        tree->right     = (int32_t*)calloc(node_count, sizeof(*tree->right));
        tree->feature   = (int16_t*)calloc(node_count, sizeof(*tree->feature));
        tree->threshold = (double*)calloc(node_count, sizeof(*tree->threshold));
        tree->leaf_index =
            (int32_t*)calloc(node_count, sizeof(*tree->leaf_index));
        tree->leaf_probs =
            (float*)calloc(leaf_prob_count, sizeof(*tree->leaf_probs));
        if (tree->left == NULL || tree->right == NULL ||
            tree->feature == NULL || tree->threshold == NULL ||
            tree->leaf_index == NULL || tree->leaf_probs == NULL) {
            rc = ISADETECT_ERR_NOMEM;
            goto cleanup;
        }

        rc = isadetect_read_i32_array_le(fp, tree->left, node_count);
        if (rc != ISADETECT_OK)
            goto cleanup;
        rc = isadetect_read_i32_array_le(fp, tree->right, node_count);
        if (rc != ISADETECT_OK)
            goto cleanup;
        rc = isadetect_read_i16_array_le(fp, tree->feature, node_count);
        if (rc != ISADETECT_OK)
            goto cleanup;
        rc = isadetect_read_double_array_le(fp, tree->threshold, node_count);
        if (rc != ISADETECT_OK)
            goto cleanup;
        rc = isadetect_read_i32_array_le(fp, tree->leaf_index, node_count);
        if (rc != ISADETECT_OK)
            goto cleanup;
        rc = isadetect_read_float_array_le(fp, tree->leaf_probs,
                                           leaf_prob_count);
        if (rc != ISADETECT_OK)
            goto cleanup;
    }

    fclose(fp);
    *out_model = model;
    return ISADETECT_OK;

cleanup:
    if (fp != NULL) {
        fclose(fp);
    }
    isadetect_model_free(model);
    return rc;
}

int isadetect_model_predict_proba(const isadetect_model_t* model,
                                  const double input[ISADETECT_NUM_FEATURES],
                                  double       out[ISADETECT_NUM_CLASSES])
{
    uint32_t tree_idx;
    uint32_t cls;

    if (model == NULL || input == NULL || out == NULL ||
        model->num_features != ISADETECT_NUM_FEATURES ||
        model->num_classes != ISADETECT_NUM_CLASSES) {
        return ISADETECT_ERR_INVALID_INPUT;
    }

    for (cls = 0; cls < model->num_classes; ++cls) {
        out[cls] = 0.0;
    }

    for (tree_idx = 0; tree_idx < model->num_trees; ++tree_idx) {
        const isadetect_tree_t* tree = &model->trees[tree_idx];
        int32_t                 node = 0;
        while (node >= 0 && (uint32_t)node < tree->node_count &&
               tree->feature[node] >= 0) {
            int16_t feature = tree->feature[node];
            node            = (input[feature] <= tree->threshold[node])
                                  ? tree->left[node]
                                  : tree->right[node];
        }
        if (node < 0 || (uint32_t)node >= tree->node_count) {
            return ISADETECT_ERR_FORMAT;
        }
        {
            int32_t      leaf = tree->leaf_index[node];
            const float* probs;
            if (leaf < 0 || (uint32_t)leaf >= tree->leaf_count) {
                return ISADETECT_ERR_FORMAT;
            }
            probs =
                tree->leaf_probs + ((size_t)leaf * (size_t)model->num_classes);
            for (cls = 0; cls < model->num_classes; ++cls) {
                out[cls] += (double)probs[cls];
            }
        }
    }

    for (cls = 0; cls < model->num_classes; ++cls) {
        out[cls] /= (double)model->num_trees;
    }
    return ISADETECT_OK;
}

int isadetect_model_predict_label(const isadetect_model_t* model,
                                  const double input[ISADETECT_NUM_FEATURES],
                                  int* label, double* probability)
{
    double   probs[ISADETECT_NUM_CLASSES];
    int      best = 0;
    uint32_t idx;
    int      rc = isadetect_model_predict_proba(model, input, probs);
    if (rc != ISADETECT_OK) {
        return rc;
    }
    for (idx = 1; idx < ISADETECT_NUM_CLASSES; ++idx) {
        if (probs[idx] > probs[best]) {
            best = (int)idx;
        }
    }
    if (label != NULL) {
        *label = model->classes[best];
    }
    if (probability != NULL) {
        *probability = probs[best];
    }
    return ISADETECT_OK;
}

int isadetect_model_get_class_label(const isadetect_model_t* model,
                                    size_t class_index, int* label)
{
    if (model == NULL || label == NULL || class_index >= model->num_classes) {
        return ISADETECT_ERR_INVALID_INPUT;
    }
    *label = model->classes[class_index];
    return ISADETECT_OK;
}

static int is_83_81_or_comma(uint8_t value)
{
    return value == 0x83 || value == 0x81 || value == 0x2c;
}

static int is_10_to_13(uint8_t value) { return value >= 0x10 && value <= 0x13; }

static int is_1e_5e_9e(uint8_t value)
{
    return value == 0x1e || value == 0x5e || value == 0x9e;
}

static int is_evl_suffix(uint8_t value)
{
    return value == 0x01 || value == 0xc1 || value == 0xc8 || value == 0xc9 ||
           value == 0xc0 || value == 0xd0 || value == 0xd1 || value == 0xda;
}

static size_t match_amd64_epilog_1(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(2);
    return (data[i] == 0xc9 && data[i + 1] == 0xc3) ? 2 : 0;
}

static size_t match_amd64_epilog_2(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(3);
    return (data[i + 1] >= 0x50 && data[i + 1] <= 0x5f && data[i + 2] == 0xc3)
               ? 3
               : 0;
}

static size_t match_amd64_epilog_3(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(5);
    if (data[i] != 0x48 || !is_83_81_or_comma(data[i + 1]) ||
        data[i + 2] != 0xc4) {
        return 0;
    }
    if (data[i + 4] == 0xc3) {
        return 5;
    }
    if (i + 8 <= size && data[i + 7] == 0xc3) {
        return 8;
    }
    return 0;
}

static size_t match_amd64_prolog_1(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(4);
    return (data[i] == 0x55 && data[i + 1] == 0x48 && data[i + 2] == 0x89 &&
            data[i + 3] == 0xe5)
               ? 4
               : 0;
}

static size_t match_amd64_prolog_2(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(4);
    return (data[i] == 0x48 && is_83_81_or_comma(data[i + 1]) &&
            data[i + 2] == 0xec)
               ? 4
               : 0;
}

static size_t match_arm32_epilog_1(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(8);
    return (data[i] == 0xe8 && data[i + 1] == 0xbd && data[i + 4] == 0xe1 &&
            data[i + 5] == 0x2f && data[i + 6] == 0xff && data[i + 7] == 0x1e)
               ? 8
               : 0;
}

static size_t match_arm32_epilog_2(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(8);
    return (data[i] == 0xe4 && data[i + 1] == 0x9d && data[i + 2] == 0xe0 &&
            data[i + 3] == 0x04 && data[i + 4] == 0xe1 && data[i + 5] == 0x2f &&
            data[i + 6] == 0xff && data[i + 7] == 0x1e)
               ? 8
               : 0;
}

static size_t match_arm32_prolog_1(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(4);
    return (data[i] == 0xe9 && data[i + 1] == 0x2d) ? 4 : 0;
}

static size_t match_arm32_prolog_2(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(4);
    return (data[i] == 0xe5 && data[i + 1] == 0x2d && data[i + 2] == 0xe0 &&
            data[i + 3] == 0x04)
               ? 4
               : 0;
}

static size_t match_armel32_epilog_1(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(8);
    return (data[i + 2] == 0xbd && data[i + 3] == 0xe8 && data[i + 4] == 0x1e &&
            data[i + 5] == 0xff && data[i + 6] == 0x2f && data[i + 7] == 0xe1)
               ? 8
               : 0;
}

static size_t match_armel32_epilog_2(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(8);
    return (data[i] == 0x04 && data[i + 1] == 0xe0 && data[i + 2] == 0x9d &&
            data[i + 3] == 0xe4 && data[i + 4] == 0x1e && data[i + 5] == 0xff &&
            data[i + 6] == 0x2f && data[i + 7] == 0xe1)
               ? 8
               : 0;
}

static size_t match_armel32_prolog_1(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(4);
    return (data[i + 2] == 0x2d && data[i + 3] == 0xe9) ? 4 : 0;
}

static size_t match_armel32_prolog_2(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(4);
    return (data[i] == 0x04 && data[i + 1] == 0xe0 && data[i + 2] == 0x2d &&
            data[i + 3] == 0xe5)
               ? 4
               : 0;
}

static size_t match_be_one(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(2);
    return (data[i] == 0x00 && data[i + 1] == 0x01) ? 2 : 0;
}

static size_t match_be_stack(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(2);
    return (data[i] == 0xff && data[i + 1] == 0xfe) ? 2 : 0;
}

static size_t match_le_one(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(2);
    return (data[i] == 0x01 && data[i + 1] == 0x00) ? 2 : 0;
}

static size_t match_le_stack(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(2);
    return (data[i] == 0xfe && data[i + 1] == 0xff) ? 2 : 0;
}

static size_t match_mips32_epilog_1(const uint8_t* data, size_t size, size_t i)
{
    int reps;
    NEED_BYTES(8);
    if (data[i] != 0x8f || data[i + 1] != 0xbf) {
        return 0;
    }
    for (reps = 4; reps >= 0; --reps) {
        size_t suffix = i + 4u + ((size_t)reps * 4u);
        if (suffix + 4u <= size && data[suffix] == 0x03 &&
            data[suffix + 1] == 0xe0 && data[suffix + 2] == 0x00 &&
            data[suffix + 3] == 0x08) {
            return 8u + ((size_t)reps * 4u);
        }
    }
    return 0;
}

static size_t match_mips32_prolog_1(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(4);
    return (data[i] == 0x27 && data[i + 1] == 0xbd && data[i + 2] == 0xff) ? 4
                                                                           : 0;
}

static size_t match_mips32_prolog_2(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(8);
    return (data[i] == 0x3c && data[i + 1] == 0x1c && data[i + 4] == 0x9c &&
            data[i + 5] == 0x27)
               ? 8
               : 0;
}

static size_t match_mips32el_epilog_1(const uint8_t* data, size_t size,
                                      size_t i)
{
    int reps;
    NEED_BYTES(8);
    if (data[i + 2] != 0xbf || data[i + 3] != 0x8f) {
        return 0;
    }
    for (reps = 4; reps >= 0; --reps) {
        size_t suffix = i + 4u + ((size_t)reps * 4u);
        if (suffix + 4u <= size && data[suffix] == 0x08 &&
            data[suffix + 1] == 0x00 && data[suffix + 2] == 0xe0 &&
            data[suffix + 3] == 0x03) {
            return 8u + ((size_t)reps * 4u);
        }
    }
    return 0;
}

static size_t match_mips32el_prolog_1(const uint8_t* data, size_t size,
                                      size_t i)
{
    NEED_BYTES(4);
    return (data[i + 1] == 0xff && data[i + 2] == 0xbd && data[i + 3] == 0x27)
               ? 4
               : 0;
}

static size_t match_mips32el_prolog_2(const uint8_t* data, size_t size,
                                      size_t i)
{
    NEED_BYTES(8);
    return (data[i + 2] == 0x1c && data[i + 3] == 0x3c && data[i + 6] == 0x9c &&
            data[i + 7] == 0x27)
               ? 8
               : 0;
}

static size_t match_powerpcspe_spe_instruction_evl(const uint8_t* data,
                                                   size_t size, size_t i)
{
    NEED_BYTES(4);
    return (is_10_to_13(data[i]) && is_evl_suffix(data[i + 3])) ? 4 : 0;
}

static size_t match_powerpcspe_spe_instruction_isel(const uint8_t* data,
                                                    size_t size, size_t i)
{
    NEED_BYTES(4);
    return (data[i] >= 0x7d && data[i] <= 0x7f && is_1e_5e_9e(data[i + 3])) ? 4
                                                                            : 0;
}

static size_t match_ppc32_epilog_1(const uint8_t* data, size_t size, size_t i)
{
    int reps;
    NEED_BYTES(8);
    if (data[i + 2] != 0x03 || data[i + 3] != 0xa6) {
        return 0;
    }
    for (reps = 6; reps >= 0; --reps) {
        size_t suffix = i + 4u + ((size_t)reps * 4u);
        if (suffix + 4u <= size && data[suffix] == 0x4e &&
            data[suffix + 1] == 0x80 && data[suffix + 2] == 0x00 &&
            data[suffix + 3] == 0x20) {
            return 8u + ((size_t)reps * 4u);
        }
    }
    return 0;
}

static size_t match_ppc32_prolog_1(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(8);
    return (data[i] == 0x94 && data[i + 1] == 0x21 && data[i + 4] == 0x7c &&
            data[i + 5] == 0x08 && data[i + 6] == 0x02 && data[i + 7] == 0xa6)
               ? 8
               : 0;
}

static size_t match_ppc64_epilog_1(const uint8_t* data, size_t size, size_t i)
{
    return match_ppc32_epilog_1(data, size, i);
}

static size_t match_ppc64_prolog_1(const uint8_t* data, size_t size, size_t i)
{
    return match_ppc32_prolog_1(data, size, i);
}

static size_t match_ppc64_prolog_2(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(4);
    return (data[i] == 0x7c && data[i + 1] == 0x08 && data[i + 2] == 0x02 &&
            data[i + 3] == 0xa6)
               ? 4
               : 0;
}

static size_t match_ppc64_prolog_3(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(4);
    return (data[i] == 0xf8 && data[i + 1] == 0x61) ? 4 : 0;
}

static size_t match_ppcel32_epilog_1(const uint8_t* data, size_t size, size_t i)
{
    int reps;
    NEED_BYTES(8);
    if (data[i] != 0xa6 || data[i + 1] != 0x03) {
        return 0;
    }
    for (reps = 6; reps >= 0; --reps) {
        size_t suffix = i + 4u + ((size_t)reps * 4u);
        if (suffix + 4u <= size && data[suffix] == 0x20 &&
            data[suffix + 1] == 0x00 && data[suffix + 2] == 0x80 &&
            data[suffix + 3] == 0x4e) {
            return 8u + ((size_t)reps * 4u);
        }
    }
    return 0;
}

static size_t match_ppcel32_prolog_1(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(8);
    return (data[i + 2] == 0x21 && data[i + 3] == 0x94 && data[i + 4] == 0xa6 &&
            data[i + 5] == 0x02 && data[i + 6] == 0x08 && data[i + 7] == 0x7c)
               ? 8
               : 0;
}

static size_t match_ppcel64_epilog_1(const uint8_t* data, size_t size, size_t i)
{
    return match_ppcel32_epilog_1(data, size, i);
}

static size_t match_ppcel64_prolog_1(const uint8_t* data, size_t size, size_t i)
{
    return match_ppcel32_prolog_1(data, size, i);
}

static size_t match_s390x_epilog_1(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(2);
    return (data[i] == 0x07 && data[i + 1] == 0xf4) ? 2 : 0;
}

static size_t match_s390x_prolog_1(const uint8_t* data, size_t size, size_t i)
{
    NEED_BYTES(6);
    return (data[i] == 0xeb && data[i + 2] >= 0xf0 && data[i + 2] <= 0xff &&
            data[i + 5] == 0x24)
               ? 6
               : 0;
}

static const isadetect_match_fn
    ISADETECT_MATCH_FNS[ISADETECT_NUM_MATCH_FEATURES] = {
        match_amd64_epilog_1,
        match_amd64_epilog_2,
        match_amd64_epilog_3,
        match_amd64_prolog_1,
        match_amd64_prolog_2,
        match_arm32_epilog_1,
        match_arm32_epilog_2,
        match_arm32_prolog_1,
        match_arm32_prolog_2,
        match_armel32_epilog_1,
        match_armel32_epilog_2,
        match_armel32_prolog_1,
        match_armel32_prolog_2,
        match_be_one,
        match_be_stack,
        match_le_one,
        match_le_stack,
        match_mips32_epilog_1,
        match_mips32_prolog_1,
        match_mips32_prolog_2,
        match_mips32el_epilog_1,
        match_mips32el_prolog_1,
        match_mips32el_prolog_2,
        match_powerpcspe_spe_instruction_evl,
        match_powerpcspe_spe_instruction_isel,
        match_ppc32_epilog_1,
        match_ppc32_prolog_1,
        match_ppc64_epilog_1,
        match_ppc64_prolog_1,
        match_ppc64_prolog_2,
        match_ppc64_prolog_3,
        match_ppcel32_epilog_1,
        match_ppcel32_prolog_1,
        match_ppcel64_epilog_1,
        match_ppcel64_prolog_1,
        match_s390x_epilog_1,
        match_s390x_prolog_1,
};

static size_t isadetect_count_matches(const uint8_t* data, size_t size,
                                      isadetect_match_fn match_fn)
{
    size_t count = 0;
    size_t i     = 0;
    while (i < size) {
        size_t matched = match_fn(data, size, i);
        if (matched > 0) {
            ++count;
            i += matched;
        } else {
            ++i;
        }
    }
    return count;
}

void isadetect_feature_extractor_init(isadetect_feature_extractor_t* extractor)
{
    if (extractor != NULL) {
        memset(extractor, 0, sizeof(*extractor));
    }
}

static int isadetect_feature_extractor_update_match(
    isadetect_feature_extractor_t* extractor, size_t match_idx,
    const uint8_t* buffer, size_t size)
{
    size_t   pending_size;
    size_t   total_size;
    uint8_t* combined;
    size_t   i;
    size_t   safe_end;

    pending_size = extractor->pending_sizes[match_idx];
    total_size   = pending_size + size;
    combined     = (uint8_t*)malloc(total_size > 0 ? total_size : 1u);
    if (combined == NULL) {
        return ISADETECT_ERR_NOMEM;
    }

    if (pending_size > 0) {
        memcpy(combined, extractor->pending[match_idx], pending_size);
    }
    memcpy(combined + pending_size, buffer, size);

    safe_end = total_size > ISADETECT_STREAM_TAIL_SIZE
                   ? total_size - ISADETECT_STREAM_TAIL_SIZE
                   : 0u;
    i        = 0;
    while (i < safe_end) {
        size_t matched =
            ISADETECT_MATCH_FNS[match_idx](combined, total_size, i);
        if (matched > 0) {
            extractor->match_counts[match_idx] += 1u;
            i += matched;
        } else {
            ++i;
        }
    }

    extractor->pending_sizes[match_idx] = total_size - i;
    if (extractor->pending_sizes[match_idx] > 0) {
        memcpy(extractor->pending[match_idx], combined + i,
               extractor->pending_sizes[match_idx]);
    }

    free(combined);
    return ISADETECT_OK;
}

int isadetect_feature_extractor_update(isadetect_feature_extractor_t* extractor,
                                       const uint8_t* buffer, size_t size)
{
    size_t idx;
    int    rc;

    if (extractor == NULL || buffer == NULL) {
        return ISADETECT_ERR_INVALID_INPUT;
    }
    if (size == 0) {
        return ISADETECT_OK;
    }

    extractor->total_size += size;
    for (idx = 0; idx < size; ++idx) {
        extractor->byte_counts[buffer[idx]] += 1u;
    }

    for (idx = 0; idx < ISADETECT_NUM_MATCH_FEATURES; ++idx) {
        rc = isadetect_feature_extractor_update_match(extractor, idx, buffer,
                                                      size);
        if (rc != ISADETECT_OK) {
            return rc;
        }
    }

    return ISADETECT_OK;
}

int isadetect_feature_extractor_finalize(
    const isadetect_feature_extractor_t* extractor,
    double                               features[ISADETECT_NUM_FEATURES])
{
    size_t                        idx;
    double                        denom;
    isadetect_feature_extractor_t tmp;

    if (extractor == NULL || features == NULL || extractor->total_size == 0) {
        return ISADETECT_ERR_INVALID_INPUT;
    }

    tmp = *extractor;
    for (idx = 0; idx < ISADETECT_NUM_MATCH_FEATURES; ++idx) {
        tmp.match_counts[idx] += isadetect_count_matches(
            tmp.pending[idx], tmp.pending_sizes[idx], ISADETECT_MATCH_FNS[idx]);
        tmp.pending_sizes[idx] = 0;
    }

    denom = (double)tmp.total_size;
    for (idx = 0; idx < 256u; ++idx) {
        features[idx] = ((double)tmp.byte_counts[idx]) / denom;
    }
    for (idx = 0; idx < ISADETECT_NUM_MATCH_FEATURES; ++idx) {
        features[256u + idx] = ((double)tmp.match_counts[idx]) / denom;
    }

    return ISADETECT_OK;
}

int isadetect_extract_features(const uint8_t* buffer, size_t size,
                               double features[ISADETECT_NUM_FEATURES])
{
    isadetect_feature_extractor_t extractor;
    int                           rc;

    if (buffer == NULL || features == NULL || size == 0) {
        return ISADETECT_ERR_INVALID_INPUT;
    }

    isadetect_feature_extractor_init(&extractor);
    rc = isadetect_feature_extractor_update(&extractor, buffer, size);
    if (rc != ISADETECT_OK) {
        return rc;
    }
    return isadetect_feature_extractor_finalize(&extractor, features);
}

isadetect_prediction_t isadetect_predict_buffer(const isadetect_model_t* model,
                                                const uint8_t*           buffer,
                                                size_t                   size)
{
    isadetect_prediction_t       result;
    double                       features[ISADETECT_NUM_FEATURES];
    int                          best_class = 0;
    uint32_t                     idx;
    const isadetect_arch_info_t* info;

    memset(&result, 0, sizeof(result));
    result.status = isadetect_extract_features(buffer, size, features);
    if (result.status != ISADETECT_OK) {
        return result;
    }

    result.status =
        isadetect_model_predict_proba(model, features, result.probabilities);
    if (result.status != ISADETECT_OK) {
        return result;
    }

    for (idx = 1; idx < ISADETECT_NUM_CLASSES; ++idx) {
        if (result.probabilities[idx] > result.probabilities[best_class]) {
            best_class = (int)idx;
        }
    }

    result.label       = model->classes[best_class];
    result.probability = result.probabilities[best_class];

    info = isadetect_lookup_arch(result.label);
    if (info != NULL) {
        result.architecture = info->architecture;
        result.endianness   = info->endianness;
        result.wordsize     = info->wordsize;
    }

    return result;
}
