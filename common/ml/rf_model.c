// Copyright (c) 2022-2026, bageyelet

#include "rf_model.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct bhex_rf_tree {
    uint32_t node_count;
    uint32_t leaf_count;
    int32_t* left;
    int32_t* right;
    int16_t* feature;
    double*  threshold;
    int32_t* leaf_index;
    float*   leaf_probs;
} bhex_rf_tree_t;

struct bhex_rf_model {
    uint32_t        num_features;
    uint32_t        num_classes;
    uint32_t        num_trees;
    size_t          extra_header_size;
    uint8_t*        extra_header;
    int32_t*        classes;
    bhex_rf_tree_t* trees;
};

static int bhex_rf_read_exact(FILE* fp, void* buffer, size_t size)
{
    return fread(buffer, 1u, size, fp) == size ? BHEX_ML_OK : BHEX_ML_ERR_IO;
}

static int bhex_rf_read_u32_le(FILE* fp, uint32_t* value)
{
    uint8_t b[4];

    if (bhex_rf_read_exact(fp, b, sizeof(b)) != BHEX_ML_OK) {
        return BHEX_ML_ERR_IO;
    }

    *value = ((uint32_t)b[0]) | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
             ((uint32_t)b[3] << 24);
    return BHEX_ML_OK;
}

static int bhex_rf_read_i16_array_le(FILE* fp, int16_t* values, size_t count)
{
    size_t idx;

    for (idx = 0; idx < count; ++idx) {
        uint8_t  b[2];
        uint16_t raw;

        if (bhex_rf_read_exact(fp, b, sizeof(b)) != BHEX_ML_OK) {
            return BHEX_ML_ERR_IO;
        }

        raw         = (uint16_t)(((uint16_t)b[0]) | ((uint16_t)b[1] << 8));
        values[idx] = (int16_t)raw;
    }

    return BHEX_ML_OK;
}

static int bhex_rf_read_i32_array_le(FILE* fp, int32_t* values, size_t count)
{
    size_t idx;

    for (idx = 0; idx < count; ++idx) {
        uint32_t raw;
        int      rc = bhex_rf_read_u32_le(fp, &raw);
        if (rc != BHEX_ML_OK) {
            return rc;
        }
        values[idx] = (int32_t)raw;
    }

    return BHEX_ML_OK;
}

static int bhex_rf_read_float_array_le(FILE* fp, float* values, size_t count)
{
    size_t idx;

    for (idx = 0; idx < count; ++idx) {
        uint32_t raw;
        int      rc = bhex_rf_read_u32_le(fp, &raw);
        if (rc != BHEX_ML_OK) {
            return rc;
        }
        memcpy(&values[idx], &raw, sizeof(raw));
    }

    return BHEX_ML_OK;
}

static int bhex_rf_read_double_array_le(FILE* fp, double* values, size_t count)
{
    size_t idx;

    for (idx = 0; idx < count; ++idx) {
        uint8_t  b[8];
        uint64_t raw;

        if (bhex_rf_read_exact(fp, b, sizeof(b)) != BHEX_ML_OK) {
            return BHEX_ML_ERR_IO;
        }

        raw = ((uint64_t)b[0]) | ((uint64_t)b[1] << 8) |
              ((uint64_t)b[2] << 16) | ((uint64_t)b[3] << 24) |
              ((uint64_t)b[4] << 32) | ((uint64_t)b[5] << 40) |
              ((uint64_t)b[6] << 48) | ((uint64_t)b[7] << 56);
        memcpy(&values[idx], &raw, sizeof(raw));
    }

    return BHEX_ML_OK;
}

static void bhex_rf_free_tree(bhex_rf_tree_t* tree)
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

void bhex_rf_model_free(bhex_rf_model_t* model)
{
    size_t idx;

    if (model == NULL) {
        return;
    }

    if (model->trees != NULL) {
        for (idx = 0; idx < model->num_trees; ++idx) {
            bhex_rf_free_tree(&model->trees[idx]);
        }
    }

    free(model->extra_header);
    free(model->trees);
    free(model->classes);
    free(model);
}

int bhex_rf_model_load(bhex_rf_model_t** out_model, const char* path,
                       const bhex_rf_model_spec_t* spec)
{
    FILE*            fp    = NULL;
    bhex_rf_model_t* model = NULL;
    uint8_t*         magic = NULL;
    uint32_t         idx;
    int              rc = BHEX_ML_OK;

    if (out_model == NULL || path == NULL || spec == NULL ||
        spec->magic == NULL || spec->magic_size == 0 ||
        spec->num_features == 0 || spec->num_classes == 0) {
        return BHEX_ML_ERR_INVALID_INPUT;
    }

    *out_model = NULL;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return BHEX_ML_ERR_IO;
    }

    magic = (uint8_t*)malloc(spec->magic_size);
    if (magic == NULL) {
        rc = BHEX_ML_ERR_NOMEM;
        goto cleanup;
    }

    if (bhex_rf_read_exact(fp, magic, spec->magic_size) != BHEX_ML_OK ||
        memcmp(magic, spec->magic, spec->magic_size) != 0) {
        rc = BHEX_ML_ERR_FORMAT;
        goto cleanup;
    }

    model = (bhex_rf_model_t*)calloc(1u, sizeof(*model));
    if (model == NULL) {
        rc = BHEX_ML_ERR_NOMEM;
        goto cleanup;
    }

    rc = bhex_rf_read_u32_le(fp, &model->num_features);
    if (rc != BHEX_ML_OK)
        goto cleanup;
    rc = bhex_rf_read_u32_le(fp, &model->num_classes);
    if (rc != BHEX_ML_OK)
        goto cleanup;
    rc = bhex_rf_read_u32_le(fp, &model->num_trees);
    if (rc != BHEX_ML_OK)
        goto cleanup;

    if (model->num_features != spec->num_features ||
        model->num_classes != spec->num_classes || model->num_trees == 0u) {
        rc = BHEX_ML_ERR_UNSUPPORTED;
        goto cleanup;
    }

    model->extra_header_size = spec->extra_header_size;
    if (model->extra_header_size != 0u) {
        model->extra_header = (uint8_t*)malloc(
            model->extra_header_size > 0u ? model->extra_header_size : 1u);
        if (model->extra_header == NULL) {
            rc = BHEX_ML_ERR_NOMEM;
            goto cleanup;
        }
        rc = bhex_rf_read_exact(fp, model->extra_header,
                                model->extra_header_size);
        if (rc != BHEX_ML_OK) {
            goto cleanup;
        }
    }

    model->classes =
        (int32_t*)calloc(model->num_classes, sizeof(*model->classes));
    model->trees =
        (bhex_rf_tree_t*)calloc(model->num_trees, sizeof(*model->trees));
    if (model->classes == NULL || model->trees == NULL) {
        rc = BHEX_ML_ERR_NOMEM;
        goto cleanup;
    }

    rc = bhex_rf_read_i32_array_le(fp, model->classes, model->num_classes);
    if (rc != BHEX_ML_OK)
        goto cleanup;

    for (idx = 0; idx < model->num_trees; ++idx) {
        bhex_rf_tree_t* tree = &model->trees[idx];
        size_t          node_count;
        size_t          leaf_prob_count;

        rc = bhex_rf_read_u32_le(fp, &tree->node_count);
        if (rc != BHEX_ML_OK)
            goto cleanup;
        rc = bhex_rf_read_u32_le(fp, &tree->leaf_count);
        if (rc != BHEX_ML_OK)
            goto cleanup;
        if (tree->node_count == 0u || tree->leaf_count == 0u) {
            rc = BHEX_ML_ERR_FORMAT;
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
            rc = BHEX_ML_ERR_NOMEM;
            goto cleanup;
        }

        rc = bhex_rf_read_i32_array_le(fp, tree->left, node_count);
        if (rc != BHEX_ML_OK)
            goto cleanup;
        rc = bhex_rf_read_i32_array_le(fp, tree->right, node_count);
        if (rc != BHEX_ML_OK)
            goto cleanup;
        rc = bhex_rf_read_i16_array_le(fp, tree->feature, node_count);
        if (rc != BHEX_ML_OK)
            goto cleanup;
        rc = bhex_rf_read_double_array_le(fp, tree->threshold, node_count);
        if (rc != BHEX_ML_OK)
            goto cleanup;
        rc = bhex_rf_read_i32_array_le(fp, tree->leaf_index, node_count);
        if (rc != BHEX_ML_OK)
            goto cleanup;
        rc = bhex_rf_read_float_array_le(fp, tree->leaf_probs, leaf_prob_count);
        if (rc != BHEX_ML_OK)
            goto cleanup;
    }

    fclose(fp);
    free(magic);
    *out_model = model;
    return BHEX_ML_OK;

cleanup:
    if (fp != NULL) {
        fclose(fp);
    }
    free(magic);
    bhex_rf_model_free(model);
    return rc;
}

int bhex_rf_model_predict_proba(const bhex_rf_model_t* model,
                                const double* input, size_t input_features,
                                double* out, size_t out_classes)
{
    uint32_t tree_idx;
    uint32_t cls;

    if (model == NULL || input == NULL || out == NULL ||
        input_features != model->num_features ||
        out_classes != model->num_classes) {
        return BHEX_ML_ERR_INVALID_INPUT;
    }

    for (cls = 0; cls < model->num_classes; ++cls) {
        out[cls] = 0.0;
    }

    for (tree_idx = 0; tree_idx < model->num_trees; ++tree_idx) {
        const bhex_rf_tree_t* tree = &model->trees[tree_idx];
        int32_t               node = 0;

        while (node >= 0 && (uint32_t)node < tree->node_count &&
               tree->feature[node] >= 0) {
            int16_t feature = tree->feature[node];
            if ((uint32_t)feature >= model->num_features) {
                return BHEX_ML_ERR_FORMAT;
            }
            node = (input[feature] <= tree->threshold[node])
                       ? tree->left[node]
                       : tree->right[node];
        }
        if (node < 0 || (uint32_t)node >= tree->node_count) {
            return BHEX_ML_ERR_FORMAT;
        }

        {
            int32_t      leaf = tree->leaf_index[node];
            const float* probs;

            if (leaf < 0 || (uint32_t)leaf >= tree->leaf_count) {
                return BHEX_ML_ERR_FORMAT;
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

    return BHEX_ML_OK;
}

int bhex_rf_model_get_class_label(const bhex_rf_model_t* model,
                                  size_t class_index, int* label)
{
    if (model == NULL || label == NULL || class_index >= model->num_classes) {
        return BHEX_ML_ERR_INVALID_INPUT;
    }

    *label = model->classes[class_index];
    return BHEX_ML_OK;
}

int bhex_rf_model_get_header_extra(const bhex_rf_model_t* model, void* out,
                                   size_t size)
{
    if (model == NULL) {
        return BHEX_ML_ERR_INVALID_INPUT;
    }
    if (size != model->extra_header_size) {
        return BHEX_ML_ERR_INVALID_INPUT;
    }
    if (size == 0u) {
        return BHEX_ML_OK;
    }
    if (out == NULL || model->extra_header == NULL) {
        return BHEX_ML_ERR_INVALID_INPUT;
    }

    memcpy(out, model->extra_header, size);
    return BHEX_ML_OK;
}

uint32_t bhex_rf_model_num_features(const bhex_rf_model_t* model)
{
    return model != NULL ? model->num_features : 0u;
}

uint32_t bhex_rf_model_num_classes(const bhex_rf_model_t* model)
{
    return model != NULL ? model->num_classes : 0u;
}

const char* bhex_ml_err_to_string(int err)
{
    switch (err) {
        case BHEX_ML_OK:
            return "no error";
        case BHEX_ML_ERR_INVALID_INPUT:
            return "invalid input";
        case BHEX_ML_ERR_IO:
            return "I/O error";
        case BHEX_ML_ERR_FORMAT:
            return "invalid model format";
        case BHEX_ML_ERR_UNSUPPORTED:
            return "unsupported model";
        case BHEX_ML_ERR_NOMEM:
            return "out of memory";
        default:
            return "unknown error";
    }
}
