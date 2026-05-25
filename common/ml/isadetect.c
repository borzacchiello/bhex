// Copyright (c) 2022-2026, bageyelet
/*
 * The bundled model was trained using this project:
 *   https://github.com/kairis/isadetect
 *   isadetect - "ML-based ISA detection
                (architecture and endianness of binary code/sequences)"
 *   Copyright (c) 2019, Sami Kairajarvi <sami.kairajarvi@gmail.com>
 */

#include "isadetect.h"
#include "rf_model.h"

#include <string.h>

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

int isadetect_model_load(isadetect_model_t** out_model, const char* path)
{
    const bhex_rf_model_spec_t spec = {
        ISADETECT_MAGIC,
        sizeof(ISADETECT_MAGIC),
        ISADETECT_NUM_FEATURES,
        ISADETECT_NUM_CLASSES,
        0,
    };

    return bhex_rf_model_load(out_model, path, &spec);
}

void isadetect_model_free(isadetect_model_t* model)
{
    bhex_rf_model_free(model);
}

int isadetect_model_predict_proba(const isadetect_model_t* model,
                                  const double input[ISADETECT_NUM_FEATURES],
                                  double       out[ISADETECT_NUM_CLASSES])
{
    return bhex_rf_model_predict_proba(model, input, ISADETECT_NUM_FEATURES,
                                       out, ISADETECT_NUM_CLASSES);
}

int isadetect_model_predict_label(const isadetect_model_t* model,
                                  const double input[ISADETECT_NUM_FEATURES],
                                  int* label, double* probability)
{
    double probs[ISADETECT_NUM_CLASSES];
    int    best = 0;
    size_t idx;
    int    rc;

    rc = isadetect_model_predict_proba(model, input, probs);
    if (rc != ISADETECT_OK) {
        return rc;
    }

    for (idx = 1; idx < ISADETECT_NUM_CLASSES; ++idx) {
        if (probs[idx] > probs[best]) {
            best = (int)idx;
        }
    }

    if (label != NULL) {
        rc = isadetect_model_get_class_label(model, (size_t)best, label);
        if (rc != ISADETECT_OK) {
            return rc;
        }
    }
    if (probability != NULL) {
        *probability = probs[best];
    }

    return ISADETECT_OK;
}

int isadetect_model_get_class_label(const isadetect_model_t* model,
                                    size_t class_index, int* label)
{
    return bhex_rf_model_get_class_label(model, class_index, label);
}

isadetect_prediction_t isadetect_predict_buffer(const isadetect_model_t* model,
                                                const uint8_t*           buffer,
                                                size_t                   size)
{
    isadetect_prediction_t       result;
    double                       features[ISADETECT_NUM_FEATURES];
    int                          best_class = 0;
    size_t                       idx;
    int                          label = 0;
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

    result.status =
        isadetect_model_get_class_label(model, (size_t)best_class, &label);
    if (result.status != ISADETECT_OK) {
        return result;
    }

    result.label       = label;
    result.probability = result.probabilities[best_class];

    info = isadetect_lookup_arch(result.label);
    if (info != NULL) {
        result.architecture = info->architecture;
        result.endianness   = info->endianness;
        result.wordsize     = info->wordsize;
    }

    return result;
}
