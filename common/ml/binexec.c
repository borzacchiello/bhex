// Copyright (c) 2022-2026, bageyelet

#include "binexec.h"
#include "isadetect.h"
#include "rf_model.h"

#include <string.h>

static const uint8_t BINEXEC_MAGIC[8] = {'B', 'I', 'N', 'E',
                                         'R', 'F', '0', '1'};

static int binexec_get_threshold(const binexec_model_t* model,
                                 double*                threshold)
{
    if (threshold == NULL) {
        return BINEXEC_ERR_INVALID_INPUT;
    }
    return bhex_rf_model_get_header_extra(model, threshold, sizeof(*threshold));
}

int binexec_model_load(binexec_model_t** out_model, const char* path)
{
    const bhex_rf_model_spec_t spec = {
        BINEXEC_MAGIC,       sizeof(BINEXEC_MAGIC), BINEXEC_NUM_FEATURES,
        BINEXEC_NUM_CLASSES, sizeof(double),
    };
    int              rc;
    binexec_model_t* model;
    int              label0;
    int              label1;

    rc = bhex_rf_model_load(out_model, path, &spec);
    if (rc != BINEXEC_OK) {
        return rc;
    }

    model = *out_model;
    rc    = bhex_rf_model_get_class_label(model, 0u, &label0);
    if (rc != BINEXEC_OK) {
        binexec_model_free(model);
        *out_model = NULL;
        return rc;
    }
    rc = bhex_rf_model_get_class_label(model, 1u, &label1);
    if (rc != BINEXEC_OK) {
        binexec_model_free(model);
        *out_model = NULL;
        return rc;
    }
    if (label0 != 0 || label1 != 1) {
        binexec_model_free(model);
        *out_model = NULL;
        return BINEXEC_ERR_UNSUPPORTED;
    }

    return BINEXEC_OK;
}

void binexec_model_free(binexec_model_t* model) { bhex_rf_model_free(model); }

int binexec_model_predict_proba(const binexec_model_t* model,
                                const double input[BINEXEC_NUM_FEATURES],
                                double       out[BINEXEC_NUM_CLASSES])
{
    return bhex_rf_model_predict_proba(model, input, BINEXEC_NUM_FEATURES, out,
                                       BINEXEC_NUM_CLASSES);
}

int binexec_model_predict_score(const binexec_model_t* model,
                                const double input[BINEXEC_NUM_FEATURES],
                                double*      positive_probability,
                                int*         contains_code)
{
    double probs[BINEXEC_NUM_CLASSES];
    double threshold;
    int    rc;

    rc = binexec_model_predict_proba(model, input, probs);
    if (rc != BINEXEC_OK) {
        return rc;
    }

    rc = binexec_get_threshold(model, &threshold);
    if (rc != BINEXEC_OK) {
        return rc;
    }

    if (positive_probability != NULL) {
        *positive_probability = probs[1];
    }
    if (contains_code != NULL) {
        *contains_code = probs[1] >= threshold ? 1 : 0;
    }

    return BINEXEC_OK;
}

int binexec_chunk_contains_code(const binexec_model_t* model,
                                const uint8_t* buffer, size_t size,
                                int*    contains_code,
                                double* positive_probability)
{
    double features[BINEXEC_NUM_FEATURES];
    int    rc;

    rc = isadetect_extract_features(buffer, size, features);
    if (rc != ISADETECT_OK) {
        return rc;
    }

    return binexec_model_predict_score(model, features, positive_probability,
                                       contains_code);
}

binexec_prediction_t binexec_predict_buffer(const binexec_model_t* model,
                                            const uint8_t* buffer, size_t size)
{
    binexec_prediction_t result;
    double               features[BINEXEC_NUM_FEATURES];

    memset(&result, 0, sizeof(result));
    if (model == NULL) {
        result.status = BINEXEC_ERR_INVALID_INPUT;
        return result;
    }

    result.status = isadetect_extract_features(buffer, size, features);
    if (result.status != ISADETECT_OK) {
        return result;
    }

    result.status =
        binexec_model_predict_proba(model, features, result.probabilities);
    if (result.status != BINEXEC_OK) {
        return result;
    }

    result.status = binexec_get_threshold(model, &result.threshold);
    if (result.status != BINEXEC_OK) {
        return result;
    }

    result.negative_probability = result.probabilities[0];
    result.positive_probability = result.probabilities[1];
    result.contains_code =
        result.positive_probability >= result.threshold ? 1 : 0;
    return result;
}
