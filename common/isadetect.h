// Copyright (c) 2022-2026, bageyelet

#ifndef ISADETECT_H
#define ISADETECT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ISADETECT_NUM_FEATURES       293
#define ISADETECT_NUM_CLASSES        23
#define ISADETECT_NUM_MATCH_FEATURES (ISADETECT_NUM_FEATURES - 256)
#define ISADETECT_STREAM_TAIL_SIZE   7

#define ISADETECT_OK                0
#define ISADETECT_ERR_INVALID_INPUT -1
#define ISADETECT_ERR_IO            -2
#define ISADETECT_ERR_FORMAT        -3
#define ISADETECT_ERR_UNSUPPORTED   -4
#define ISADETECT_ERR_NOMEM         -5

typedef struct isadetect_model isadetect_model_t;

typedef struct isadetect_prediction {
    int         status; /* 0 on success, negative on error */
    int         label;
    const char* architecture;
    const char* endianness;
    int         wordsize;
    double      probability;
    double      probabilities[ISADETECT_NUM_CLASSES];
} isadetect_prediction_t;

typedef struct isadetect_feature_extractor {
    size_t  total_size;
    size_t  byte_counts[256];
    size_t  match_counts[ISADETECT_NUM_MATCH_FEATURES];
    size_t  pending_sizes[ISADETECT_NUM_MATCH_FEATURES];
    uint8_t pending[ISADETECT_NUM_MATCH_FEATURES][ISADETECT_STREAM_TAIL_SIZE];
} isadetect_feature_extractor_t;

/* Export the sklearn random-forest model once into a compact binary file and
 * load it at runtime. */
int  isadetect_model_load(isadetect_model_t** out_model, const char* path);
void isadetect_model_free(isadetect_model_t* model);

/* Low-level APIs. */
void isadetect_feature_extractor_init(isadetect_feature_extractor_t* extractor);
int isadetect_feature_extractor_update(isadetect_feature_extractor_t* extractor,
                                       const uint8_t* buffer, size_t size);
int isadetect_feature_extractor_finalize(
    const isadetect_feature_extractor_t* extractor,
    double                               features[ISADETECT_NUM_FEATURES]);
int isadetect_extract_features(const uint8_t* buffer, size_t size,
                               double features[ISADETECT_NUM_FEATURES]);
int isadetect_model_predict_proba(const isadetect_model_t* model,
                                  const double input[ISADETECT_NUM_FEATURES],
                                  double       out[ISADETECT_NUM_CLASSES]);
int isadetect_model_predict_label(const isadetect_model_t* model,
                                  const double input[ISADETECT_NUM_FEATURES],
                                  int* label, double* probability);
int isadetect_model_get_class_label(const isadetect_model_t* model,
                                    size_t class_index, int* label);
int isadetect_describe_label(int label, const char** architecture,
                             const char** endianness, int* wordsize);

/* High-level API: predict directly from a memory buffer. */
isadetect_prediction_t isadetect_predict_buffer(const isadetect_model_t* model,
                                                const uint8_t*           buffer,
                                                size_t                   size);

#ifdef __cplusplus
}
#endif

#endif
