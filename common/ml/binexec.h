// Copyright (c) 2022-2026, bageyelet

#ifndef BINEXEC_H
#define BINEXEC_H

#include <stddef.h>
#include <stdint.h>

#define BINEXEC_NUM_FEATURES 293
#define BINEXEC_NUM_CLASSES  2
#define BINEXEC_CHUNK_SIZE   1024

#define BINEXEC_OK                0
#define BINEXEC_ERR_INVALID_INPUT -1
#define BINEXEC_ERR_IO            -2
#define BINEXEC_ERR_FORMAT        -3
#define BINEXEC_ERR_UNSUPPORTED   -4
#define BINEXEC_ERR_NOMEM         -5

typedef struct bhex_rf_model binexec_model_t;

typedef struct binexec_prediction {
    int    status;
    int    contains_code;
    double threshold;
    double positive_probability;
    double negative_probability;
    double probabilities[BINEXEC_NUM_CLASSES];
} binexec_prediction_t;

int  binexec_model_load(binexec_model_t** out_model, const char* path);
void binexec_model_free(binexec_model_t* model);
int  binexec_model_predict_proba(const binexec_model_t* model,
                                 const double input[BINEXEC_NUM_FEATURES],
                                 double       out[BINEXEC_NUM_CLASSES]);
int  binexec_model_predict_score(const binexec_model_t* model,
                                 const double input[BINEXEC_NUM_FEATURES],
                                 double*      positive_probability,
                                 int*         contains_code);
int  binexec_chunk_contains_code(const binexec_model_t* model,
                                 const uint8_t* buffer, size_t size,
                                 int*    contains_code,
                                 double* positive_probability);
binexec_prediction_t binexec_predict_buffer(const binexec_model_t* model,
                                            const uint8_t* buffer, size_t size);

#endif
