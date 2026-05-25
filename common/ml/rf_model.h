// Copyright (c) 2022-2026, bageyelet

#ifndef RF_MODEL_H
#define RF_MODEL_H

#include <stddef.h>
#include <stdint.h>

#define BHEX_ML_OK                0
#define BHEX_ML_ERR_INVALID_INPUT -1
#define BHEX_ML_ERR_IO            -2
#define BHEX_ML_ERR_FORMAT        -3
#define BHEX_ML_ERR_UNSUPPORTED   -4
#define BHEX_ML_ERR_NOMEM         -5

typedef struct bhex_rf_model bhex_rf_model_t;

typedef struct bhex_rf_model_spec {
    const uint8_t* magic;
    size_t         magic_size;
    uint32_t       num_features;
    uint32_t       num_classes;
    size_t         extra_header_size;
} bhex_rf_model_spec_t;

int      bhex_rf_model_load(bhex_rf_model_t** out_model, const char* path,
                            const bhex_rf_model_spec_t* spec);
void     bhex_rf_model_free(bhex_rf_model_t* model);
int      bhex_rf_model_predict_proba(const bhex_rf_model_t* model,
                                     const double* input, size_t input_features,
                                     double* out, size_t out_classes);
int      bhex_rf_model_get_class_label(const bhex_rf_model_t* model,
                                       size_t class_index, int* label);
int      bhex_rf_model_get_header_extra(const bhex_rf_model_t* model, void* out,
                                        size_t size);
int      bhex_rf_model_get_header_double_le(const bhex_rf_model_t* model,
                                            size_t offset, double* value);
uint32_t bhex_rf_model_num_features(const bhex_rf_model_t* model);
uint32_t bhex_rf_model_num_classes(const bhex_rf_model_t* model);
const char* bhex_ml_err_to_string(int err);

#endif
