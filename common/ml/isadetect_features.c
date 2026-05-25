// Copyright (c) 2022-2026, bageyelet
/*
 * The bundled models were trained using this project:
 *   https://github.com/kairis/isadetect
 *   isadetect - "ML-based ISA detection
                (architecture and endianness of binary code/sequences)"
 *   Copyright (c) 2019, Sami Kairajarvi <sami.kairajarvi@gmail.com>
 */

#include "isadetect.h"

#include <stdlib.h>
#include <string.h>

#define NEED_BYTES(nbytes)                                                     \
    do {                                                                       \
        if (i + (nbytes) > size)                                               \
            return 0;                                                          \
    } while (0)

typedef size_t (*isadetect_match_fn)(const uint8_t* data, size_t size,
                                     size_t i);

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
