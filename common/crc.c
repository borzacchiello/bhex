#include "crc.h"
#include "defs.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    const char*         name;
    const crc_params_t* params;
} crc_name_map_t;

static const crc_name_map_t crc_name_table[] = {
    {"CRC-8/AUTOSAR", &crc8_autosar},
    {"CRC-8/BLUETOOTH", &crc8_bluetooth},
    {"CRC-8/CDMA2000", &crc8_cdma2000},
    {"CRC-8/DARC", &crc8_darc},
    {"CRC-8/DVB-S2", &crc8_dvb_s2},
    {"CRC-8/GSM-A", &crc8_gsm_a},
    {"CRC-8/GSM-B", &crc8_gsm_b},
    {"CRC-8/HITAG", &crc8_hitag},
    {"CRC-8/I-432-1", &crc8_i_432_1},
    {"CRC-8/I-CODE", &crc8_i_code},
    {"CRC-8/LTE", &crc8_lte},
    {"CRC-8/MAXIM-DOW", &crc8_maxim_dow},
    {"CRC-8/MIFARE-MAD", &crc8_mifare_mad},
    {"CRC-8/NRSC-5", &crc8_nrsc_5},
    {"CRC-8/OPENSAFETY", &crc8_opensafety},
    {"CRC-8/ROHC", &crc8_rohc},
    {"CRC-8/SAE-J1850", &crc8_sae_j1850},
    {"CRC-8/SMBUS", &crc8_smbus},
    {"CRC-8/TECH-3250", &crc8_tech_3250},
    {"CRC-8/WCDMA", &crc8_wcdma},

    {"CRC-16/ARC", &crc16_arc},
    {"CRC-16/CDMA2000", &crc16_cdma2000},
    {"CRC-16/CMS", &crc16_cms},
    {"CRC-16/DDS-110", &crc16_dds_110},
    {"CRC-16/DECT-R", &crc16_dect_r},
    {"CRC-16/DECT-X", &crc16_dect_x},
    {"CRC-16/DNP", &crc16_dnp},
    {"CRC-16/EN-13757", &crc16_en_13757},
    {"CRC-16/GENIBUS", &crc16_genibus},
    {"CRC-16/GSM", &crc16_gsm},
    {"CRC-16/IBM-3740", &crc16_ibm_3740},
    {"CRC-16/IBM-SDLC", &crc16_ibm_sdlc},
    {"CRC-16/ISO-IEC-14443-3-A", &crc16_iso_iec_14443_3_a},
    {"CRC-16/KERMIT", &crc16_kermit},
    {"CRC-16/LJ1200", &crc16_lj1200},
    {"CRC-16/M17", &crc16_m17},
    {"CRC-16/MAXIM-DOW", &crc16_maxim_dow},
    {"CRC-16/MCRF4XX", &crc16_mcrf4xx},
    {"CRC-16/MODBUS", &crc16_modbus},
    {"CRC-16/NRSC-5", &crc16_nrsc_5},
    {"CRC-16/OPENSAFETY-A", &crc16_opensafety_a},
    {"CRC-16/OPENSAFETY-B", &crc16_opensafety_b},
    {"CRC-16/PROFIBUS", &crc16_profibus},
    {"CRC-16/RIELLO", &crc16_riello},
    {"CRC-16/SPI-FUJITSU", &crc16_spi_fujitsu},
    {"CRC-16/T10-DIF", &crc16_t10_dif},
    {"CRC-16/TELEDISK", &crc16_teledisk},
    {"CRC-16/TMS37157", &crc16_tms37157},
    {"CRC-16/UMTS", &crc16_umts},
    {"CRC-16/USB", &crc16_usb},
    {"CRC-16/XMODEM", &crc16_xmodem},

    {"CRC-32/AIXM", &crc32_aixm},
    {"CRC-32/AUTOSAR", &crc32_autosar},
    {"CRC-32/BASE91-D", &crc32_base91_d},
    {"CRC-32/BZIP2", &crc32_bzip2},
    {"CRC-32/CD-ROM-EDC", &crc32_cd_rom_edc},
    {"CRC-32/CKSUM", &crc32_cksum},
    {"CRC-32/ISCSI", &crc32_iscsi},
    {"CRC-32/ISO-HDLC", &crc32_iso_hdlc},
    {"CRC-32/JAMCRC", &crc32_jamcrc},
    {"CRC-32/MEF", &crc32_mef},
    {"CRC-32/MPEG-2", &crc32_mpeg_2},
    {"CRC-32/XFER", &crc32_xfer},
};

static const u32_t crc_name_table_size =
    sizeof(crc_name_table) / sizeof(crc_name_table[0]);

const crc_params_t* get_crc_by_name(const char* name)
{
    if (name == NULL)
        return NULL;

    for (u32_t i = 0; i < crc_name_table_size; i++) {
        if (strcmp(name, crc_name_table[i].name) == 0)
            return crc_name_table[i].params;
    }

    return NULL;
}

const char* const* get_all_crc_names(void)
{
    static const char*
               names[sizeof(crc_name_table) / sizeof(crc_name_table[0]) + 1];
    static int initialized = 0;

    if (!initialized) {
        for (u32_t i = 0; i < crc_name_table_size; i++) {
            names[i] = crc_name_table[i].name;
        }
        names[crc_name_table_size] = NULL;
        initialized                = 1;
    }

    return names;
}

static u8_t reverse_byte(u8_t b)
{
    b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
    b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
    b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
    return b;
}

static u32_t reverse_bits(u32_t data, int width)
{
    u32_t result = 0;
    for (int i = 0; i < width; i++) {
        if (data & (1U << i)) {
            result |= (1U << (width - 1 - i));
        }
    }
    return result;
}

u32_t crc_initialize(const crc_params_t* params) { return params->init; }

u32_t crc_step(u32_t crc, const u8_t* buffer, u32_t size,
               const crc_params_t* params)
{
    u32_t poly  = params->poly;
    int   width = params->width;

    u32_t mask = (width == 32) ? 0xFFFFFFFF : ((1U << width) - 1);
    u32_t msb  = 1U << (width - 1);

    for (u32_t i = 0; i < size; i++) {
        u8_t byte = buffer[i];

        if (params->ref_in)
            byte = reverse_byte(byte);

        if (width <= 8)
            crc ^= byte;
        else if (width <= 16)
            crc ^= (u32_t)byte << (width - 8);
        else
            crc ^= (u32_t)byte << (width - 8);

        for (int bit = 0; bit < 8; bit++) {
            if (crc & msb)
                crc = (crc << 1) ^ poly;
            else
                crc <<= 1;
            crc &= mask;
        }
    }
    return crc;
}

u32_t crc_finalize(u32_t crc, const crc_params_t* params)
{
    int   width = params->width;
    u32_t mask  = (width == 32) ? 0xFFFFFFFF : ((1U << width) - 1);

    if (params->ref_out)
        crc = reverse_bits(crc, width);
    crc ^= params->xor_out;
    return crc & mask;
}

u32_t calculate_crc(const u8_t* buffer, u32_t size, const crc_params_t* params)
{
    if (!buffer || !params || size == 0)
        return 0;

    int width = params->width;
    if (width != 8 && width != 16 && width != 32)
        return 0;

    u32_t crc = crc_initialize(params);
    crc       = crc_step(crc, buffer, size, params);
    return crc_finalize(crc, params);
}

// clang-format off
crc_params_t crc8_autosar = {.poly = 0x2F, .init = 0xFF, .ref_in = 0, .ref_out = 0, .xor_out = 0xFF, .width = 8};
crc_params_t crc8_bluetooth = {.poly = 0xA7, .init = 0x00, .ref_in = 1, .ref_out = 1, .xor_out = 0x00, .width = 8};
crc_params_t crc8_cdma2000 = {.poly = 0x9B, .init = 0xFF, .ref_in = 0, .ref_out = 0, .xor_out = 0x00, .width = 8};
crc_params_t crc8_darc = {.poly = 0x39, .init = 0x00, .ref_in = 1, .ref_out = 1, .xor_out = 0x00, .width = 8};
crc_params_t crc8_dvb_s2 = {.poly = 0xD5, .init = 0x00, .ref_in = 0, .ref_out = 0, .xor_out = 0x00, .width = 8};
crc_params_t crc8_gsm_a = {.poly = 0x1D, .init = 0x00, .ref_in = 0, .ref_out = 0, .xor_out = 0x00, .width = 8};
crc_params_t crc8_gsm_b = {.poly = 0x49, .init = 0x00, .ref_in = 0, .ref_out = 0, .xor_out = 0xFF, .width = 8};
crc_params_t crc8_hitag = {.poly = 0x1D, .init = 0xFF, .ref_in = 0, .ref_out = 0, .xor_out = 0x00, .width = 8};
crc_params_t crc8_i_432_1 = {.poly = 0x07, .init = 0x00, .ref_in = 0, .ref_out = 0, .xor_out = 0x55, .width = 8};
crc_params_t crc8_i_code = {.poly = 0x1D, .init = 0xFD, .ref_in = 0, .ref_out = 0, .xor_out = 0x00, .width = 8};
crc_params_t crc8_lte = {.poly = 0x9B, .init = 0x00, .ref_in = 0, .ref_out = 0, .xor_out = 0x00, .width = 8};
crc_params_t crc8_maxim_dow = {.poly = 0x31, .init = 0x00, .ref_in = 1, .ref_out = 1, .xor_out = 0x00, .width = 8};
crc_params_t crc8_mifare_mad = {.poly = 0x1D, .init = 0xC7, .ref_in = 0, .ref_out = 0, .xor_out = 0x00, .width = 8};
crc_params_t crc8_nrsc_5 = {.poly = 0x31, .init = 0xFF, .ref_in = 0, .ref_out = 0, .xor_out = 0x00, .width = 8};
crc_params_t crc8_opensafety = {.poly = 0x2F, .init = 0x00, .ref_in = 0, .ref_out = 0, .xor_out = 0x00, .width = 8};
crc_params_t crc8_rohc = {.poly = 0x07, .init = 0xFF, .ref_in = 1, .ref_out = 1, .xor_out = 0x00, .width = 8};
crc_params_t crc8_sae_j1850 = {.poly = 0x1D, .init = 0xFF, .ref_in = 0, .ref_out = 0, .xor_out = 0xFF, .width = 8};
crc_params_t crc8_smbus = {.poly = 0x07, .init = 0x00, .ref_in = 0, .ref_out = 0, .xor_out = 0x00, .width = 8};
crc_params_t crc8_tech_3250 = {.poly = 0x1D, .init = 0xFF, .ref_in = 1, .ref_out = 1, .xor_out = 0x00, .width = 8};
crc_params_t crc8_wcdma = {.poly = 0x9B, .init = 0x00, .ref_in = 1, .ref_out = 1, .xor_out = 0x00, .width = 8};

crc_params_t crc16_arc = {.poly = 0x8005, .init = 0x0000, .ref_in = 1, .ref_out = 1, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_cdma2000 = {.poly = 0xC867, .init = 0xFFFF, .ref_in = 0, .ref_out = 0, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_cms = {.poly = 0x8005, .init = 0xFFFF, .ref_in = 0, .ref_out = 0, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_dds_110 = {.poly = 0x8005, .init = 0x800D, .ref_in = 0, .ref_out = 0, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_dect_r = {.poly = 0x0589, .init = 0x0000, .ref_in = 0, .ref_out = 0, .xor_out = 0x0001, .width = 16};
crc_params_t crc16_dect_x = {.poly = 0x0589, .init = 0x0000, .ref_in = 0, .ref_out = 0, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_dnp = {.poly = 0x3D65, .init = 0x0000, .ref_in = 1, .ref_out = 1, .xor_out = 0xFFFF, .width = 16};
crc_params_t crc16_en_13757 = {.poly = 0x3D65, .init = 0x0000, .ref_in = 0, .ref_out = 0, .xor_out = 0xFFFF, .width = 16};
crc_params_t crc16_genibus = {.poly = 0x1021, .init = 0xFFFF, .ref_in = 0, .ref_out = 0, .xor_out = 0xFFFF, .width = 16};
crc_params_t crc16_gsm = {.poly = 0x1021, .init = 0x0000, .ref_in = 0, .ref_out = 0, .xor_out = 0xFFFF, .width = 16};
crc_params_t crc16_ibm_3740 = {.poly = 0x1021, .init = 0xFFFF, .ref_in = 0, .ref_out = 0, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_ibm_sdlc = {.poly = 0x1021, .init = 0xFFFF, .ref_in = 1, .ref_out = 1, .xor_out = 0xFFFF, .width = 16};
crc_params_t crc16_iso_iec_14443_3_a = {.poly = 0x1021, .init = 0xC6C6, .ref_in = 1, .ref_out = 1, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_kermit = {.poly = 0x1021, .init = 0x0000, .ref_in = 1, .ref_out = 1, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_lj1200 = {.poly = 0x6F63, .init = 0x0000, .ref_in = 0, .ref_out = 0, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_m17 = {.poly = 0x5935, .init = 0xFFFF, .ref_in = 0, .ref_out = 0, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_maxim_dow = {.poly = 0x8005, .init = 0x0000, .ref_in = 1, .ref_out = 1, .xor_out = 0xFFFF, .width = 16};
crc_params_t crc16_mcrf4xx = {.poly = 0x1021, .init = 0xFFFF, .ref_in = 1, .ref_out = 1, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_modbus = {.poly = 0x8005, .init = 0xFFFF, .ref_in = 1, .ref_out = 1, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_nrsc_5 = {.poly = 0x080B, .init = 0xFFFF, .ref_in = 1, .ref_out = 1, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_opensafety_a = {.poly = 0x5935, .init = 0x0000, .ref_in = 0, .ref_out = 0, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_opensafety_b = {.poly = 0x755B, .init = 0x0000, .ref_in = 0, .ref_out = 0, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_profibus = {.poly = 0x1DCF, .init = 0xFFFF, .ref_in = 0, .ref_out = 0, .xor_out = 0xFFFF, .width = 16};
crc_params_t crc16_riello = {.poly = 0x1021, .init = 0xB2AA, .ref_in = 1, .ref_out = 1, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_spi_fujitsu = {.poly = 0x1021, .init = 0x1D0F, .ref_in = 0, .ref_out = 0, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_t10_dif = {.poly = 0x8BB7, .init = 0x0000, .ref_in = 0, .ref_out = 0, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_teledisk = {.poly = 0xA097, .init = 0x0000, .ref_in = 0, .ref_out = 0, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_tms37157 = {.poly = 0x1021, .init = 0x89EC, .ref_in = 1, .ref_out = 1, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_umts = {.poly = 0x8005, .init = 0x0000, .ref_in = 0, .ref_out = 0, .xor_out = 0x0000, .width = 16};
crc_params_t crc16_usb = {.poly = 0x8005, .init = 0xFFFF, .ref_in = 1, .ref_out = 1, .xor_out = 0xFFFF, .width = 16};
crc_params_t crc16_xmodem = {.poly = 0x1021, .init = 0x0000, .ref_in = 0, .ref_out = 0, .xor_out = 0x0000, .width = 16};

crc_params_t crc32_aixm = {.poly = 0x814141AB, .init = 0x00000000, .ref_in = 0, .ref_out = 0, .xor_out = 0x00000000, .width = 32};
crc_params_t crc32_autosar = {.poly = 0xF4ACFB13, .init = 0xFFFFFFFF, .ref_in = 1, .ref_out = 1, .xor_out = 0xFFFFFFFF, .width = 32};
crc_params_t crc32_base91_d = {.poly = 0xA833982B, .init = 0xFFFFFFFF, .ref_in = 1, .ref_out = 1, .xor_out = 0xFFFFFFFF, .width = 32};
crc_params_t crc32_bzip2 = {.poly = 0x04C11DB7, .init = 0xFFFFFFFF, .ref_in = 0, .ref_out = 0, .xor_out = 0xFFFFFFFF, .width = 32};
crc_params_t crc32_cd_rom_edc = {.poly = 0x8001801B, .init = 0x00000000, .ref_in = 1, .ref_out = 1, .xor_out = 0x00000000, .width = 32};
crc_params_t crc32_cksum = {.poly = 0x04C11DB7, .init = 0x00000000, .ref_in = 0, .ref_out = 0, .xor_out = 0xFFFFFFFF, .width = 32};
crc_params_t crc32_iscsi = {.poly = 0x1EDC6F41, .init = 0xFFFFFFFF, .ref_in = 1, .ref_out = 1, .xor_out = 0xFFFFFFFF, .width = 32};
crc_params_t crc32_iso_hdlc = {.poly = 0x04C11DB7, .init = 0xFFFFFFFF, .ref_in = 1, .ref_out = 1, .xor_out = 0xFFFFFFFF, .width = 32};
crc_params_t crc32_jamcrc = {.poly = 0x04C11DB7, .init = 0xFFFFFFFF, .ref_in = 1, .ref_out = 1, .xor_out = 0x00000000, .width = 32};
crc_params_t crc32_mef = {.poly = 0x741B8CD7, .init = 0xFFFFFFFF, .ref_in = 1, .ref_out = 1, .xor_out = 0x00000000, .width = 32};
crc_params_t crc32_mpeg_2 = {.poly = 0x04C11DB7, .init = 0xFFFFFFFF, .ref_in = 0, .ref_out = 0, .xor_out = 0x00000000, .width = 32};
crc_params_t crc32_xfer = {.poly = 0x000000AF, .init = 0x00000000, .ref_in = 0, .ref_out = 0, .xor_out = 0x00000000, .width = 32};
// clang-format on
