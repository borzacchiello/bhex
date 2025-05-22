#include "defs.h"

typedef struct crc_params_t {
    u32_t    poly;    // Generator polynomial
    u32_t    init;    // Initial value
    u8_t     ref_in;  // Reflect input bytes (1;
    u8_t     ref_out; // Reflect output (1;
    uint32_t xor_out; // XOR applied to final result
    u8_t     width;   // CRC width in bits (8, 16, 32)
} crc_params_t;

u32_t crc_initialize(const crc_params_t* params);
u32_t crc_step(u32_t crc, const u8_t* buffer, u32_t size,
               const crc_params_t* params);
u32_t crc_finalize(u32_t crc, const crc_params_t* params);

u32_t calculate_crc(const u8_t* buffer, u32_t size, const crc_params_t* params);
const crc_params_t* get_crc_by_name(const char* name);
const char* const*  get_all_crc_names(void);

extern crc_params_t crc8_autosar;
extern crc_params_t crc8_bluetooth;
extern crc_params_t crc8_cdma2000;
extern crc_params_t crc8_darc;
extern crc_params_t crc8_dvb_s2;
extern crc_params_t crc8_gsm_a;
extern crc_params_t crc8_gsm_b;
extern crc_params_t crc8_hitag;
extern crc_params_t crc8_i_432_1;
extern crc_params_t crc8_i_code;
extern crc_params_t crc8_lte;
extern crc_params_t crc8_maxim_dow;
extern crc_params_t crc8_mifare_mad;
extern crc_params_t crc8_nrsc_5;
extern crc_params_t crc8_opensafety;
extern crc_params_t crc8_rohc;
extern crc_params_t crc8_sae_j1850;
extern crc_params_t crc8_smbus;
extern crc_params_t crc8_tech_3250;
extern crc_params_t crc8_wcdma;

extern crc_params_t crc16_arc;
extern crc_params_t crc16_cdma2000;
extern crc_params_t crc16_cms;
extern crc_params_t crc16_dds_110;
extern crc_params_t crc16_dect_r;
extern crc_params_t crc16_dect_x;
extern crc_params_t crc16_dnp;
extern crc_params_t crc16_en_13757;
extern crc_params_t crc16_genibus;
extern crc_params_t crc16_gsm;
extern crc_params_t crc16_ibm_3740;
extern crc_params_t crc16_ibm_sdlc;
extern crc_params_t crc16_iso_iec_14443_3_a;
extern crc_params_t crc16_kermit;
extern crc_params_t crc16_lj1200;
extern crc_params_t crc16_m17;
extern crc_params_t crc16_maxim_dow;
extern crc_params_t crc16_mcrf4xx;
extern crc_params_t crc16_modbus;
extern crc_params_t crc16_nrsc_5;
extern crc_params_t crc16_opensafety_a;
extern crc_params_t crc16_opensafety_b;
extern crc_params_t crc16_profibus;
extern crc_params_t crc16_riello;
extern crc_params_t crc16_spi_fujitsu;
extern crc_params_t crc16_t10_dif;
extern crc_params_t crc16_teledisk;
extern crc_params_t crc16_tms37157;
extern crc_params_t crc16_umts;
extern crc_params_t crc16_usb;
extern crc_params_t crc16_xmodem;

extern crc_params_t crc32_aixm;
extern crc_params_t crc32_autosar;
extern crc_params_t crc32_base91_d;
extern crc_params_t crc32_bzip2;
extern crc_params_t crc32_cd_rom_edc;
extern crc_params_t crc32_cksum;
extern crc_params_t crc32_iscsi;
extern crc_params_t crc32_iso_hdlc;
extern crc_params_t crc32_jamcrc;
extern crc_params_t crc32_mef;
extern crc_params_t crc32_mpeg_2;
extern crc_params_t crc32_xfer;
