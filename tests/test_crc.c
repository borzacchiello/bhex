#include "t.h"
#include <crc.h>

#ifndef TEST
#define TEST(name) test_##name
#endif

static const u8_t  test_data[]    = "123456789";
static const u32_t test_data_size = 9;

int TEST(crc8_autosar)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_autosar);
    u32_t expected = 0xDF;
    return result == expected;
}

int TEST(crc8_bluetooth)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_bluetooth);
    u32_t expected = 0x26;
    return result == expected;
}

int TEST(crc8_cdma2000)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_cdma2000);
    u32_t expected = 0xDA;
    return result == expected;
}

int TEST(crc8_darc)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_darc);
    u32_t expected = 0x15;
    return result == expected;
}

int TEST(crc8_dvb_s2)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_dvb_s2);
    u32_t expected = 0xBC;
    return result == expected;
}

int TEST(crc8_gsm_a)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_gsm_a);
    u32_t expected = 0x37;
    return result == expected;
}

int TEST(crc8_gsm_b)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_gsm_b);
    u32_t expected = 0x94;
    return result == expected;
}

int TEST(crc8_hitag)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_hitag);
    u32_t expected = 0xB4;
    return result == expected;
}

int TEST(crc8_i_432_1)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_i_432_1);
    u32_t expected = 0xA1;
    return result == expected;
}

int TEST(crc8_i_code)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_i_code);
    u32_t expected = 0x7E;
    return result == expected;
}

int TEST(crc8_lte)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_lte);
    u32_t expected = 0xEA;
    return result == expected;
}

int TEST(crc8_maxim_dow)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_maxim_dow);
    u32_t expected = 0xA1;
    return result == expected;
}

int TEST(crc8_mifare_mad)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_mifare_mad);
    u32_t expected = 0x99;
    return result == expected;
}

int TEST(crc8_nrsc_5)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_nrsc_5);
    u32_t expected = 0xF7;
    return result == expected;
}

int TEST(crc8_opensafety)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_opensafety);
    u32_t expected = 0x3E;
    return result == expected;
}

int TEST(crc8_rohc)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_rohc);
    u32_t expected = 0xD0;
    return result == expected;
}

int TEST(crc8_sae_j1850)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_sae_j1850);
    u32_t expected = 0x4B;
    return result == expected;
}

int TEST(crc8_smbus)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_smbus);
    u32_t expected = 0xF4;
    return result == expected;
}

int TEST(crc8_tech_3250)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_tech_3250);
    u32_t expected = 0x97;
    return result == expected;
}

int TEST(crc8_wcdma)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc8_wcdma);
    u32_t expected = 0x25;
    return result == expected;
}

int TEST(crc16_arc)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_arc);
    u32_t expected = 0xBB3D;
    return result == expected;
}

int TEST(crc16_cdma2000)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_cdma2000);
    u32_t expected = 0x4C06;
    return result == expected;
}

int TEST(crc16_cms)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_cms);
    u32_t expected = 0xAEE7;
    return result == expected;
}

int TEST(crc16_dds_110)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_dds_110);
    u32_t expected = 0x9ECF;
    return result == expected;
}

int TEST(crc16_dect_r)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_dect_r);
    u32_t expected = 0x007E;
    return result == expected;
}

int TEST(crc16_dect_x)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_dect_x);
    u32_t expected = 0x007F;
    return result == expected;
}

int TEST(crc16_dnp)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_dnp);
    u32_t expected = 0xEA82;
    return result == expected;
}

int TEST(crc16_en_13757)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_en_13757);
    u32_t expected = 0xC2B7;
    return result == expected;
}

int TEST(crc16_genibus)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_genibus);
    u32_t expected = 0xD64E;
    return result == expected;
}

int TEST(crc16_gsm)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_gsm);
    u32_t expected = 0xCE3C;
    return result == expected;
}

int TEST(crc16_ibm_3740)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_ibm_3740);
    u32_t expected = 0x29B1;
    return result == expected;
}

int TEST(crc16_ibm_sdlc)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_ibm_sdlc);
    u32_t expected = 0x906E;
    return result == expected;
}

int TEST(crc16_iso_iec_14443_3_a)(void)
{
    u32_t result =
        calculate_crc(test_data, test_data_size, &crc16_iso_iec_14443_3_a);
    u32_t expected = 0xBF05;
    return result == expected;
}

int TEST(crc16_kermit)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_kermit);
    u32_t expected = 0x2189;
    return result == expected;
}

int TEST(crc16_lj1200)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_lj1200);
    u32_t expected = 0xBDF4;
    return result == expected;
}

int TEST(crc16_m17)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_m17);
    u32_t expected = 0x772B;
    return result == expected;
}

int TEST(crc16_maxim_dow)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_maxim_dow);
    u32_t expected = 0x44C2;
    return result == expected;
}

int TEST(crc16_mcrf4xx)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_mcrf4xx);
    u32_t expected = 0x6F91;
    return result == expected;
}

int TEST(crc16_modbus)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_modbus);
    u32_t expected = 0x4B37;
    return result == expected;
}

int TEST(crc16_nrsc_5)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_nrsc_5);
    u32_t expected = 0xA066;
    return result == expected;
}

int TEST(crc16_opensafety_a)(void)
{
    u32_t result =
        calculate_crc(test_data, test_data_size, &crc16_opensafety_a);
    u32_t expected = 0x5D38;
    return result == expected;
}

int TEST(crc16_opensafety_b)(void)
{
    u32_t result =
        calculate_crc(test_data, test_data_size, &crc16_opensafety_b);
    u32_t expected = 0x20FE;
    return result == expected;
}

int TEST(crc16_profibus)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_profibus);
    u32_t expected = 0xA819;
    return result == expected;
}

int TEST(crc16_riello)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_riello);
    u32_t expected = 0x63D0;
    return result == expected;
}

int TEST(crc16_spi_fujitsu)(void)
{
    u32_t result = calculate_crc(test_data, test_data_size, &crc16_spi_fujitsu);
    u32_t expected = 0xE5CC;
    return result == expected;
}

int TEST(crc16_t10_dif)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_t10_dif);
    u32_t expected = 0xD0DB;
    return result == expected;
}

int TEST(crc16_teledisk)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_teledisk);
    u32_t expected = 0x0FB3;
    return result == expected;
}

int TEST(crc16_tms37157)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_tms37157);
    u32_t expected = 0x26B1;
    return result == expected;
}

int TEST(crc16_umts)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_umts);
    u32_t expected = 0xFEE8;
    return result == expected;
}

int TEST(crc16_usb)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_usb);
    u32_t expected = 0xB4C8;
    return result == expected;
}

int TEST(crc16_xmodem)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc16_xmodem);
    u32_t expected = 0x31C3;
    return result == expected;
}

int TEST(crc32_aixm)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc32_aixm);
    u32_t expected = 0x3010BF7F;
    return result == expected;
}

int TEST(crc32_autosar)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc32_autosar);
    u32_t expected = 0x1697D06A;
    return result == expected;
}

int TEST(crc32_base91_d)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc32_base91_d);
    u32_t expected = 0x87315576;
    return result == expected;
}

int TEST(crc32_bzip2)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc32_bzip2);
    u32_t expected = 0xFC891918;
    return result == expected;
}

int TEST(crc32_cd_rom_edc)(void)
{
    u32_t result = calculate_crc(test_data, test_data_size, &crc32_cd_rom_edc);
    u32_t expected = 0x6EC2EDC4;
    return result == expected;
}

int TEST(crc32_cksum)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc32_cksum);
    u32_t expected = 0x765E7680;
    return result == expected;
}

int TEST(crc32_iscsi)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc32_iscsi);
    u32_t expected = 0xE3069283;
    return result == expected;
}

int TEST(crc32_iso_hdlc)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc32_iso_hdlc);
    u32_t expected = 0xCBF43926;
    return result == expected;
}

int TEST(crc32_jamcrc)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc32_jamcrc);
    u32_t expected = 0x340BC6D9;
    return result == expected;
}

int TEST(crc32_mef)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc32_mef);
    u32_t expected = 0xD2C22F51;
    return result == expected;
}

int TEST(crc32_mpeg_2)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc32_mpeg_2);
    u32_t expected = 0x0376E6E7;
    return result == expected;
}

int TEST(crc32_xfer)(void)
{
    u32_t result   = calculate_crc(test_data, test_data_size, &crc32_xfer);
    u32_t expected = 0xBD0BE338;
    return result == expected;
}

int TEST(crc32_iso_hdlc_string)(void)
{
    const crc_params_t* params = get_crc_by_name("CRC-32/ISO-HDLC");
    if (params == NULL)
        return 0;

    u32_t result   = calculate_crc(test_data, test_data_size, params);
    u32_t expected = 0xCBF43926;
    return result == expected;
}
