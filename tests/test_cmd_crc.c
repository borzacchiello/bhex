#include "t_cmd_common.h"
#include "t.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(whole_file_all_crcs)(void)
{
    // clang-format off
    const char* expected =
    "             CRC-8/AUTOSAR : 0xe3\n"
    "           CRC-8/BLUETOOTH : 0x4f\n"
    "            CRC-8/CDMA2000 : 0x6e\n"
    "                CRC-8/DARC : 0x7e\n"
    "              CRC-8/DVB-S2 : 0x91\n"
    "               CRC-8/GSM-A : 0x6\n"
    "               CRC-8/GSM-B : 0x80\n"
    "               CRC-8/HITAG : 0x9d\n"
    "             CRC-8/I-432-1 : 0xbf\n"
    "              CRC-8/I-CODE : 0xea\n"
    "                 CRC-8/LTE : 0xec\n"
    "           CRC-8/MAXIM-DOW : 0xe9\n"
    "          CRC-8/MIFARE-MAD : 0xe0\n"
    "              CRC-8/NRSC-5 : 0xf4\n"
    "          CRC-8/OPENSAFETY : 0xfe\n"
    "                CRC-8/ROHC : 0x3b\n"
    "           CRC-8/SAE-J1850 : 0x62\n"
    "               CRC-8/SMBUS : 0xea\n"
    "           CRC-8/TECH-3250 : 0x16\n"
    "               CRC-8/WCDMA : 0xcb\n"
    "                CRC-16/ARC : 0x392\n"
    "           CRC-16/CDMA2000 : 0xf03a\n"
    "                CRC-16/CMS : 0xd810\n"
    "            CRC-16/DDS-110 : 0x2afa\n"
    "             CRC-16/DECT-R : 0x9c8d\n"
    "             CRC-16/DECT-X : 0x9c8c\n"
    "                CRC-16/DNP : 0x2720\n"
    "           CRC-16/EN-13757 : 0xb498\n"
    "            CRC-16/GENIBUS : 0x1905\n"
    "                CRC-16/GSM : 0x7330\n"
    "           CRC-16/IBM-3740 : 0xe6fa\n"
    "           CRC-16/IBM-SDLC : 0x2fc5\n"
    "  CRC-16/ISO-IEC-14443-3-A : 0xe6af\n"
    "             CRC-16/KERMIT : 0x7c6c\n"
    "             CRC-16/LJ1200 : 0x2d48\n"
    "                CRC-16/M17 : 0x6208\n"
    "          CRC-16/MAXIM-DOW : 0xfc6d\n"
    "            CRC-16/MCRF4XX : 0xd03a\n"
    "             CRC-16/MODBUS : 0xea41\n"
    "             CRC-16/NRSC-5 : 0x4464\n"
    "       CRC-16/OPENSAFETY-A : 0x6c7b\n"
    "       CRC-16/OPENSAFETY-B : 0xc1ae\n"
    "           CRC-16/PROFIBUS : 0xa139\n"
    "             CRC-16/RIELLO : 0x163f\n"
    "        CRC-16/SPI-FUJITSU : 0xed8\n"
    "            CRC-16/T10-DIF : 0xa62e\n"
    "           CRC-16/TELEDISK : 0x6ede\n"
    "           CRC-16/TMS37157 : 0xd5d8\n"
    "               CRC-16/UMTS : 0x1387\n"
    "                CRC-16/USB : 0x15be\n"
    "             CRC-16/XMODEM : 0x8ccf\n"
    "               CRC-32/AIXM : 0x4758370b\n"
    "            CRC-32/AUTOSAR : 0x3a69037c\n"
    "           CRC-32/BASE91-D : 0x8e4eb8c1\n"
    "              CRC-32/BZIP2 : 0x2e7f16d8\n"
    "         CRC-32/CD-ROM-EDC : 0xb31db842\n"
    "              CRC-32/CKSUM : 0x791f4197\n"
    "              CRC-32/ISCSI : 0x7f6b009d\n"
    "           CRC-32/ISO-HDLC : 0xf251bea0\n"
    "             CRC-32/JAMCRC : 0xdae415f\n"
    "                CRC-32/MEF : 0x99bd579f\n"
    "             CRC-32/MPEG-2 : 0xd180e927\n"
    "               CRC-32/XFER : 0x8e478947\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("crc CRC-") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    bhex_free(strbuilder_reset(sb));
    return r;
}

int TEST(whole_file_all_crc32)(void)
{
    // clang-format off
    const char* expected =
    "               CRC-32/AIXM : 0x4758370b\n"
    "            CRC-32/AUTOSAR : 0x3a69037c\n"
    "           CRC-32/BASE91-D : 0x8e4eb8c1\n"
    "              CRC-32/BZIP2 : 0x2e7f16d8\n"
    "         CRC-32/CD-ROM-EDC : 0xb31db842\n"
    "              CRC-32/CKSUM : 0x791f4197\n"
    "              CRC-32/ISCSI : 0x7f6b009d\n"
    "           CRC-32/ISO-HDLC : 0xf251bea0\n"
    "             CRC-32/JAMCRC : 0xdae415f\n"
    "                CRC-32/MEF : 0x99bd579f\n"
    "             CRC-32/MPEG-2 : 0xd180e927\n"
    "               CRC-32/XFER : 0x8e478947\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("crc CRC-32") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    bhex_free(strbuilder_reset(sb));
    return r;
}

int TEST(whole_file_one_crc)(void)
{
    // clang-format off
    const char* expected =
    "           CRC-8/BLUETOOTH : 0x4f\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("crc CRC-8/BLUETOOTH") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    bhex_free(strbuilder_reset(sb));
    return r;
}

int TEST(one_byte_one_crc)(void)
{
    // clang-format off
    const char* expected =
    "           CRC-8/BLUETOOTH : 0x7a\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("crc CRC-8/BLUETOOTH 1") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    bhex_free(strbuilder_reset(sb));
    return r;
}

int TEST(one_byte_off_one_one_crc)(void)
{
    // clang-format off
    const char* expected =
    "           CRC-8/BLUETOOTH : 0x9b\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("crc CRC-8/BLUETOOTH 1 1") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    bhex_free(strbuilder_reset(sb));
    return r;
}

int TEST(invalid_offset)(void)
{
    int r = TEST_SUCCEEDED;
    if (exec_commands("crc CRC-8/BLUETOOTH 1 99999999") == 0)
        r = TEST_FAILED;
    bhex_free(strbuilder_reset(sb));
    return r;
}

int TEST(size_too_big)(void)
{
    // clang-format off
    const char* expected =
    "           CRC-8/BLUETOOTH : 0xde\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("crc CRC-8/BLUETOOTH 99999 1") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    bhex_free(strbuilder_reset(sb));
    return r;
}
