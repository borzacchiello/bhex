// Copyright (c) 2022-2026, bageyelet

#include <stdlib.h>
#include <string.h>
#include <checksums.h>

#ifndef TEST
#define TEST(name) test_##name
#endif

static const u8_t  cs_test_data[]    = "123456789";
static const u32_t cs_test_data_size = 9;

int TEST(checksum_bsd)(void)
{
    const checksum_algo_t* algo = get_checksum_by_name("BSD");
    return algo &&
           calculate_checksum(cs_test_data, cs_test_data_size, algo) == 0xD16F;
}

int TEST(checksum_sysv)(void)
{
    const checksum_algo_t* algo = get_checksum_by_name("SYSV");
    return algo &&
           calculate_checksum(cs_test_data, cs_test_data_size, algo) == 0x1DD;
}

int TEST(checksum_sum8)(void)
{
    const checksum_algo_t* algo = get_checksum_by_name("SUM-8");
    return algo &&
           calculate_checksum(cs_test_data, cs_test_data_size, algo) == 0xDD;
}

int TEST(checksum_internet)(void)
{
    const checksum_algo_t* algo = get_checksum_by_name("INTERNET");
    return algo &&
           calculate_checksum(cs_test_data, cs_test_data_size, algo) == 0xF62A;
}

int TEST(checksum_sum24)(void)
{
    const checksum_algo_t* algo = get_checksum_by_name("SUM-24");
    return algo &&
           calculate_checksum(cs_test_data, cs_test_data_size, algo) == 0x1DD;
}

int TEST(checksum_sum32)(void)
{
    const checksum_algo_t* algo = get_checksum_by_name("SUM-32");
    return algo &&
           calculate_checksum(cs_test_data, cs_test_data_size, algo) == 0x1DD;
}

int TEST(checksum_fletcher4)(void)
{
    const checksum_algo_t* algo = get_checksum_by_name("FLETCHER-4");
    return algo &&
           calculate_checksum(cs_test_data, cs_test_data_size, algo) == 0x8;
}

int TEST(checksum_fletcher8)(void)
{
    const checksum_algo_t* algo = get_checksum_by_name("FLETCHER-8");
    return algo &&
           calculate_checksum(cs_test_data, cs_test_data_size, algo) == 0xC;
}

int TEST(checksum_fletcher16)(void)
{
    const checksum_algo_t* algo = get_checksum_by_name("FLETCHER-16");
    return algo &&
           calculate_checksum(cs_test_data, cs_test_data_size, algo) == 0x1EDE;
}

int TEST(checksum_fletcher32)(void)
{
    const checksum_algo_t* algo = get_checksum_by_name("FLETCHER-32");
    return algo && calculate_checksum(cs_test_data, cs_test_data_size, algo) ==
                       0x9DF09D5;
}

int TEST(checksum_adler32)(void)
{
    const checksum_algo_t* algo = get_checksum_by_name("ADLER-32");
    return algo && calculate_checksum(cs_test_data, cs_test_data_size, algo) ==
                       0x91E01DE;
}

int TEST(checksum_xor8)(void)
{
    const checksum_algo_t* algo = get_checksum_by_name("XOR-8");
    return algo &&
           calculate_checksum(cs_test_data, cs_test_data_size, algo) == 0x31;
}

int TEST(checksum_luhn)(void)
{
    const checksum_algo_t* algo = get_checksum_by_name("LUHN");
    return algo &&
           calculate_checksum(cs_test_data, cs_test_data_size, algo) == 0;
}

int TEST(checksum_verhoeff)(void)
{
    const checksum_algo_t* algo = get_checksum_by_name("VERHOEFF");
    return algo &&
           calculate_checksum(cs_test_data, cs_test_data_size, algo) == 8;
}

int TEST(checksum_damm)(void)
{
    const checksum_algo_t* algo = get_checksum_by_name("DAMM");
    return algo &&
           calculate_checksum(cs_test_data, cs_test_data_size, algo) == 7;
}

int TEST(checksum_streaming)(void)
{
    const checksum_algo_t* algo = get_checksum_by_name("ADLER-32");
    if (!algo)
        return 0;

    u32_t expected = calculate_checksum(cs_test_data, cs_test_data_size, algo);

    checksum_state_t s = algo->init();
    s                  = algo->step(s, cs_test_data, 4);
    s                  = algo->step(s, cs_test_data + 4, 5);
    u32_t result       = algo->finalize(s);

    return result == expected;
}

int TEST(checksum_get_by_name_null)(void)
{
    return get_checksum_by_name(NULL) == NULL;
}

int TEST(checksum_get_by_name_invalid)(void)
{
    return get_checksum_by_name("NONEXISTENT") == NULL;
}

int TEST(checksum_get_all_names)(void)
{
    const char* const* names = get_all_checksum_names();
    int                count = 0;
    while (names[count])
        count++;
    return count == 15;
}
