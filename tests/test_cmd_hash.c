#include "t_cmd_common.h"
#include "t.h"
#include "data/big_buffers.h"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(notkitty_all_hashes)(void)
{
    // clang-format off
    const char* expected =
    "       md2 : 39a678d255754109e1be9259b980115f\n"
    "       md4 : b2cdd438a0405b70b2ada17b21316675\n"
    "       md5 : 29aedda82de8f860e085d0a3fa7b8b7b\n"
    "   md6-128 : 715057975c14fdaa5b33df5a44716e14\n"
    "   md6-256 : 6735fc6b1103c7b372b79c581fb6b850b35eb57a122ba00e6c4bb2e42bc460a6\n"
    "   md6-384 : 2cd82629bdd6c6bf25870b9ecdb618aae0ed632ef812b4438b4f1781d3bed526233e1cc22b265b6e521522353fe328ae\n"
    "   md6-512 : a1a37d450f1502966bd921b407a074edebfc5f878f27b343d89ef4a328db6da1a6f126ccce0165e9b01309efa91a23e05b0881954db0da3f848326811b6cd042\n"
    "      sha1 : c4046bf205e3effade0a4d3df02ffef614d6b917\n"
    "    sha224 : 2110a12f02fa6d3a34035ca0135bfbbf5e303835bb7418e6570e98d7\n"
    "    sha256 : 9557f79685f4a6c3525cbb641834e787fe98bff62f9b822c13eb6ece23233484\n"
    "    sha384 : e2e4e08c8d5434dccbdd6f5013094ea5457b9df4e3df19e86f40e948a532815647411d67a975c9abe65962f72fd974ad\n"
    "    sha512 : f75d42af5af0bf02e994969c1e9945bbbaafaf52c37cc35f37197b736a6266627759ae4b4e13a47e149e59eb54c09bad8e6d4a131cc5081c0b4a2cfb7c1d0276\n"
    "  sha3-128 : 53a2a118670fc36bcfd10e9e6853d4ef\n"
    "  sha3-224 : d1fa66f17e2d8b2d21172d8074589f55e210e49e2f315c931d9f88c8\n"
    "  sha3-256 : 59c6585e35ad306120654f0a8a71bd2e780d16eaa73b46668bbe2856ce42549f\n"
    "  sha3-384 : a221c2f8bbf2bd757ef27b23e1137cf7c640dc813bc72edfc736d0a7968e945365167e7cf61afe2911ef2d40367794f4\n"
    "  sha3-512 : 5cc86b7c3bbc77c730dfe8da1e998e94b088011770105e0f5d626610bb4bb7b6920e85472ed58111f303c419b1b9492afb7ea96f8997b2a29ed4f4a99c108dc3\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("hh *") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(answer_to_universe_all_hashes)(void)
{
    // clang-format off
    const char* expected =
    "       md2 : 66d95a4b053cd6fc116f6a6fb343bf8f\n"
    "       md4 : 7639e556f646d117b2a9099600185bdc\n"
    "       md5 : 471972b39f15792c973bc23952feb72c\n"
    "   md6-128 : 99d56c61792fb2122b8d9e1fa7b23d97\n"
    "   md6-256 : b7c80f5c6e8d793bc76d99342310e239947cf0cfed1568974894494ef38bcf5d\n"
    "   md6-384 : 5a66d18a53947ac663eb1974c647ca96ec22ffad466644df9aea58b162d90dab0b54434b2faeb35b60c9378df1811f20\n"
    "   md6-512 : 93e3e24b3969133d553a3e95be9e0723ecd83ea15b526d80cd23d2f7f56c7eac3fb4391dea8a81c21b0cbd3405f5f6ce80c84e6e1e54a545860d4a2cb5cd9168\n"
    "      sha1 : 22a34b0b4dae9bd90d573045fcef86877980de10\n"
    "    sha224 : f1b9ab1cb2c22a331a9a7636e251428658637c98de8a47401dd0243f\n"
    "    sha256 : 52cfd0f284a6f745ffc05576fd2179e6d91db19d58f91729d737e43ae547dba0\n"
    "    sha384 : 7ac112d2c47eabe1365f6967c01a1320b19341e4e21754d5da9911a2475feb80e4633fb859e8adac8198c1d98a81d904\n"
    "    sha512 : fb30acf22eb1be144c6469c760c087ad5fd10e7b90780454300a3532d1bb5ace44093e8b8345370e1dad7d7dfa8d61d776d3c4baf8613308b509f9ecf0c3df7c\n"
    "  sha3-128 : 6b512351dcadef16dbfed499c47aebc7\n"
    "  sha3-224 : 64c2ad47bb7cc8d30c3117feb3c8472b834a85112ed71be36371d3c7\n"
    "  sha3-256 : 52c9b875be992743eb681976527c83ac3ccfec94aeff1a1526c90a71f6666940\n"
    "  sha3-384 : a3e1c59b4001aed941632ae35e4c5b22e2d1ef2ebeb2059d41858c1ec8af43fa2551a0b79d26519e4e8164dc0bc8416f\n"
    "  sha3-512 : ed7a2325f0e562eb9e7074d31a4dba3a98b04312573589901fa0096d36f14346134d9c9545882e43b9f95a2eed23f730510c6d09087b015ea159426f8725687e\n";
    // clang-format on

    DummyFilebuffer* tfb =
        dummyfilebuffer_create(answer_to_universe, sizeof(answer_to_universe));

    int r = TEST_FAILED;
    if (exec_commands_on("hh *", tfb) != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    dummyfilebuffer_destroy(tfb);
    return r;
}

int TEST(empty)(void)
{
    // clang-format off
    const char* expected =
    "       md2 : 8350e5a3e24c153df2275c9f80692773\n"
    "       md4 : 31d6cfe0d16ae931b73c59d7e0c089c0\n"
    "       md5 : d41d8cd98f00b204e9800998ecf8427e\n"
    "   md6-128 : 032f75b3ca02a393196a818328bd32e8\n"
    "   md6-256 : bca38b24a804aa37d821d31af00f5598230122c5bbfc4c4ad5ed40e4258f04ca\n"
    "   md6-384 : b0bafffceebe856c1eff7e1ba2f539693f828b532ebf60ae9c16cbc3499020401b942ac25b310b2227b2954ccacc2f1f\n"
    "   md6-512 : 6b7f33821a2c060ecdd81aefddea2fd3c4720270e18654f4cb08ece49ccb469f8beeee7c831206bd577f9f2630d9177979203a9489e47e04df4e6deaa0f8e0c0\n"
    "      sha1 : da39a3ee5e6b4b0d3255bfef95601890afd80709\n"
    "    sha224 : d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f\n"
    "    sha256 : e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
    "    sha384 : 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b\n"
    "    sha512 : cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e\n"
    "  sha3-128 : b38fcdb382ebdd1d57afaf02bcc9fb19\n"
    "  sha3-224 : 6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7\n"
    "  sha3-256 : a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a\n"
    "  sha3-384 : 0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004\n"
    "  sha3-512 : a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("s 0; d 324 ; hh *; u") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(notkitty_only_md_family)(void)
{
    // clang-format off
    const char* expected =
    "       md2 : 39a678d255754109e1be9259b980115f\n"
    "       md4 : b2cdd438a0405b70b2ada17b21316675\n"
    "       md5 : 29aedda82de8f860e085d0a3fa7b8b7b\n"
    "   md6-128 : 715057975c14fdaa5b33df5a44716e14\n"
    "   md6-256 : 6735fc6b1103c7b372b79c581fb6b850b35eb57a122ba00e6c4bb2e42bc460a6\n"
    "   md6-384 : 2cd82629bdd6c6bf25870b9ecdb618aae0ed632ef812b4438b4f1781d3bed526233e1cc22b265b6e521522353fe328ae\n"
    "   md6-512 : a1a37d450f1502966bd921b407a074edebfc5f878f27b343d89ef4a328db6da1a6f126ccce0165e9b01309efa91a23e05b0881954db0da3f848326811b6cd042\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("hh md") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(notkitty_size_too_big)(void)
{
    // clang-format off
    const char* expected =
    "[  ERROR  ] invalid size, exceeding file size\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("hh * 9999999") == 0)
        goto end;

    char* out = strbuilder_reset(err_sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(notkitty_offset_too_big)(void)
{
    // clang-format off
    const char* expected =
    "[  ERROR  ] invalid offset, exceeding file size\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("hh * 0 99999999") == 0)
        goto end;

    char* out = strbuilder_reset(err_sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(notkitty_size_plus_offset_too_big)(void)
{
    // clang-format off
    const char* expected =
    "[  ERROR  ] calculated offset exceeds file size\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("hh * 100 250") == 0)
        goto end;

    char* out = strbuilder_reset(err_sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(notkitty_with_size_1)(void)
{
    // clang-format off
    const char* expected =
    "       md2 : a90201383bcc37675c363e2a6549d0b6\n"
    "       md4 : 6a0e86dd59f27acf0dbaf3c2942d5783\n"
    "       md5 : 83acb6e67e50e31db6ed341dd2de1595\n"
    "   md6-128 : f380e3356f690c536e3d81d8b080a16c\n"
    "   md6-256 : 5e3a11d8d5d3540278d57aa4a366e28d1310f3740d419f01572c302a613d738c\n"
    "   md6-384 : 6f83e9846f5b6424aef4b9837601c691990ac0dbbcc33ed01c9db2bb3369835420db2278b24b5130f86e952b71483c9d\n"
    "   md6-512 : 8fe808ac8cb830f655296f0a9788832606f9e43e0226492bbf100963bdcef1ffca820c1183775fadc3645a772108322bda0c030a6a6ca84cafda5604037fab59\n"
    "      sha1 : 23833462f55515a900e016db2eb943fb474c19f6\n"
    "    sha224 : a9ab1c5b26ddfea1cf0cc71c44363662af955b7bbf076d70af3ff9c2\n"
    "    sha256 : 620bfdaa346b088fb49998d92f19a7eaf6bfc2fb0aee015753966da1028cb731\n"
    "    sha384 : 23a8a9d42d150a471e8502ee2f4e822cb955e798882d698c5bd5aa01e43137cb566fefb1b06dced14b43c2e49758569d\n"
    "    sha512 : 75eb69a43e3bbcff322ec624ae7511cf3ad99df84b90d48b2665c70dff548c4857d4446c1eb04535bf54daa96e2cf5c3d5203d1fb43bbf4d40301bab95ac7772\n"
    "  sha3-128 : f2f1a7e794999f0d447a96ca5c351e6f\n"
    "  sha3-224 : 6f733daaa9696d60dd5c543b365a9ce953ea3ae5ef71a9c6040eca63\n"
    "  sha3-256 : aac68691d102829ac973f5b44c26165aa4e29cd498aff642a08944645d6ca5bd\n"
    "  sha3-384 : c6d45f444a995d9aee6f989b3cce12f3a94fa58c4a49218ad3f0405f9be1df2a848c008684b9d9e5f342d27978624846\n"
    "  sha3-512 : 5d6289e2eb89d4099552ad261115d31e1cfddf67f4997f19bd95d2436427deba817b9d4d3d107656283c602c19fa77f8c985b2a5e33d61cd0d56f3c1d61e93ea\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("hh * 1") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(notkitty_sha1_with_size)(void)
{
    // clang-format off
    const char* expected =
    "      sha1 : afcb97e87528305aa7bb20c6969d073175d3aecb\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("hh sha1 8") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(notkitty_sha1_with_size_and_off)(void)
{
    // clang-format off
    const char* expected =
    "      sha1 : 05fe405753166f125559e7c9ac558654f107c7e9\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("hh sha1 8 8") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}

int TEST(notkitty_sha1_with_off)(void)
{
    // clang-format off
    const char* expected =
    "      sha1 : da39a3ee5e6b4b0d3255bfef95601890afd80709\n";
    // clang-format on

    int r = TEST_FAILED;
    if (exec_commands("hh sha1 0 8") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = compare_strings_ignoring_X(expected, out);
    bhex_free(out);

end:
    return r;
}
