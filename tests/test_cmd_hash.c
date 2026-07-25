// Copyright (c) 2022-2026, bageyelet

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
    "           md2 : 39a678d255754109e1be9259b980115f\n"
    "           md4 : b2cdd438a0405b70b2ada17b21316675\n"
    "           md5 : 29aedda82de8f860e085d0a3fa7b8b7b\n"
    "       md6-128 : 715057975c14fdaa5b33df5a44716e14\n"
    "       md6-256 : 6735fc6b1103c7b372b79c581fb6b850b35eb57a122ba00e6c4bb2e42bc460a6\n"
    "       md6-384 : 2cd82629bdd6c6bf25870b9ecdb618aae0ed632ef812b4438b4f1781d3bed526233e1cc22b265b6e521522353fe328ae\n"
    "       md6-512 : a1a37d450f1502966bd921b407a074edebfc5f878f27b343d89ef4a328db6da1a6f126ccce0165e9b01309efa91a23e05b0881954db0da3f848326811b6cd042\n"
    "           sm3 : 0a642763c258bdeb9eb8c33367b12a258dfabed33f80bb59b821f57165ab9d25\n"
    "          sha1 : c4046bf205e3effade0a4d3df02ffef614d6b917\n"
    "        sha224 : 2110a12f02fa6d3a34035ca0135bfbbf5e303835bb7418e6570e98d7\n"
    "        sha256 : 9557f79685f4a6c3525cbb641834e787fe98bff62f9b822c13eb6ece23233484\n"
    "        sha384 : e2e4e08c8d5434dccbdd6f5013094ea5457b9df4e3df19e86f40e948a532815647411d67a975c9abe65962f72fd974ad\n"
    "        sha512 : f75d42af5af0bf02e994969c1e9945bbbaafaf52c37cc35f37197b736a6266627759ae4b4e13a47e149e59eb54c09bad8e6d4a131cc5081c0b4a2cfb7c1d0276\n"
    "      sha3-128 : 53a2a118670fc36bcfd10e9e6853d4ef\n"
    "      sha3-224 : d1fa66f17e2d8b2d21172d8074589f55e210e49e2f315c931d9f88c8\n"
    "      sha3-256 : 59c6585e35ad306120654f0a8a71bd2e780d16eaa73b46668bbe2856ce42549f\n"
    "      sha3-384 : a221c2f8bbf2bd757ef27b23e1137cf7c640dc813bc72edfc736d0a7968e945365167e7cf61afe2911ef2d40367794f4\n"
    "      sha3-512 : 5cc86b7c3bbc77c730dfe8da1e998e94b088011770105e0f5d626610bb4bb7b6920e85472ed58111f303c419b1b9492afb7ea96f8997b2a29ed4f4a99c108dc3\n"
    "    RipeMD-128 : b4563447abf7cc5d80e258002e470ec4\n"
    "    RipeMD-160 : b657ee770eb25c720381d8b64cf487a03e37e220\n"
    "    RipeMD-256 : 8814cc34336ccad19000c18d17aa98abb9c999566abed2e925f0e30205a816e2\n"
    "    RipeMD-320 : d655786d8d1ffe7fd2695a481f20b0ba8e1cfd2f256ec315aefa2c2a640502b0c70abd87100611ce\n"
    "       blake2s : 67f7c9bed696f1ce6704e5ea4d2ab7e2ee8314f6f9041db48740798ffa75f06f\n"
    "       blake2b : 5786ddb5ec49b658047191511dd05c047d2e5ab33051ef9e3a1ab4598a43be5ecc9ce58ce2e7b56e397c52723c2a59f5eea6364122ab08c480362576d013c6ec\n"
    "        blake3 : 4a6856e40fde37e44a4899b201d9544b637ecccef216b695b50f3deda350ead2\n"
    "          gost : 42b7c31dea43e2fa79e154105d449335fea473d6a6fcbd53edf275d5d57b3ab9\n"
    "   groestl-224 : ca1e68b3d7fc038e37708f54aca69e2d247be08e64c5ff66a903f78b\n"
    "   groestl-256 : 584b3849a43147709d5db32ce5375d019b62020189c599f07dea46dfa1ab9a0a\n"
    "   groestl-384 : 789f0ff3c619c38e98d74d486e387276bfd57a37ed725332879de6c1b2b72aa50daa23ab807261e5c8db0d5886bd1470\n"
    "   groestl-512 : 09e00c49a7e13592c068b9a60b6d8967c85cec65972c91c33c954c3fa9bb8596740e295f7d4ed6b954575c2a331e1eff1a42b3388ae657ff18b4e87fbd7d41cc\n"
    "        jh-224 : 3a86fb6a5a09b09e098e350cff1d051593d58d9e74dfc75502817055\n"
    "        jh-256 : 03faf82ef077b4a0e2c1749b991de64667f2bb0ca0d4f2f6f519aa3921067e81\n"
    "        jh-384 : 7d9205be062c93dcd1ac69305fe3db8060a61726d5d2288ce79980f740f3bb3f187e59c96eecd054d9c1405c8cdc7477\n"
    "        jh-512 : 449c1e378357fd3e9b81409cfa09a257acfc10aed3c1daf134cc27227b84a65823d75da4dfb9e6200c911a2c9a0ad5d514b16cfcfd835ba00b97f0b3e9d44724\n"
    "    snefru-128 : 73a1f2c464a449f06e0fce691d6ef2f4\n"
    "    snefru-256 : dd083bd7cf0a464f42f6bdc3890758216ef4d883ac354259a561411cb78326fd\n"
    "  spectral-256 : f5d93f497472d8b3c7087a8e069b155927500a8bf17316f96973b1cd3aa42604\n"
    "  spectral-512 : c7394bab4293f6a46eace4f316ac054babe1bfe1517d8b83e3c2cbe4af42bbba9da2adf59006aa443ed25c5114f7dcaab279f1f88fbd2f3e746973e8a98614d4\n"
    "   haval-128-3 : d693ec0defd29aad37bd5d914bb5200a\n"
    "   haval-128-4 : 7c87d57d64426e90b357df6af0ea6619\n"
    "   haval-128-5 : 3f93f058bd947a1b246ee143fb165336\n"
    "   haval-160-3 : 95bb3d499a2cad8fa80024caa7b72fbdb0d3b861\n"
    "   haval-160-4 : d68a953e84620c10d2a4ce3d09e68b6199f39f3d\n"
    "   haval-160-5 : bbb96f4db9e8ac01baecf0b82824e3eea515dea8\n"
    "   haval-192-3 : 8b75a23e60ea541b284dbbc25183d179054ee2058b4e2129\n"
    "   haval-192-4 : 547c4e9c13d955b78046e19146e4e67350532d6cac7d1090\n"
    "   haval-192-5 : 688b2e6b6282da51b2e6130fb01eeac07357278d9f85cea7\n"
    "   haval-224-3 : dbdc08bc4c67ccec28904374e35089598733c0f1d9663312e6c7652c\n"
    "   haval-224-4 : a361ac7122af72eaec62786f9a5b5fe70da5501b0b68fa0d51e0981b\n"
    "   haval-224-5 : 70b036df41310b36c41c4eb1804e8e178ab39123242919a5f1c6c067\n"
    "   haval-256-3 : 8276dae33378cf79e22309c993d9f0c5e88dc508422a0c3e14dd7df5d155b169\n"
    "   haval-256-4 : da53b3a5f8c9a120e61a9983471b348aaab390803afa22faaf31be901f41860f\n"
    "   haval-256-5 : ea0006d570f7abf643224d21d0d20fe8f9a67fe0f5876f44ece4fa9b19dc7166\n"
    "         tiger : 2548abf82405228ef4124ea25697930ff0d411c3600f4930\n"
    "        tiger2 : 83a9dbaa6f616eeba92960ecc0f1fe5bd0e206410b659d27\n"
    "     whirlpool : 8ff340018588ebb0603e53b187e42ff4d5e516bc45c0d7e12f84259fa4ce58be28119286fa189e1219d231eff0c638c0c5f3b8508a9885e92bcacb4d2cfec472\n";
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
    "           md2 : 66d95a4b053cd6fc116f6a6fb343bf8f\n"
    "           md4 : 7639e556f646d117b2a9099600185bdc\n"
    "           md5 : 471972b39f15792c973bc23952feb72c\n"
    "       md6-128 : 99d56c61792fb2122b8d9e1fa7b23d97\n"
    "       md6-256 : b7c80f5c6e8d793bc76d99342310e239947cf0cfed1568974894494ef38bcf5d\n"
    "       md6-384 : 5a66d18a53947ac663eb1974c647ca96ec22ffad466644df9aea58b162d90dab0b54434b2faeb35b60c9378df1811f20\n"
    "       md6-512 : 93e3e24b3969133d553a3e95be9e0723ecd83ea15b526d80cd23d2f7f56c7eac3fb4391dea8a81c21b0cbd3405f5f6ce80c84e6e1e54a545860d4a2cb5cd9168\n"
    "           sm3 : 1d9ca3cf9b7b701765e28e11afa493e24192479b7f27b40d2c10db18d483480e\n"
    "          sha1 : 22a34b0b4dae9bd90d573045fcef86877980de10\n"
    "        sha224 : f1b9ab1cb2c22a331a9a7636e251428658637c98de8a47401dd0243f\n"
    "        sha256 : 52cfd0f284a6f745ffc05576fd2179e6d91db19d58f91729d737e43ae547dba0\n"
    "        sha384 : 7ac112d2c47eabe1365f6967c01a1320b19341e4e21754d5da9911a2475feb80e4633fb859e8adac8198c1d98a81d904\n"
    "        sha512 : fb30acf22eb1be144c6469c760c087ad5fd10e7b90780454300a3532d1bb5ace44093e8b8345370e1dad7d7dfa8d61d776d3c4baf8613308b509f9ecf0c3df7c\n"
    "      sha3-128 : 6b512351dcadef16dbfed499c47aebc7\n"
    "      sha3-224 : 64c2ad47bb7cc8d30c3117feb3c8472b834a85112ed71be36371d3c7\n"
    "      sha3-256 : 52c9b875be992743eb681976527c83ac3ccfec94aeff1a1526c90a71f6666940\n"
    "      sha3-384 : a3e1c59b4001aed941632ae35e4c5b22e2d1ef2ebeb2059d41858c1ec8af43fa2551a0b79d26519e4e8164dc0bc8416f\n"
    "      sha3-512 : ed7a2325f0e562eb9e7074d31a4dba3a98b04312573589901fa0096d36f14346134d9c9545882e43b9f95a2eed23f730510c6d09087b015ea159426f8725687e\n"
    "    RipeMD-128 : 4328ca16e9bfcb0302e30ba841524793\n"
    "    RipeMD-160 : ff500b620c1d880928f74fd2e0bdfc1dd0aa7d7e\n"
    "    RipeMD-256 : 10edc6a6dc7bac123572f53dfbb8f359b624d83ed00f0d7733137e913ed696ed\n"
    "    RipeMD-320 : 5e81a7d551d8dd4365769817beea49b1a5db2a512aab654956406a7c5591cb9407d8e6170eb95ccb\n"
    "       blake2s : 0e1361f22dba63b71bbefc96a85a581267755cb5ecb20c40d46cb69c4989320a\n"
    "       blake2b : 4a8979ddd9e465c3634e84dce132976bd503596616974d95256be161e2a81199f6a3846fb65fa90a568caa7b801b49671d3be70b32237d8fac1d428011bc769f\n"
    "        blake3 : 8d0a62ce469f300a55d8c6bc2ab1c639b1cd8b6a2aa94fd1be56d61e779a1ebe\n"
    "          gost : 498f0bc6ef005a73776a6c2f063452121608f859d78f93ceaf704d1cc7973a77\n"
    "   groestl-224 : b3b0ee2672280bdbaf36b4cbadc5cada891c30cca846a99bab881959\n"
    "   groestl-256 : cdf5c89af0b57a1c522f28d54e9cb078f257d36a3b49bcad2129bf36859c0c29\n"
    "   groestl-384 : cfdfeafc23e4a365bdc3ad3135e5f0b6456b55fa1f54b78666251d9d9e6660a58a9feba292e49767ee4ffc046b037bad\n"
    "   groestl-512 : 9cc385b60e3deb7574a97bb309d01d0ec6b8805afc8f2ce69232b8f7d7ea01b80256cec4682aad04ff75a8bd65c0db33f139ef2cee396ff0a3139c5d22fe185f\n"
    "        jh-224 : c296c400d7f8a90c35d8cb0cc1b952733ecd7a1263b7423e7b0d8e11\n"
    "        jh-256 : 85765a09fb35ebe489e51fb501338fd64f18948a34f3cec99ba454ecf7db9962\n"
    "        jh-384 : 5ee8161db3122e9aeaa28db7daa773d2ad9f88def30f8a824191d11359904470f596a31c55c911bda6afc16cf5d127d2\n"
    "        jh-512 : f94130466fc22e6bddf2112fbe6a9aa4a34aa6d7a964942720dd7e3eadb88e0601cabc6a3d92f41ecacc83fc1743f90f8f3f76c01f2832552e5cc937cc9a0331\n"
    "    snefru-128 : f10f2db5f64a712070a93d205afe7dad\n"
    "    snefru-256 : 91eb5cbd94ed38f0f7e7e083d3e54a7c7db6627a0008ca241dfa05187c8dd7fb\n"
    "  spectral-256 : 802af7a44b4db4b55b46ae40aa4c6dbb8b373ef9e1f3ed019824e32111933c67\n"
    "  spectral-512 : ee308caae1eae4a4850a630cfcf4d0cd128dfa83a9af473145655478d56b2fc6a467099e473fd3f8bba03bb7f8e442370f9011b7ac49a0644d360f2cd199113f\n"
    "   haval-128-3 : 4b5543812fe25f6a66fdcba7298effc4\n"
    "   haval-128-4 : 73c617874367c18a8558938a95b1c122\n"
    "   haval-128-5 : 3370d314b69ce1f655b1d47817192c24\n"
    "   haval-160-3 : db90dbdb9170827ffad2a6f52a56ec465c7eedde\n"
    "   haval-160-4 : 9643be3fb5a7b2588fbf2fff58748c3b4c2798fd\n"
    "   haval-160-5 : dc90db1672d6bd5b324b8827e3594c44862a9246\n"
    "   haval-192-3 : cb32ca5db92be492c7fb64cd3753c6de2c086232700bb6f2\n"
    "   haval-192-4 : 6f13962178f7f0586f7567cd53ef5e9091f52c5147b8f874\n"
    "   haval-192-5 : 5a161efaefe3dfc63b136bedb32e335e32317e8d1f8f9397\n"
    "   haval-224-3 : 5eb851e96bb20d613b4604fb455bd50981cf6f2373ce86beab8d8774\n"
    "   haval-224-4 : 85c58513605ab1da0e24d8d8f244b15fed37a6696020d295b8cc1557\n"
    "   haval-224-5 : faf374aca9a752206f437541f222fb4c8b1fe52727b66d33def5af25\n"
    "   haval-256-3 : a60fcb4f1b700b573eb0fef7da149447fe0bc718573f59b3964e38bfbef9f829\n"
    "   haval-256-4 : d5f97825d89f090a0389de899b39f356637eb7d427a9025c7aeaceb518df69be\n"
    "   haval-256-5 : 875aeea0a5421e5e2a661756e242623192f6e349e4ba3a8e10aec4b0a8baf60a\n"
    "         tiger : 7371d6b382eebdb56131de1c4a0694fe8aa3dc71f948eb03\n"
    "        tiger2 : d088a34c5da520e3920f767fb892337db5f373daa951e726\n"
    "     whirlpool : 639273f566b49e8329bddb349a6218d9895be2b24e185b060dd0415a919c721636b86438495c72bd4c60659dbf4892b2b570c644beaee05df8764547cedca015\n";
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

int TEST(quick_brown_fox_all_hashes)(void)
{
    static const char fox[] = "The quick brown fox jumps over the lazy dog";

    // clang-format off
    const char* expected =
    "           md2 : 03d85a0d629d2c442e987525319fc471\n"
    "           md4 : 1bee69a46ba811185c194762abaeae90\n"
    "           md5 : 9e107d9d372bb6826bd81d3542a419d6\n"
    "       md6-128 : 7b428f5ec47e0174faf31dc7c89590c6\n"
    "       md6-256 : 977592608c45c9923340338450fdcccc21a68888e1e6350e133c5186cd9736ee\n"
    "       md6-384 : d850fdde986e16df19d65c50788afd0a8953914a4bc65831f5283c3016b79ddfa4a0bc00694e472f4a0bed7da601bb90\n"
    "       md6-512 : dcba0c6593fbd83a0f5f148588baa79530579c1f5e7f19d500fe282d137bff465106f25c9f0619b4082a730683d5f58311c0c1913068e91b0ebdf9ace3ff5b9e\n"
    "           sm3 : 5fdfe814b8573ca021983970fc79b2218c9570369b4859684e2e4c3fc76cb8ea\n"
    "          sha1 : 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12\n"
    "        sha224 : 730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525\n"
    "        sha256 : d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592\n"
    "        sha384 : ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1\n"
    "        sha512 : 07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6\n"
    "      sha3-128 : 4d7869754147b578b50c0b658399212f\n"
    "      sha3-224 : d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795\n"
    "      sha3-256 : 69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04\n"
    "      sha3-384 : 7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41\n"
    "      sha3-512 : 01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450\n"
    "    RipeMD-128 : 3fa9b57f053c053fbe2735b2380db596\n"
    "    RipeMD-160 : 37f332f68db77bd9d7edd4969571ad671cf9dd3b\n"
    "    RipeMD-256 : c3b0c2f764ac6d576a6c430fb61a6f2255b4fa833e094b1ba8c1e29b6353036f\n"
    "    RipeMD-320 : e7660e67549435c62141e51c9ab1dcc3b1ee9f65c0b3e561ae8f58c5dba3d21997781cd1cc6fbc34\n"
    "       blake2s : 606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812\n"
    "       blake2b : a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918\n"
    "        blake3 : 2f1514181aadccd913abd94cfa592701a5686ab23f8df1dff1b74710febc6d4a\n"
    "          gost : 77b7fa410c9ac58a25f49bca7d0468c9296529315eaca76bd1a10f376d1f4294\n"
    "   groestl-224 : 8ce3ce0f7092cada755be8f614fd6d5e5738ff1f6cd5dabe42404c46\n"
    "   groestl-256 : 8c7ad62eb26a21297bc39c2d7293b4bd4d3399fa8afab29e970471739e28b301\n"
    "   groestl-384 : 9330aeb62a1fc0a464dd70ac27b57075e00ae5d627f9bd6ff72952b3857aba2cfbcc4345af9a04fcc13eb346829e4088\n"
    "   groestl-512 : badc1f70ccd69e0cf3760c3f93884289da84ec13c70b3d12a53a7a8a4a513f99715d46288f55e1dbf926e6d084a0538e4eebfc91cf2b21452921ccde9131718d\n"
    "        jh-224 : bb21255e4a6bcbd3ddbf8694df2e7f41b74a69c1a7e1c2d36a3fd405\n"
    "        jh-256 : 6a049fed5fc6874acfdc4a08b568a4f8cbac27de933496f031015b38961608a0\n"
    "        jh-384 : de44fe5f835f5518c603aec9d67363466d9f3a5b54d4cfbd4083b055f95a21a2562abaa59b830b3bc4e023d0b52a1268\n"
    "        jh-512 : 043f14e7c0775e7b1ef5ad657b1e858250b21e2e61fd699783f8634cb86f3ff938451cabd0c8cdae91d4f659d3f9f6f654f1bfedca117ffba735c15fedda47a3\n"
    "    snefru-128 : 59d9539d0dd96d635b5bdbd1395bb86c\n"
    "    snefru-256 : 674caa75f9d8fd2089856b95e93a4fb42fa6c8702f8980e11d97a142d76cb358\n"
    "  spectral-256 : 201a3eb9c76eb403bad609bdc421591ad8922c9bd55d94be5719902cf8714b72\n"
    "  spectral-512 : 4822278b3bba55fa6f1f39b36eb95003b9f46745e88549fbd86160436f3f0da4c19918e86ac44f457ab4acdb0b32f3217d2c7cd06240a3251b923fa4b9276322\n"
    "   haval-128-3 : 713502673d67e5fa557629a71d331945\n"
    "   haval-128-4 : 6eece560a2e8d6b919e81fe91b0e7156\n"
    "   haval-128-5 : 696f02111f2e1da5c21d50eb782b7e8f\n"
    "   haval-160-3 : b338ac397e8bccadcccd96549cadd4882d834107\n"
    "   haval-160-4 : 6e739d01f5739ceed94da1a115b52d5951280560\n"
    "   haval-160-5 : ecce9fa8a428866304ff082af2f9062637d36b23\n"
    "   haval-192-3 : 58e6ced002e311172483d434ba738ad033e7fa950e431503\n"
    "   haval-192-4 : 228ee09bc7e36151c6f285f558e6aede66ad38c8341592b9\n"
    "   haval-192-5 : 023d045f75d4bf051fd6e50f7b7417bf9949c4b5d2b4b7ef\n"
    "   haval-224-3 : e1d5792306f56b22419662b06d1885a66dca3eba01f53274c89aeaeb\n"
    "   haval-224-4 : dddd6689885f6db4ad91e35a35e1f4498446510df798d4fd54b8654f\n"
    "   haval-224-5 : 03d953298c8e56b46385c6761cd4b2e377889a75c97eaea475421c73\n"
    "   haval-256-3 : 9446028f42b3768a41bd873ca69b0c006341d986613567f39eb61f96ca683300\n"
    "   haval-256-4 : c0d4c6ea514105fd1a9c38a238553fb7fa21d4127eb1a3035a75ce9d06a83d96\n"
    "   haval-256-5 : b89c551cdfe2e06dbd4cea2be1bc7d557416c58ebb4d07cbc94e49f710c55be4\n"
    "         tiger : 6d12a41e72e644f017b6f0e2f7b44c6285f06dd5d2c5b075\n"
    "        tiger2 : 976abff8062a2e9dcea3a1ace966ed9c19cb85558b4976d8\n"
    "     whirlpool : b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725fd2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35\n";
    // clang-format on

    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)fox, sizeof(fox) - 1);

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
    "           md2 : 8350e5a3e24c153df2275c9f80692773\n"
    "           md4 : 31d6cfe0d16ae931b73c59d7e0c089c0\n"
    "           md5 : d41d8cd98f00b204e9800998ecf8427e\n"
    "       md6-128 : 032f75b3ca02a393196a818328bd32e8\n"
    "       md6-256 : bca38b24a804aa37d821d31af00f5598230122c5bbfc4c4ad5ed40e4258f04ca\n"
    "       md6-384 : b0bafffceebe856c1eff7e1ba2f539693f828b532ebf60ae9c16cbc3499020401b942ac25b310b2227b2954ccacc2f1f\n"
    "       md6-512 : 6b7f33821a2c060ecdd81aefddea2fd3c4720270e18654f4cb08ece49ccb469f8beeee7c831206bd577f9f2630d9177979203a9489e47e04df4e6deaa0f8e0c0\n"
    "           sm3 : 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b\n"
    "          sha1 : da39a3ee5e6b4b0d3255bfef95601890afd80709\n"
    "        sha224 : d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f\n"
    "        sha256 : e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
    "        sha384 : 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b\n"
    "        sha512 : cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e\n"
    "      sha3-128 : b38fcdb382ebdd1d57afaf02bcc9fb19\n"
    "      sha3-224 : 6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7\n"
    "      sha3-256 : a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a\n"
    "      sha3-384 : 0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004\n"
    "      sha3-512 : a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26\n"
    "    RipeMD-128 : cdf26213a150dc3ecb610f18f6b38b46\n"
    "    RipeMD-160 : 9c1185a5c5e9fc54612808977ee8f548b2258d31\n"
    "    RipeMD-256 : 02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d\n"
    "    RipeMD-320 : 22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8\n"
    "       blake2s : 69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9\n"
    "       blake2b : 786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce\n"
    "        blake3 : af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262\n"
    "          gost : ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d\n"
    "   groestl-224 : f2e180fb5947be964cd584e22e496242c6a329c577fc4ce8c36d34c3\n"
    "   groestl-256 : 1a52d11d550039be16107f9c58db9ebcc417f16f736adb2502567119f0083467\n"
    "   groestl-384 : ac353c1095ace21439251007862d6c62f829ddbe6de4f78e68d310a9205a736d8b11d99bffe448f57a1cfa2934f044a5\n"
    "   groestl-512 : 6d3ad29d279110eef3adbd66de2a0345a77baede1557f5d099fce0c03d6dc2ba8e6d4a6633dfbd66053c20faa87d1a11f39a7fbe4a6c2f009801370308fc4ad8\n"
    "        jh-224 : 2c99df889b019309051c60fecc2bd285a774940e43175b76b2626630\n"
    "        jh-256 : 46e64619c18bb0a92a5e87185a47eef83ca747b8fcc8e1412921357e326df434\n"
    "        jh-384 : 2fe5f71b1b3290d3c017fb3c1a4d02a5cbeb03a0476481e25082434a881994b0ff99e078d2c16b105ad069b569315328\n"
    "        jh-512 : 90ecf2f76f9d2c8017d979ad5ab96b87d58fc8fc4b83060f3f900774faa2c8fabe69c5f4ff1ec2b61d6b316941cedee117fb04b1f4c5bc1b919ae841c50eec4f\n"
    "    snefru-128 : 8617f366566a011837f4fb4ba5bedea2\n"
    "    snefru-256 : 8617f366566a011837f4fb4ba5bedea2b892f3ed8b894023d16ae344b2be5881\n"
    "  spectral-256 : ec7c8524cdfabab3f4447d06464409f5420274f6b755fe0c45ee16ad64eaf47f\n"
    "  spectral-512 : fac1e798195e8d353f77f2a4c2a6fcf5d90b210df742a0d880d8a89a253bc6a0bc54345ac683dec96ef9495b3bf11862162edb7f0cbd71669324574743b01ee1\n"
    "   haval-128-3 : c68f39913f901f3ddf44c707357a7d70\n"
    "   haval-128-4 : ee6bbf4d6a46a679b3a856c88538bb98\n"
    "   haval-128-5 : 184b8482a0c050dca54b59c7f05bf5dd\n"
    "   haval-160-3 : d353c3ae22a25401d257643836d7231a9a95f953\n"
    "   haval-160-4 : 1d33aae1be4146dbaaca0b6e70d7a11f10801525\n"
    "   haval-160-5 : 255158cfc1eed1a7be7c55ddd64d9790415b933b\n"
    "   haval-192-3 : e9c48d7903eaf2a91c5b350151efcb175c0fc82de2289a4e\n"
    "   haval-192-4 : 4a8372945afa55c7dead800311272523ca19d42ea47b72da\n"
    "   haval-192-5 : 4839d0626f95935e17ee2fc4509387bbe2cc46cb382ffe85\n"
    "   haval-224-3 : c5aae9d47bffcaaf84a8c6e7ccacd60a0dd1932be7b1a192b9214b6d\n"
    "   haval-224-4 : 3e56243275b3b81561750550e36fcd676ad2f5dd9e15f2e89e6ed78e\n"
    "   haval-224-5 : 4a0513c032754f5582a758d35917ac9adf3854219b39e3ac77d1837e\n"
    "   haval-256-3 : 4f6938531f0bc8991f62da7bbd6f7de3fad44562b8c6f4ebf146d5b4e46f7c17\n"
    "   haval-256-4 : c92b2e23091e80e375dadce26982482d197b1a2521be82da819f8ca2c579b99b\n"
    "   haval-256-5 : be417bb4dd5cfb76c7126f4f8eeb1553a449039307b1a3cd451dbfdc0fbbe330\n"
    "         tiger : 3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3\n"
    "        tiger2 : 4441be75f6018773c206c22745374b924aa8313fef919f41\n"
    "     whirlpool : 19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3\n";
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
    "           md2 : 39a678d255754109e1be9259b980115f\n"
    "           md4 : b2cdd438a0405b70b2ada17b21316675\n"
    "           md5 : 29aedda82de8f860e085d0a3fa7b8b7b\n"
    "       md6-128 : 715057975c14fdaa5b33df5a44716e14\n"
    "       md6-256 : 6735fc6b1103c7b372b79c581fb6b850b35eb57a122ba00e6c4bb2e42bc460a6\n"
    "       md6-384 : 2cd82629bdd6c6bf25870b9ecdb618aae0ed632ef812b4438b4f1781d3bed526233e1cc22b265b6e521522353fe328ae\n"
    "       md6-512 : a1a37d450f1502966bd921b407a074edebfc5f878f27b343d89ef4a328db6da1a6f126ccce0165e9b01309efa91a23e05b0881954db0da3f848326811b6cd042\n"
    "    RipeMD-128 : b4563447abf7cc5d80e258002e470ec4\n"
    "    RipeMD-160 : b657ee770eb25c720381d8b64cf487a03e37e220\n"
    "    RipeMD-256 : 8814cc34336ccad19000c18d17aa98abb9c999566abed2e925f0e30205a816e2\n"
    "    RipeMD-320 : d655786d8d1ffe7fd2695a481f20b0ba8e1cfd2f256ec315aefa2c2a640502b0c70abd87100611ce\n";
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
    "           md2 : a90201383bcc37675c363e2a6549d0b6\n"
    "           md4 : 6a0e86dd59f27acf0dbaf3c2942d5783\n"
    "           md5 : 83acb6e67e50e31db6ed341dd2de1595\n"
    "       md6-128 : f380e3356f690c536e3d81d8b080a16c\n"
    "       md6-256 : 5e3a11d8d5d3540278d57aa4a366e28d1310f3740d419f01572c302a613d738c\n"
    "       md6-384 : 6f83e9846f5b6424aef4b9837601c691990ac0dbbcc33ed01c9db2bb3369835420db2278b24b5130f86e952b71483c9d\n"
    "       md6-512 : 8fe808ac8cb830f655296f0a9788832606f9e43e0226492bbf100963bdcef1ffca820c1183775fadc3645a772108322bda0c030a6a6ca84cafda5604037fab59\n"
    "           sm3 : 005b4e9445a688705515a094c36e43b6ce6e441382f863b28ff7b45c9842093c\n"
    "          sha1 : 23833462f55515a900e016db2eb943fb474c19f6\n"
    "        sha224 : a9ab1c5b26ddfea1cf0cc71c44363662af955b7bbf076d70af3ff9c2\n"
    "        sha256 : 620bfdaa346b088fb49998d92f19a7eaf6bfc2fb0aee015753966da1028cb731\n"
    "        sha384 : 23a8a9d42d150a471e8502ee2f4e822cb955e798882d698c5bd5aa01e43137cb566fefb1b06dced14b43c2e49758569d\n"
    "        sha512 : 75eb69a43e3bbcff322ec624ae7511cf3ad99df84b90d48b2665c70dff548c4857d4446c1eb04535bf54daa96e2cf5c3d5203d1fb43bbf4d40301bab95ac7772\n"
    "      sha3-128 : f2f1a7e794999f0d447a96ca5c351e6f\n"
    "      sha3-224 : 6f733daaa9696d60dd5c543b365a9ce953ea3ae5ef71a9c6040eca63\n"
    "      sha3-256 : aac68691d102829ac973f5b44c26165aa4e29cd498aff642a08944645d6ca5bd\n"
    "      sha3-384 : c6d45f444a995d9aee6f989b3cce12f3a94fa58c4a49218ad3f0405f9be1df2a848c008684b9d9e5f342d27978624846\n"
    "      sha3-512 : 5d6289e2eb89d4099552ad261115d31e1cfddf67f4997f19bd95d2436427deba817b9d4d3d107656283c602c19fa77f8c985b2a5e33d61cd0d56f3c1d61e93ea\n"
    "    RipeMD-128 : 3ef49aa6285775057773a8ae8ef478ce\n"
    "    RipeMD-160 : c8297aad716979548921b2e8e26ca8f20061dbef\n"
    "    RipeMD-256 : d9143a5a5eb6508434090cff7e8037aa9a198feb5adf4854620e3d15cdd3f490\n"
    "    RipeMD-320 : 18f1c6d1e1ff4c73efaf112dec5d798fb6c057b8c58992ceb0a7589dfe98abe86f25cac1bb514e2f\n"
    "       blake2s : bb7de2688fe7422836a025f3b3dbd7c4beed4b851e16ee98cbc550641a09b5f6\n"
    "       blake2b : e92b41dd767e71d505805bcb09c6fdb3f0954b37b06e9cd71eb09589a76d96436063c3cfd06b9ef5871124750b8d1bc515825828f97c619ecab807a4b4dd9cbf\n"
    "        blake3 : c66834cb4da1d8da1f6d7fc0cdb7f8643b1daf099801c3acbc198260c88a371a\n"
    "          gost : b5818ce86667c4f662b63b35228d69e3ea520f0ed6156c4670010af584b59086\n"
    "   groestl-224 : 5f9ad919c5c96f48d91c63f71287afba08a3ceb5f13dc041427e26f2\n"
    "   groestl-256 : 56c469307d0329bcf87c8259c8742d09cd1372d800dff5ecb174a4207c05d0b9\n"
    "   groestl-384 : bbd99ae5bc3fa61ce94814f00a02bb95d370c0bcbd4af35bd385ee781e8675eccc24191e7519e8c20cb75fc46b107cf9\n"
    "   groestl-512 : 96fe06fd0019f7264cbafe7baa7e38b6ffc93f75f1f35c2ef4f181224cb01bd4ba2034f0d6b9b701344639e11accf5f9b5b334871abac0c447d7abf349053bde\n"
    "        jh-224 : 8cf330ffa364367c0b7744985a41ad391ef50971f7b1a9410f42981e\n"
    "        jh-256 : 5325cca2e14ffaa4d248ccfa41594390d3cf582b3e0681da3c44737f353b3388\n"
    "        jh-384 : 83a9d8e4fa625100f2e542bf73ae25e98495754296f2f337d10e3fe22d233ee86e70ebb8abd375f1bb14ffc431ca8453\n"
    "        jh-512 : 23cfaf778e94fcbb29d56d8d8fa19637ca83261b1c297694e9f14ba85083acd48af22214013df4f98946a644183b62d84fa5c023029e2963a26bf4a7c430a4ea\n"
    "    snefru-128 : 10c620c639d64e3bc344018ad733e518\n"
    "    snefru-256 : 1a9418857290b8d1b6236da9debd629b0a26ef5909da567ec038d84503bc31cc\n"
    "  spectral-256 : 277b289836fdc825b4060dd23b17d61f98754b4a8c38e3027e0fac8766b600e0\n"
    "  spectral-512 : 167b47a13e8a958c137ecfdfa118b97af50a259e0b6d748ae2d255e366d60bf51b18dea4b99770acb0dc179cea3734205bfc38e196c2ac6956629dc40404de1c\n"
    "   haval-128-3 : e78c7fc90ba51af3fe4dd13ed92912fb\n"
    "   haval-128-4 : f368bb4f672d70da20528c9c0fe3ba21\n"
    "   haval-128-5 : e822c7bf9d14f4752bc32294cb045e0a\n"
    "   haval-160-3 : fdada81938ea696e049f8d5f055b70f8df657780\n"
    "   haval-160-4 : 1b113941d07975edd28a1cf2260880b52b869274\n"
    "   haval-160-5 : 6fb053d5e512ba26c6447b69b462aac74a0b5fd0\n"
    "   haval-192-3 : dbe73369c3728b3318dd6e3391846e8e22f6e2af98be4219\n"
    "   haval-192-4 : eb774826efaac676bebc92261ef4cf674a60c804ca7707d6\n"
    "   haval-192-5 : a346ce8c3e5069a92b3e70aaa574e85c705ffb1bb3fc5582\n"
    "   haval-224-3 : cfa2ba02be5254affcd6bc88c79e12caeaeef05d4d9359d365b7fe9d\n"
    "   haval-224-4 : 1bbe99df4b34b66e9c979d9de7a3322b7137d71fc9cecc563b101482\n"
    "   haval-224-5 : 316965b67da840337350f6d901f71b7fc28cf6523208db350ffee992\n"
    "   haval-256-3 : 52fdb97f18e2427391ddeeca993ce388258dd77b10fbed1912c1db4c5865edd1\n"
    "   haval-256-4 : c2e2b160889136dfb9b76c2010dfeca83423df0b89850dfbfa632ae148516236\n"
    "   haval-256-5 : dd62dab91725b66fc264bed5ba7c4abeae67ebb2b786ae093d89fc17220c437d\n"
    "         tiger : debf58dbd60c818b2151176f8223c2f5bccf57861870675d\n"
    "        tiger2 : ed0eaa6a8af698084708f561dc9f8e2481514f48966ff5d1\n"
    "     whirlpool : 88bf39ce7a2c404a9e07967c238c4c1fb7aa721b60c31bc2dbd0958bb6d019cd3c5c1c7ec267e3e51792b9379cf55cc781f3b8fa0af530d07a37e291815a9923\n";
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
    "          sha1 : afcb97e87528305aa7bb20c6969d073175d3aecb\n";
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
    "          sha1 : 05fe405753166f125559e7c9ac558654f107c7e9\n";
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
    "          sha1 : da39a3ee5e6b4b0d3255bfef95601890afd80709\n";
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
