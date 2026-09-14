// Copyright (c) 2022-2026, bageyelet

#include "t_cmd_common.h"
#include "t.h"
#include "data/big_buffers.h"

#include <color.h>

/* The escapes of the colored output, see common/color.c */
#define c_label "\x1b[0;36m"
#define c_off   "\x1b[0m"

#ifndef TEST
#define TEST(name) test_##name
#endif

int TEST(colors)(void)
{
    // the escapes wrap the padded name: the column must stay aligned
    const char* expected = "  " c_label "          md5" c_off
                           " : 29aedda82de8f860e085d0a3fa7b8b7b\n";

    // the colors are off by default in the tests, as they are whenever the
    // output is not a terminal
    colors_set_enabled(1);

    int r = TEST_FAILED;
    if (exec_commands("hash md5") != 0)
        goto end;

    char* out = strbuilder_reset(sb);
    r         = strcmp(out, expected) == 0 ? TEST_SUCCEEDED : TEST_FAILED;
    bhex_free(out);

end:
    colors_set_enabled(0);
    return r;
}

int TEST(notkitty_all_hashes)(void)
{
    // clang-format off
    const char* expected =
    "        blake2b : 5786ddb5ec49b658047191511dd05c047d2e5ab33051ef9e3a1ab4598a43be5ecc9ce58ce2e7b56e397c52723c2a59f5eea6364122ab08c480362576d013c6ec\n"
    "    blake2b-160 : d6f964b4f1e41c2506723b71daf4657c98950e9b\n"
    "    blake2b-256 : e67a081e2e1fe9dacbda322d4b5f947de20784c97cae6edc43a1fd4ca50dffc7\n"
    "    blake2b-384 : 6619478f3e4aeee13c78316a07299976df1e51c150466f18f9475d22a9575e2d947bdc84350b9de246456be83a2e995c\n"
    "        blake2s : 67f7c9bed696f1ce6704e5ea4d2ab7e2ee8314f6f9041db48740798ffa75f06f\n"
    "    blake2s-128 : 30501ca6c5becaf1f4f66eae22290d2a\n"
    "    blake2s-160 : 2f27ef249b0ea3979ac6928705fbdc45bbaaf1b7\n"
    "    blake2s-224 : 5def9ce625a70656fa61d8c18225ef1da7c52e82d167dab12013b9c8\n"
    "         blake3 : 4a6856e40fde37e44a4899b201d9544b637ecccef216b695b50f3deda350ead2\n"
    "        fnv1-32 : 5442890e\n"
    "        fnv1-64 : e6d9f322cb6d97ae\n"
    "       fnv1a-32 : 4f4d2cf4\n"
    "       fnv1a-64 : ea6f04f7eea17534\n"
    "           gost : 42b7c31dea43e2fa79e154105d449335fea473d6a6fcbd53edf275d5d57b3ab9\n"
    "    groestl-224 : ca1e68b3d7fc038e37708f54aca69e2d247be08e64c5ff66a903f78b\n"
    "    groestl-256 : 584b3849a43147709d5db32ce5375d019b62020189c599f07dea46dfa1ab9a0a\n"
    "    groestl-384 : 789f0ff3c619c38e98d74d486e387276bfd57a37ed725332879de6c1b2b72aa50daa23ab807261e5c8db0d5886bd1470\n"
    "    groestl-512 : 09e00c49a7e13592c068b9a60b6d8967c85cec65972c91c33c954c3fa9bb8596740e295f7d4ed6b954575c2a331e1eff1a42b3388ae657ff18b4e87fbd7d41cc\n"
    "    haval-128-3 : d693ec0defd29aad37bd5d914bb5200a\n"
    "    haval-128-4 : 7c87d57d64426e90b357df6af0ea6619\n"
    "    haval-128-5 : 3f93f058bd947a1b246ee143fb165336\n"
    "    haval-160-3 : 95bb3d499a2cad8fa80024caa7b72fbdb0d3b861\n"
    "    haval-160-4 : d68a953e84620c10d2a4ce3d09e68b6199f39f3d\n"
    "    haval-160-5 : bbb96f4db9e8ac01baecf0b82824e3eea515dea8\n"
    "    haval-192-3 : 8b75a23e60ea541b284dbbc25183d179054ee2058b4e2129\n"
    "    haval-192-4 : 547c4e9c13d955b78046e19146e4e67350532d6cac7d1090\n"
    "    haval-192-5 : 688b2e6b6282da51b2e6130fb01eeac07357278d9f85cea7\n"
    "    haval-224-3 : dbdc08bc4c67ccec28904374e35089598733c0f1d9663312e6c7652c\n"
    "    haval-224-4 : a361ac7122af72eaec62786f9a5b5fe70da5501b0b68fa0d51e0981b\n"
    "    haval-224-5 : 70b036df41310b36c41c4eb1804e8e178ab39123242919a5f1c6c067\n"
    "    haval-256-3 : 8276dae33378cf79e22309c993d9f0c5e88dc508422a0c3e14dd7df5d155b169\n"
    "    haval-256-4 : da53b3a5f8c9a120e61a9983471b348aaab390803afa22faaf31be901f41860f\n"
    "    haval-256-5 : ea0006d570f7abf643224d21d0d20fe8f9a67fe0f5876f44ece4fa9b19dc7166\n"
    "         jh-224 : 3a86fb6a5a09b09e098e350cff1d051593d58d9e74dfc75502817055\n"
    "         jh-256 : 03faf82ef077b4a0e2c1749b991de64667f2bb0ca0d4f2f6f519aa3921067e81\n"
    "         jh-384 : 7d9205be062c93dcd1ac69305fe3db8060a61726d5d2288ce79980f740f3bb3f187e59c96eecd054d9c1405c8cdc7477\n"
    "         jh-512 : 449c1e378357fd3e9b81409cfa09a257acfc10aed3c1daf134cc27227b84a65823d75da4dfb9e6200c911a2c9a0ad5d514b16cfcfd835ba00b97f0b3e9d44724\n"
    "     keccak-224 : 52022f6204263114f8da97241e155004b44951c14808576902b9d484\n"
    "     keccak-256 : e936468fb1177f05f633460bd20b9f4d45cdafb0bd805048d8d18a88bc2f73c9\n"
    "     keccak-384 : d5312f6c124b82054e0f651381f32bf02864309d163d0654e279727c63afc6ec172426e3ade9edd0271ba99897df1dce\n"
    "     keccak-512 : 9bbc844bb8460de5de17d58fc34b87bae4dc7873f8badff97085220174bc0acfaf10d033ad44c080b9be35176d574636b9ada8a520bc08079900f3e7589a49f7\n"
    "            md2 : 39a678d255754109e1be9259b980115f\n"
    "            md4 : b2cdd438a0405b70b2ada17b21316675\n"
    "            md5 : 29aedda82de8f860e085d0a3fa7b8b7b\n"
    "        md6-128 : 715057975c14fdaa5b33df5a44716e14\n"
    "        md6-256 : 6735fc6b1103c7b372b79c581fb6b850b35eb57a122ba00e6c4bb2e42bc460a6\n"
    "        md6-384 : 2cd82629bdd6c6bf25870b9ecdb618aae0ed632ef812b4438b4f1781d3bed526233e1cc22b265b6e521522353fe328ae\n"
    "        md6-512 : a1a37d450f1502966bd921b407a074edebfc5f878f27b343d89ef4a328db6da1a6f126ccce0165e9b01309efa91a23e05b0881954db0da3f848326811b6cd042\n"
    "    murmur3-128 : ef541afa172c65dbe6cb741df714bdf0\n"
    "     murmur3-32 : ca0154e7\n"
    "     RipeMD-128 : b4563447abf7cc5d80e258002e470ec4\n"
    "     RipeMD-160 : b657ee770eb25c720381d8b64cf487a03e37e220\n"
    "     RipeMD-256 : 8814cc34336ccad19000c18d17aa98abb9c999566abed2e925f0e30205a816e2\n"
    "     RipeMD-320 : d655786d8d1ffe7fd2695a481f20b0ba8e1cfd2f256ec315aefa2c2a640502b0c70abd87100611ce\n"
    "           sha1 : c4046bf205e3effade0a4d3df02ffef614d6b917\n"
    "         sha224 : 2110a12f02fa6d3a34035ca0135bfbbf5e303835bb7418e6570e98d7\n"
    "         sha256 : 9557f79685f4a6c3525cbb641834e787fe98bff62f9b822c13eb6ece23233484\n"
    "       sha3-128 : 53a2a118670fc36bcfd10e9e6853d4ef\n"
    "       sha3-224 : d1fa66f17e2d8b2d21172d8074589f55e210e49e2f315c931d9f88c8\n"
    "       sha3-256 : 59c6585e35ad306120654f0a8a71bd2e780d16eaa73b46668bbe2856ce42549f\n"
    "       sha3-384 : a221c2f8bbf2bd757ef27b23e1137cf7c640dc813bc72edfc736d0a7968e945365167e7cf61afe2911ef2d40367794f4\n"
    "       sha3-512 : 5cc86b7c3bbc77c730dfe8da1e998e94b088011770105e0f5d626610bb4bb7b6920e85472ed58111f303c419b1b9492afb7ea96f8997b2a29ed4f4a99c108dc3\n"
    "         sha384 : e2e4e08c8d5434dccbdd6f5013094ea5457b9df4e3df19e86f40e948a532815647411d67a975c9abe65962f72fd974ad\n"
    "         sha512 : f75d42af5af0bf02e994969c1e9945bbbaafaf52c37cc35f37197b736a6266627759ae4b4e13a47e149e59eb54c09bad8e6d4a131cc5081c0b4a2cfb7c1d0276\n"
    "     sha512-224 : d03e49a8e36fc5d76814b91a6e3644b6cf767719f5efbec408a61ac3\n"
    "     sha512-256 : 10f67b2285cf21f75df5c88af176ed1ab4012c3d5c403380d9c61c43d60e4891\n"
    "   shake128-256 : 6f4484baa319462b3cc97d8929516b9d83c8328ba00cba106508ba21178096bc\n"
    "   shake256-512 : 4a285950f39689ea9ff9f652c44db8a81db04f2d1ff89221aea1dbe2ad7176944a51abf7d96f5a3c01cc3320582b73479180a0b0d4ef5346a9b5a646561afcc0\n"
    "     skein-1024 : b2a8db9b873c686bbad82001b4e3ad1b30fd37d7c8d93a2a01eff77687878a129ed846b8b87babc0ccaa843afdbf0a5def7b10c93b865eae0cb036c04990cbe78a26f5ae21717bab4f54679b465f3db9d5c494580de9987eb14c0dcb682b9b46952846e3d17d8f009cc8efe5d0de870e6d349ffdea79327b9f12956ad9cce6f0\n"
    "      skein-256 : d839b995e6627c5207e5cf5c644bb0e9f52e520964886f4ff8c065952d4dcd56\n"
    "      skein-512 : 33342c53a36c2f4f0406345121289c7a39939d609066955554e5267badf26c863e76dd06d7c117571bf825036d07ce4385e126f579a585faf9251b07f40806f2\n"
    "  skein-512-256 : 0cefde2c409cf2f59198fe2dc2f6d944f5cd519a7a815206fdcac364a7f4c3cb\n"
    "            sm3 : 0a642763c258bdeb9eb8c33367b12a258dfabed33f80bb59b821f57165ab9d25\n"
    "     snefru-128 : 73a1f2c464a449f06e0fce691d6ef2f4\n"
    "     snefru-256 : dd083bd7cf0a464f42f6bdc3890758216ef4d883ac354259a561411cb78326fd\n"
    "   spectral-256 : f5d93f497472d8b3c7087a8e069b155927500a8bf17316f96973b1cd3aa42604\n"
    "   spectral-512 : c7394bab4293f6a46eace4f316ac054babe1bfe1517d8b83e3c2cbe4af42bbba9da2adf59006aa443ed25c5114f7dcaab279f1f88fbd2f3e746973e8a98614d4\n"
    "   streebog-256 : 18e62f1155c3e49e5daaf2dd2ac335700d33b4fb8b3dc643637ecea93f820da1\n"
    "   streebog-512 : c9aa3ccc5bcb33b48b666b2f23ea10503cf2468e252364c8213c2dac322ad7c1189e913dd31d65a4af4a7800ac3d17406f55f9e95487483f3d15901ebd73e008\n"
    "          tiger : 2548abf82405228ef4124ea25697930ff0d411c3600f4930\n"
    "         tiger2 : 83a9dbaa6f616eeba92960ecc0f1fe5bd0e206410b659d27\n"
    "      whirlpool : 8ff340018588ebb0603e53b187e42ff4d5e516bc45c0d7e12f84259fa4ce58be28119286fa189e1219d231eff0c638c0c5f3b8508a9885e92bcacb4d2cfec472\n"
    "       xxh3-128 : 4a7847c3d90a0368a5e5beb4e21ebf83\n"
    "        xxh3-64 : a5e5beb4e21ebf83\n"
    "          xxh32 : b930dbf2\n"
    "          xxh64 : f7f9d32d00f18d6d\n";
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
    "        blake2b : 4a8979ddd9e465c3634e84dce132976bd503596616974d95256be161e2a81199f6a3846fb65fa90a568caa7b801b49671d3be70b32237d8fac1d428011bc769f\n"
    "    blake2b-160 : 6fae4112889ba32fec84dd2fccf7689374350077\n"
    "    blake2b-256 : 05db633bc29672d515dedc47a579d9237fa0e06156fbb6c162dd05a1690e82c0\n"
    "    blake2b-384 : 42e011e3e07a5fd9f54ed4f0e08fa1f0854e9fdb4d8c4cd6b4488fb92a797d67b08499b41a3929a08f8085cce3260b98\n"
    "        blake2s : 0e1361f22dba63b71bbefc96a85a581267755cb5ecb20c40d46cb69c4989320a\n"
    "    blake2s-128 : 6b2ec9fdb0a61c393e8f7fa2392258d6\n"
    "    blake2s-160 : 22f62a40bedae1f19f0a852b5fc643295cacf91e\n"
    "    blake2s-224 : 766618af8bef2362b730aee8329ed579f38dd86faa01b09286d64f2d\n"
    "         blake3 : 8d0a62ce469f300a55d8c6bc2ab1c639b1cd8b6a2aa94fd1be56d61e779a1ebe\n"
    "        fnv1-32 : 330599c5\n"
    "        fnv1-64 : 477a7cb2bcb62f25\n"
    "       fnv1a-32 : 2ca5adc5\n"
    "       fnv1a-64 : 533c4ee3026e5325\n"
    "           gost : 498f0bc6ef005a73776a6c2f063452121608f859d78f93ceaf704d1cc7973a77\n"
    "    groestl-224 : b3b0ee2672280bdbaf36b4cbadc5cada891c30cca846a99bab881959\n"
    "    groestl-256 : cdf5c89af0b57a1c522f28d54e9cb078f257d36a3b49bcad2129bf36859c0c29\n"
    "    groestl-384 : cfdfeafc23e4a365bdc3ad3135e5f0b6456b55fa1f54b78666251d9d9e6660a58a9feba292e49767ee4ffc046b037bad\n"
    "    groestl-512 : 9cc385b60e3deb7574a97bb309d01d0ec6b8805afc8f2ce69232b8f7d7ea01b80256cec4682aad04ff75a8bd65c0db33f139ef2cee396ff0a3139c5d22fe185f\n"
    "    haval-128-3 : 4b5543812fe25f6a66fdcba7298effc4\n"
    "    haval-128-4 : 73c617874367c18a8558938a95b1c122\n"
    "    haval-128-5 : 3370d314b69ce1f655b1d47817192c24\n"
    "    haval-160-3 : db90dbdb9170827ffad2a6f52a56ec465c7eedde\n"
    "    haval-160-4 : 9643be3fb5a7b2588fbf2fff58748c3b4c2798fd\n"
    "    haval-160-5 : dc90db1672d6bd5b324b8827e3594c44862a9246\n"
    "    haval-192-3 : cb32ca5db92be492c7fb64cd3753c6de2c086232700bb6f2\n"
    "    haval-192-4 : 6f13962178f7f0586f7567cd53ef5e9091f52c5147b8f874\n"
    "    haval-192-5 : 5a161efaefe3dfc63b136bedb32e335e32317e8d1f8f9397\n"
    "    haval-224-3 : 5eb851e96bb20d613b4604fb455bd50981cf6f2373ce86beab8d8774\n"
    "    haval-224-4 : 85c58513605ab1da0e24d8d8f244b15fed37a6696020d295b8cc1557\n"
    "    haval-224-5 : faf374aca9a752206f437541f222fb4c8b1fe52727b66d33def5af25\n"
    "    haval-256-3 : a60fcb4f1b700b573eb0fef7da149447fe0bc718573f59b3964e38bfbef9f829\n"
    "    haval-256-4 : d5f97825d89f090a0389de899b39f356637eb7d427a9025c7aeaceb518df69be\n"
    "    haval-256-5 : 875aeea0a5421e5e2a661756e242623192f6e349e4ba3a8e10aec4b0a8baf60a\n"
    "         jh-224 : c296c400d7f8a90c35d8cb0cc1b952733ecd7a1263b7423e7b0d8e11\n"
    "         jh-256 : 85765a09fb35ebe489e51fb501338fd64f18948a34f3cec99ba454ecf7db9962\n"
    "         jh-384 : 5ee8161db3122e9aeaa28db7daa773d2ad9f88def30f8a824191d11359904470f596a31c55c911bda6afc16cf5d127d2\n"
    "         jh-512 : f94130466fc22e6bddf2112fbe6a9aa4a34aa6d7a964942720dd7e3eadb88e0601cabc6a3d92f41ecacc83fc1743f90f8f3f76c01f2832552e5cc937cc9a0331\n"
    "     keccak-224 : 5ef5a4ecff6caa0ac5a3d93da7a17627ec294bf39f19b1c624db3c4c\n"
    "     keccak-256 : d05042ceed4f7423faf589869be13d7020531b7ae7e923824ed35cdedf55fcf0\n"
    "     keccak-384 : 523a38eca347b9d9a817b765462bd428e5943cb7d8456834a9b0446e7e5c63928809da0ec80cb2bb3c1b2d28d257f4df\n"
    "     keccak-512 : 79c0723f8af1d5d23f672906486b36256eeac385b2424ee3d910c7a67ccfbb4ecad512f8b6b4514ce8bb879e65d1f514bbcb78a84e87e91073fd3fee5e35d841\n"
    "            md2 : 66d95a4b053cd6fc116f6a6fb343bf8f\n"
    "            md4 : 7639e556f646d117b2a9099600185bdc\n"
    "            md5 : 471972b39f15792c973bc23952feb72c\n"
    "        md6-128 : 99d56c61792fb2122b8d9e1fa7b23d97\n"
    "        md6-256 : b7c80f5c6e8d793bc76d99342310e239947cf0cfed1568974894494ef38bcf5d\n"
    "        md6-384 : 5a66d18a53947ac663eb1974c647ca96ec22ffad466644df9aea58b162d90dab0b54434b2faeb35b60c9378df1811f20\n"
    "        md6-512 : 93e3e24b3969133d553a3e95be9e0723ecd83ea15b526d80cd23d2f7f56c7eac3fb4391dea8a81c21b0cbd3405f5f6ce80c84e6e1e54a545860d4a2cb5cd9168\n"
    "    murmur3-128 : 63dd9a4365f674cd0abf1ffdd1f53fad\n"
    "     murmur3-32 : 9dff4e39\n"
    "     RipeMD-128 : 4328ca16e9bfcb0302e30ba841524793\n"
    "     RipeMD-160 : ff500b620c1d880928f74fd2e0bdfc1dd0aa7d7e\n"
    "     RipeMD-256 : 10edc6a6dc7bac123572f53dfbb8f359b624d83ed00f0d7733137e913ed696ed\n"
    "     RipeMD-320 : 5e81a7d551d8dd4365769817beea49b1a5db2a512aab654956406a7c5591cb9407d8e6170eb95ccb\n"
    "           sha1 : 22a34b0b4dae9bd90d573045fcef86877980de10\n"
    "         sha224 : f1b9ab1cb2c22a331a9a7636e251428658637c98de8a47401dd0243f\n"
    "         sha256 : 52cfd0f284a6f745ffc05576fd2179e6d91db19d58f91729d737e43ae547dba0\n"
    "       sha3-128 : 6b512351dcadef16dbfed499c47aebc7\n"
    "       sha3-224 : 64c2ad47bb7cc8d30c3117feb3c8472b834a85112ed71be36371d3c7\n"
    "       sha3-256 : 52c9b875be992743eb681976527c83ac3ccfec94aeff1a1526c90a71f6666940\n"
    "       sha3-384 : a3e1c59b4001aed941632ae35e4c5b22e2d1ef2ebeb2059d41858c1ec8af43fa2551a0b79d26519e4e8164dc0bc8416f\n"
    "       sha3-512 : ed7a2325f0e562eb9e7074d31a4dba3a98b04312573589901fa0096d36f14346134d9c9545882e43b9f95a2eed23f730510c6d09087b015ea159426f8725687e\n"
    "         sha384 : 7ac112d2c47eabe1365f6967c01a1320b19341e4e21754d5da9911a2475feb80e4633fb859e8adac8198c1d98a81d904\n"
    "         sha512 : fb30acf22eb1be144c6469c760c087ad5fd10e7b90780454300a3532d1bb5ace44093e8b8345370e1dad7d7dfa8d61d776d3c4baf8613308b509f9ecf0c3df7c\n"
    "     sha512-224 : 5ee211c43474e246516f649e5764fe3a6eb049b61a8ecba61a04b11c\n"
    "     sha512-256 : 27909df2197c5cf430c75317a3fb1d7b5c4c67760c782a5220e842864a3a1a9c\n"
    "   shake128-256 : 1ff501f352b8ec533acc3b3c9c009c16791cd953580ad3dc59fa7759239e242a\n"
    "   shake256-512 : 1f38fbd2fd26609dead6bdf012ab6553b909f169ae4fb5f2d7f45e71b6c441f0ce35877440440426ad6dd3f794f80c6322ab8707cbd9bd1f11b57fddf818311a\n"
    "     skein-1024 : fc204917e8b5af2d553f4ec4b3c068a96aff8b6737cb1dd3b81ef073fd461f26f741e52248e7a8789578bc88e201ab0543de5ce5b2fc59ac0ac29bdb1dc955951dcde0e6b277ae9c8cdf750ec2703642743595b83b6be62023422f721f5ee43fa38ba58ff827bcee5204b746199b57ff7d22a38a7bea83c2f649cdc60895c305\n"
    "      skein-256 : 58b0d0a6526091f1ca56f290e03510de64f0141c4feedda2e956cd37b113cf30\n"
    "      skein-512 : 148b2597e0eed788e1e3ae936f8a4ba54a795067f8e1676bbb937e13771e2c3d5f9b797d73fbe1c977549ca803ee5c8ea3886948d3285283e75930fbc3bc100e\n"
    "  skein-512-256 : 1bac8b0871992efb6d8919244e63ae69914c2f0689bd22d5bd0d1c3f6576487c\n"
    "            sm3 : 1d9ca3cf9b7b701765e28e11afa493e24192479b7f27b40d2c10db18d483480e\n"
    "     snefru-128 : f10f2db5f64a712070a93d205afe7dad\n"
    "     snefru-256 : 91eb5cbd94ed38f0f7e7e083d3e54a7c7db6627a0008ca241dfa05187c8dd7fb\n"
    "   spectral-256 : 802af7a44b4db4b55b46ae40aa4c6dbb8b373ef9e1f3ed019824e32111933c67\n"
    "   spectral-512 : ee308caae1eae4a4850a630cfcf4d0cd128dfa83a9af473145655478d56b2fc6a467099e473fd3f8bba03bb7f8e442370f9011b7ac49a0644d360f2cd199113f\n"
    "   streebog-256 : 856c49ffb8bd999aaa6a71269b7c957c296bd79d5f7ef6b67e019e7ce535e48d\n"
    "   streebog-512 : 2ff7ca84b9aa6813a90a8f35afe65d780eac62e656b013bff55ce28f7df2faf12ac7f7d6529f16776da3673616132ab9312693fd85439b25a6c494c24ba1a5dd\n"
    "          tiger : 7371d6b382eebdb56131de1c4a0694fe8aa3dc71f948eb03\n"
    "         tiger2 : d088a34c5da520e3920f767fb892337db5f373daa951e726\n"
    "      whirlpool : 639273f566b49e8329bddb349a6218d9895be2b24e185b060dd0415a919c721636b86438495c72bd4c60659dbf4892b2b570c644beaee05df8764547cedca015\n"
    "       xxh3-128 : e6d6a71c4d3ed204e295fb5ef60c5002\n"
    "        xxh3-64 : e295fb5ef60c5002\n"
    "          xxh32 : e3ccd769\n"
    "          xxh64 : 2292e993a787e883\n";
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
    "        blake2b : a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918\n"
    "    blake2b-160 : 3c523ed102ab45a37d54f5610d5a983162fde84f\n"
    "    blake2b-256 : 01718cec35cd3d796dd00020e0bfecb473ad23457d063b75eff29c0ffa2e58a9\n"
    "    blake2b-384 : b7c81b228b6bd912930e8f0b5387989691c1cee1e65aade4da3b86a3c9f678fc8018f6ed9e2906720c8d2a3aeda9c03d\n"
    "        blake2s : 606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812\n"
    "    blake2s-128 : 96fd07258925748a0d2fb1c8a1167a73\n"
    "    blake2s-160 : 5a604fec9713c369e84b0ed68daed7d7504ef240\n"
    "    blake2s-224 : e4e5cb6c7cae41982b397bf7b7d2d9d1949823ae78435326e8db4912\n"
    "         blake3 : 2f1514181aadccd913abd94cfa592701a5686ab23f8df1dff1b74710febc6d4a\n"
    "        fnv1-32 : e9c86c6e\n"
    "        fnv1-64 : a8b2f3117de37ace\n"
    "       fnv1a-32 : 048fff90\n"
    "       fnv1a-64 : f3f9b7f5e7e47110\n"
    "           gost : 77b7fa410c9ac58a25f49bca7d0468c9296529315eaca76bd1a10f376d1f4294\n"
    "    groestl-224 : 8ce3ce0f7092cada755be8f614fd6d5e5738ff1f6cd5dabe42404c46\n"
    "    groestl-256 : 8c7ad62eb26a21297bc39c2d7293b4bd4d3399fa8afab29e970471739e28b301\n"
    "    groestl-384 : 9330aeb62a1fc0a464dd70ac27b57075e00ae5d627f9bd6ff72952b3857aba2cfbcc4345af9a04fcc13eb346829e4088\n"
    "    groestl-512 : badc1f70ccd69e0cf3760c3f93884289da84ec13c70b3d12a53a7a8a4a513f99715d46288f55e1dbf926e6d084a0538e4eebfc91cf2b21452921ccde9131718d\n"
    "    haval-128-3 : 713502673d67e5fa557629a71d331945\n"
    "    haval-128-4 : 6eece560a2e8d6b919e81fe91b0e7156\n"
    "    haval-128-5 : 696f02111f2e1da5c21d50eb782b7e8f\n"
    "    haval-160-3 : b338ac397e8bccadcccd96549cadd4882d834107\n"
    "    haval-160-4 : 6e739d01f5739ceed94da1a115b52d5951280560\n"
    "    haval-160-5 : ecce9fa8a428866304ff082af2f9062637d36b23\n"
    "    haval-192-3 : 58e6ced002e311172483d434ba738ad033e7fa950e431503\n"
    "    haval-192-4 : 228ee09bc7e36151c6f285f558e6aede66ad38c8341592b9\n"
    "    haval-192-5 : 023d045f75d4bf051fd6e50f7b7417bf9949c4b5d2b4b7ef\n"
    "    haval-224-3 : e1d5792306f56b22419662b06d1885a66dca3eba01f53274c89aeaeb\n"
    "    haval-224-4 : dddd6689885f6db4ad91e35a35e1f4498446510df798d4fd54b8654f\n"
    "    haval-224-5 : 03d953298c8e56b46385c6761cd4b2e377889a75c97eaea475421c73\n"
    "    haval-256-3 : 9446028f42b3768a41bd873ca69b0c006341d986613567f39eb61f96ca683300\n"
    "    haval-256-4 : c0d4c6ea514105fd1a9c38a238553fb7fa21d4127eb1a3035a75ce9d06a83d96\n"
    "    haval-256-5 : b89c551cdfe2e06dbd4cea2be1bc7d557416c58ebb4d07cbc94e49f710c55be4\n"
    "         jh-224 : bb21255e4a6bcbd3ddbf8694df2e7f41b74a69c1a7e1c2d36a3fd405\n"
    "         jh-256 : 6a049fed5fc6874acfdc4a08b568a4f8cbac27de933496f031015b38961608a0\n"
    "         jh-384 : de44fe5f835f5518c603aec9d67363466d9f3a5b54d4cfbd4083b055f95a21a2562abaa59b830b3bc4e023d0b52a1268\n"
    "         jh-512 : 043f14e7c0775e7b1ef5ad657b1e858250b21e2e61fd699783f8634cb86f3ff938451cabd0c8cdae91d4f659d3f9f6f654f1bfedca117ffba735c15fedda47a3\n"
    "     keccak-224 : 310aee6b30c47350576ac2873fa89fd190cdc488442f3ef654cf23fe\n"
    "     keccak-256 : 4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15\n"
    "     keccak-384 : 283990fa9d5fb731d786c5bbee94ea4db4910f18c62c03d173fc0a5e494422e8a0b3da7574dae7fa0baf005e504063b3\n"
    "     keccak-512 : d135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609\n"
    "            md2 : 03d85a0d629d2c442e987525319fc471\n"
    "            md4 : 1bee69a46ba811185c194762abaeae90\n"
    "            md5 : 9e107d9d372bb6826bd81d3542a419d6\n"
    "        md6-128 : 7b428f5ec47e0174faf31dc7c89590c6\n"
    "        md6-256 : 977592608c45c9923340338450fdcccc21a68888e1e6350e133c5186cd9736ee\n"
    "        md6-384 : d850fdde986e16df19d65c50788afd0a8953914a4bc65831f5283c3016b79ddfa4a0bc00694e472f4a0bed7da601bb90\n"
    "        md6-512 : dcba0c6593fbd83a0f5f148588baa79530579c1f5e7f19d500fe282d137bff465106f25c9f0619b4082a730683d5f58311c0c1913068e91b0ebdf9ace3ff5b9e\n"
    "    murmur3-128 : e34bbc7bbc071b6c7a433ca9c49a9347\n"
    "     murmur3-32 : 2e4ff723\n"
    "     RipeMD-128 : 3fa9b57f053c053fbe2735b2380db596\n"
    "     RipeMD-160 : 37f332f68db77bd9d7edd4969571ad671cf9dd3b\n"
    "     RipeMD-256 : c3b0c2f764ac6d576a6c430fb61a6f2255b4fa833e094b1ba8c1e29b6353036f\n"
    "     RipeMD-320 : e7660e67549435c62141e51c9ab1dcc3b1ee9f65c0b3e561ae8f58c5dba3d21997781cd1cc6fbc34\n"
    "           sha1 : 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12\n"
    "         sha224 : 730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525\n"
    "         sha256 : d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592\n"
    "       sha3-128 : 4d7869754147b578b50c0b658399212f\n"
    "       sha3-224 : d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795\n"
    "       sha3-256 : 69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04\n"
    "       sha3-384 : 7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41\n"
    "       sha3-512 : 01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450\n"
    "         sha384 : ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1\n"
    "         sha512 : 07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6\n"
    "     sha512-224 : 944cd2847fb54558d4775db0485a50003111c8e5daa63fe722c6aa37\n"
    "     sha512-256 : dd9d67b371519c339ed8dbd25af90e976a1eeefd4ad3d889005e532fc5bef04d\n"
    "   shake128-256 : f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e\n"
    "   shake256-512 : 2f671343d9b2e1604dc9dcf0753e5fe15c7c64a0d283cbbf722d411a0e36f6ca1d01d1369a23539cd80f7c054b6e5daf9c962cad5b8ed5bd11998b40d5734442\n"
    "     skein-1024 : 4cf6152f1a7e598098d28f04e13d7742ba39b7fadbbcf2167bda4e1615d551f3f6b4edbbb391ffa09e6cc0a4af1eb366b30b5f107b437e2ea5cb586afb0341bd97dabe7cc46e7be3a054aa605395e43b243654c01ffc14c8b5443488f35d80b504a612f3d29d767106d0d9249aaa4fd99b67a94fb8661a3520004501192d84fa\n"
    "      skein-256 : c0fbd7d779b20f0a4614a66697f9e41859eaf382f14bf857e8cdb210adb9b3fe\n"
    "      skein-512 : 94c2ae036dba8783d0b3f7d6cc111ff810702f5c77707999be7e1c9486ff238a7044de734293147359b4ac7e1d09cd247c351d69826b78dcddd951f0ef912713\n"
    "  skein-512-256 : b3250457e05d3060b1a4bbc1428bc75a3f525ca389aeab96cfa34638d96e492a\n"
    "            sm3 : 5fdfe814b8573ca021983970fc79b2218c9570369b4859684e2e4c3fc76cb8ea\n"
    "     snefru-128 : 59d9539d0dd96d635b5bdbd1395bb86c\n"
    "     snefru-256 : 674caa75f9d8fd2089856b95e93a4fb42fa6c8702f8980e11d97a142d76cb358\n"
    "   spectral-256 : 201a3eb9c76eb403bad609bdc421591ad8922c9bd55d94be5719902cf8714b72\n"
    "   spectral-512 : 4822278b3bba55fa6f1f39b36eb95003b9f46745e88549fbd86160436f3f0da4c19918e86ac44f457ab4acdb0b32f3217d2c7cd06240a3251b923fa4b9276322\n"
    "   streebog-256 : 3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4\n"
    "   streebog-512 : d2b793a0bb6cb5904828b5b6dcfb443bb8f33efc06ad09368878ae4cdc8245b97e60802469bed1e7c21a64ff0b179a6a1e0bb74d92965450a0adab69162c00fe\n"
    "          tiger : 6d12a41e72e644f017b6f0e2f7b44c6285f06dd5d2c5b075\n"
    "         tiger2 : 976abff8062a2e9dcea3a1ace966ed9c19cb85558b4976d8\n"
    "      whirlpool : b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725fd2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35\n"
    "       xxh3-128 : ddd650205ca3e7fa24a1cc2e3a8a7651\n"
    "        xxh3-64 : ce7d19a5418fb365\n"
    "          xxh32 : e85ea4de\n"
    "          xxh64 : 0b242d361fda71bc\n";
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
    "        blake2b : 786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce\n"
    "    blake2b-160 : 3345524abf6bbe1809449224b5972c41790b6cf2\n"
    "    blake2b-256 : 0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8\n"
    "    blake2b-384 : b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100\n"
    "        blake2s : 69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9\n"
    "    blake2s-128 : 64550d6ffe2c0a01a14aba1eade0200c\n"
    "    blake2s-160 : 354c9c33f735962418bdacb9479873429c34916f\n"
    "    blake2s-224 : 1fa1291e65248b37b3433475b2a0dd63d54a11ecc4e3e034e7bc1ef4\n"
    "         blake3 : af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262\n"
    "        fnv1-32 : 811c9dc5\n"
    "        fnv1-64 : cbf29ce484222325\n"
    "       fnv1a-32 : 811c9dc5\n"
    "       fnv1a-64 : cbf29ce484222325\n"
    "           gost : ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d\n"
    "    groestl-224 : f2e180fb5947be964cd584e22e496242c6a329c577fc4ce8c36d34c3\n"
    "    groestl-256 : 1a52d11d550039be16107f9c58db9ebcc417f16f736adb2502567119f0083467\n"
    "    groestl-384 : ac353c1095ace21439251007862d6c62f829ddbe6de4f78e68d310a9205a736d8b11d99bffe448f57a1cfa2934f044a5\n"
    "    groestl-512 : 6d3ad29d279110eef3adbd66de2a0345a77baede1557f5d099fce0c03d6dc2ba8e6d4a6633dfbd66053c20faa87d1a11f39a7fbe4a6c2f009801370308fc4ad8\n"
    "    haval-128-3 : c68f39913f901f3ddf44c707357a7d70\n"
    "    haval-128-4 : ee6bbf4d6a46a679b3a856c88538bb98\n"
    "    haval-128-5 : 184b8482a0c050dca54b59c7f05bf5dd\n"
    "    haval-160-3 : d353c3ae22a25401d257643836d7231a9a95f953\n"
    "    haval-160-4 : 1d33aae1be4146dbaaca0b6e70d7a11f10801525\n"
    "    haval-160-5 : 255158cfc1eed1a7be7c55ddd64d9790415b933b\n"
    "    haval-192-3 : e9c48d7903eaf2a91c5b350151efcb175c0fc82de2289a4e\n"
    "    haval-192-4 : 4a8372945afa55c7dead800311272523ca19d42ea47b72da\n"
    "    haval-192-5 : 4839d0626f95935e17ee2fc4509387bbe2cc46cb382ffe85\n"
    "    haval-224-3 : c5aae9d47bffcaaf84a8c6e7ccacd60a0dd1932be7b1a192b9214b6d\n"
    "    haval-224-4 : 3e56243275b3b81561750550e36fcd676ad2f5dd9e15f2e89e6ed78e\n"
    "    haval-224-5 : 4a0513c032754f5582a758d35917ac9adf3854219b39e3ac77d1837e\n"
    "    haval-256-3 : 4f6938531f0bc8991f62da7bbd6f7de3fad44562b8c6f4ebf146d5b4e46f7c17\n"
    "    haval-256-4 : c92b2e23091e80e375dadce26982482d197b1a2521be82da819f8ca2c579b99b\n"
    "    haval-256-5 : be417bb4dd5cfb76c7126f4f8eeb1553a449039307b1a3cd451dbfdc0fbbe330\n"
    "         jh-224 : 2c99df889b019309051c60fecc2bd285a774940e43175b76b2626630\n"
    "         jh-256 : 46e64619c18bb0a92a5e87185a47eef83ca747b8fcc8e1412921357e326df434\n"
    "         jh-384 : 2fe5f71b1b3290d3c017fb3c1a4d02a5cbeb03a0476481e25082434a881994b0ff99e078d2c16b105ad069b569315328\n"
    "         jh-512 : 90ecf2f76f9d2c8017d979ad5ab96b87d58fc8fc4b83060f3f900774faa2c8fabe69c5f4ff1ec2b61d6b316941cedee117fb04b1f4c5bc1b919ae841c50eec4f\n"
    "     keccak-224 : f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd\n"
    "     keccak-256 : c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470\n"
    "     keccak-384 : 2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff\n"
    "     keccak-512 : 0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e\n"
    "            md2 : 8350e5a3e24c153df2275c9f80692773\n"
    "            md4 : 31d6cfe0d16ae931b73c59d7e0c089c0\n"
    "            md5 : d41d8cd98f00b204e9800998ecf8427e\n"
    "        md6-128 : 032f75b3ca02a393196a818328bd32e8\n"
    "        md6-256 : bca38b24a804aa37d821d31af00f5598230122c5bbfc4c4ad5ed40e4258f04ca\n"
    "        md6-384 : b0bafffceebe856c1eff7e1ba2f539693f828b532ebf60ae9c16cbc3499020401b942ac25b310b2227b2954ccacc2f1f\n"
    "        md6-512 : 6b7f33821a2c060ecdd81aefddea2fd3c4720270e18654f4cb08ece49ccb469f8beeee7c831206bd577f9f2630d9177979203a9489e47e04df4e6deaa0f8e0c0\n"
    "    murmur3-128 : 00000000000000000000000000000000\n"
    "     murmur3-32 : 00000000\n"
    "     RipeMD-128 : cdf26213a150dc3ecb610f18f6b38b46\n"
    "     RipeMD-160 : 9c1185a5c5e9fc54612808977ee8f548b2258d31\n"
    "     RipeMD-256 : 02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d\n"
    "     RipeMD-320 : 22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8\n"
    "           sha1 : da39a3ee5e6b4b0d3255bfef95601890afd80709\n"
    "         sha224 : d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f\n"
    "         sha256 : e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
    "       sha3-128 : b38fcdb382ebdd1d57afaf02bcc9fb19\n"
    "       sha3-224 : 6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7\n"
    "       sha3-256 : a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a\n"
    "       sha3-384 : 0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004\n"
    "       sha3-512 : a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26\n"
    "         sha384 : 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b\n"
    "         sha512 : cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e\n"
    "     sha512-224 : 6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4\n"
    "     sha512-256 : c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a\n"
    "   shake128-256 : 7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26\n"
    "   shake256-512 : 46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be\n"
    "     skein-1024 : 0fff9563bb3279289227ac77d319b6fff8d7e9f09da1247b72a0a265cd6d2a62645ad547ed8193db48cff847c06494a03f55666d3b47eb4c20456c9373c86297d630d5578ebd34cb40991578f9f52b18003efa35d3da6553ff35db91b81ab890bec1b189b7f52cb2a783ebb7d823d725b0b4a71f6824e88f68f982eefc6d19c6\n"
    "      skein-256 : c8877087da56e072870daa843f176e9453115929094c3a40c463a196c29bf7ba\n"
    "      skein-512 : bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af41fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a\n"
    "  skein-512-256 : 39ccc4554a8b31853b9de7a1fe638a24cce6b35a55f2431009e18780335d2621\n"
    "            sm3 : 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b\n"
    "     snefru-128 : 8617f366566a011837f4fb4ba5bedea2\n"
    "     snefru-256 : 8617f366566a011837f4fb4ba5bedea2b892f3ed8b894023d16ae344b2be5881\n"
    "   spectral-256 : ec7c8524cdfabab3f4447d06464409f5420274f6b755fe0c45ee16ad64eaf47f\n"
    "   spectral-512 : fac1e798195e8d353f77f2a4c2a6fcf5d90b210df742a0d880d8a89a253bc6a0bc54345ac683dec96ef9495b3bf11862162edb7f0cbd71669324574743b01ee1\n"
    "   streebog-256 : 3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb\n"
    "   streebog-512 : 8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a\n"
    "          tiger : 3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3\n"
    "         tiger2 : 4441be75f6018773c206c22745374b924aa8313fef919f41\n"
    "      whirlpool : 19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3\n"
    "       xxh3-128 : 99aa06d3014798d86001c324468d497f\n"
    "        xxh3-64 : 2d06800538d394c2\n"
    "          xxh32 : 02cc5d05\n"
    "          xxh64 : ef46db3751d8e999\n";
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

// The digests of "abc" as the standards that define them publish them. The
// big listings above pin every algorithm, but they pin it to what this code
// produces; these few are worth writing down separately, traceable to the
// document rather than to us
int TEST(published_vectors_abc)(void)
{
    static const char abc[] = "abc";

    // clang-format off
    const char* expected =
    "       sha3-256 : 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532\n" // FIPS 202
    "     keccak-256 : 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45\n" // the original padding
    "     sha512-256 : 53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23\n" // FIPS 180-4
    "          xxh32 : 32d153ff\n"                                                         // xxHash spec
    "          xxh64 : 44bc2cf5ad770999\n";
    // clang-format on

    int              r   = TEST_FAILED;
    char*            out = NULL;
    DummyFilebuffer* tfb =
        dummyfilebuffer_create((const u8_t*)abc, sizeof(abc) - 1);
    if (tfb == NULL)
        goto end;

    if (exec_commands_on("hh sha3-256 ; hh keccak-256 ; hh sha512-256 ; "
                         "hh xxh32 ; hh xxh64",
                         tfb) != 0)
        goto end;

    out = strbuilder_reset(sb);
    r   = compare_strings_ignoring_X(expected, out);

end:
    bhex_free(out);
    dummyfilebuffer_destroy(tfb);
    return r;
}

// Keccak is not SHA-3: the padding NIST changed on standardisation makes them
// different functions, and the whole point of carrying both is that a digest
// from one never passes for the other
int TEST(keccak_is_not_sha3)(void)
{
    int   r    = TEST_FAILED;
    char* out  = NULL;
    char* sha3 = NULL;

    if (exec_commands("hh sha3-256") != 0)
        goto end;
    sha3 = strbuilder_reset(sb);

    if (exec_commands("hh keccak-256") != 0)
        goto end;
    out = strbuilder_reset(sb);

    // same length, different value
    r = (strlen(sha3) == strlen(out) && strcmp(sha3, out) != 0) ? TEST_SUCCEEDED
                                                                : TEST_FAILED;

end:
    bhex_free(out);
    bhex_free(sha3);
    return r;
}

int TEST(notkitty_only_md_family)(void)
{
    // clang-format off
    const char* expected =
    "            md2 : 39a678d255754109e1be9259b980115f\n"
    "            md4 : b2cdd438a0405b70b2ada17b21316675\n"
    "            md5 : 29aedda82de8f860e085d0a3fa7b8b7b\n"
    "        md6-128 : 715057975c14fdaa5b33df5a44716e14\n"
    "        md6-256 : 6735fc6b1103c7b372b79c581fb6b850b35eb57a122ba00e6c4bb2e42bc460a6\n"
    "        md6-384 : 2cd82629bdd6c6bf25870b9ecdb618aae0ed632ef812b4438b4f1781d3bed526233e1cc22b265b6e521522353fe328ae\n"
    "        md6-512 : a1a37d450f1502966bd921b407a074edebfc5f878f27b343d89ef4a328db6da1a6f126ccce0165e9b01309efa91a23e05b0881954db0da3f848326811b6cd042\n";
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

// A name is read at the narrowest tier that matches something: exact first,
// then prefix, then anywhere. Without the tiers "hh md" also ran RipeMD and
// "hh skein-512" also ran skein-512-256
int TEST(name_matching_tiers)(void)
{
    int   r   = TEST_FAILED;
    char* out = NULL;

    // exact: one algorithm, even though it is the start of another name
    if (exec_commands("hh skein-512") != 0)
        goto end;
    out = strbuilder_reset(sb);
    ASSERT(strstr(out, "skein-512 :") != NULL);
    ASSERT(strstr(out, "skein-512-256") == NULL);
    bhex_free(out);
    out = NULL;

    // prefix: the family, and nothing that merely contains the name
    if (exec_commands("hh md") != 0)
        goto end;
    out = strbuilder_reset(sb);
    ASSERT(strstr(out, "md5 :") != NULL);
    ASSERT(strstr(out, "RipeMD") == NULL);
    bhex_free(out);
    out = NULL;

    // anywhere: only once nothing matches at a narrower tier
    if (exec_commands("hh 512-256") != 0)
        goto end;
    out = strbuilder_reset(sb);
    ASSERT(strstr(out, "sha512-256 :") != NULL);
    ASSERT(strstr(out, "skein-512-256 :") != NULL);
    r = TEST_SUCCEEDED;

end:
    bhex_free(out);
    return r;

fail:
    r = TEST_FAILED;
    goto end;
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
    "        blake2b : e92b41dd767e71d505805bcb09c6fdb3f0954b37b06e9cd71eb09589a76d96436063c3cfd06b9ef5871124750b8d1bc515825828f97c619ecab807a4b4dd9cbf\n"
    "    blake2b-160 : 0ca0f270f7bb24ff3701c17de1bf5a3540d57f41\n"
    "    blake2b-256 : a0ff17711d7b5c50b84998e1d7c354a55ae91901ea48a24dbbb3d4c95af153d0\n"
    "    blake2b-384 : 4b84e1d7cb289fee27405b3a4e79046cd1a627205c869addcdf8ce1f75ccb7f4543db76a5c6e61becf59f7f84d2d4336\n"
    "        blake2s : bb7de2688fe7422836a025f3b3dbd7c4beed4b851e16ee98cbc550641a09b5f6\n"
    "    blake2s-128 : 62fd84a4d7aa7cdbd9cd1e93c73c62f0\n"
    "    blake2s-160 : eb52ab60f31af563c219774a8da14a73d352dd6d\n"
    "    blake2s-224 : aa5ae5142c777141abb519fe4e3d300c82d947137ab5e01b16de795c\n"
    "         blake3 : c66834cb4da1d8da1f6d7fc0cdb7f8643b1daf099801c3acbc198260c88a371a\n"
    "        fnv1-32 : 050c5d60\n"
    "        fnv1-64 : af63bd4c8601b7a0\n"
    "       fnv1a-32 : fa0c4bce\n"
    "       fnv1a-64 : af63f24c860211ee\n"
    "           gost : b5818ce86667c4f662b63b35228d69e3ea520f0ed6156c4670010af584b59086\n"
    "    groestl-224 : 5f9ad919c5c96f48d91c63f71287afba08a3ceb5f13dc041427e26f2\n"
    "    groestl-256 : 56c469307d0329bcf87c8259c8742d09cd1372d800dff5ecb174a4207c05d0b9\n"
    "    groestl-384 : bbd99ae5bc3fa61ce94814f00a02bb95d370c0bcbd4af35bd385ee781e8675eccc24191e7519e8c20cb75fc46b107cf9\n"
    "    groestl-512 : 96fe06fd0019f7264cbafe7baa7e38b6ffc93f75f1f35c2ef4f181224cb01bd4ba2034f0d6b9b701344639e11accf5f9b5b334871abac0c447d7abf349053bde\n"
    "    haval-128-3 : e78c7fc90ba51af3fe4dd13ed92912fb\n"
    "    haval-128-4 : f368bb4f672d70da20528c9c0fe3ba21\n"
    "    haval-128-5 : e822c7bf9d14f4752bc32294cb045e0a\n"
    "    haval-160-3 : fdada81938ea696e049f8d5f055b70f8df657780\n"
    "    haval-160-4 : 1b113941d07975edd28a1cf2260880b52b869274\n"
    "    haval-160-5 : 6fb053d5e512ba26c6447b69b462aac74a0b5fd0\n"
    "    haval-192-3 : dbe73369c3728b3318dd6e3391846e8e22f6e2af98be4219\n"
    "    haval-192-4 : eb774826efaac676bebc92261ef4cf674a60c804ca7707d6\n"
    "    haval-192-5 : a346ce8c3e5069a92b3e70aaa574e85c705ffb1bb3fc5582\n"
    "    haval-224-3 : cfa2ba02be5254affcd6bc88c79e12caeaeef05d4d9359d365b7fe9d\n"
    "    haval-224-4 : 1bbe99df4b34b66e9c979d9de7a3322b7137d71fc9cecc563b101482\n"
    "    haval-224-5 : 316965b67da840337350f6d901f71b7fc28cf6523208db350ffee992\n"
    "    haval-256-3 : 52fdb97f18e2427391ddeeca993ce388258dd77b10fbed1912c1db4c5865edd1\n"
    "    haval-256-4 : c2e2b160889136dfb9b76c2010dfeca83423df0b89850dfbfa632ae148516236\n"
    "    haval-256-5 : dd62dab91725b66fc264bed5ba7c4abeae67ebb2b786ae093d89fc17220c437d\n"
    "         jh-224 : 8cf330ffa364367c0b7744985a41ad391ef50971f7b1a9410f42981e\n"
    "         jh-256 : 5325cca2e14ffaa4d248ccfa41594390d3cf582b3e0681da3c44737f353b3388\n"
    "         jh-384 : 83a9d8e4fa625100f2e542bf73ae25e98495754296f2f337d10e3fe22d233ee86e70ebb8abd375f1bb14ffc431ca8453\n"
    "         jh-512 : 23cfaf778e94fcbb29d56d8d8fa19637ca83261b1c297694e9f14ba85083acd48af22214013df4f98946a644183b62d84fa5c023029e2963a26bf4a7c430a4ea\n"
    "     keccak-224 : 103e79f6d2390470c39cda2ee37b0ab86e31d4422d088f0965fded9b\n"
    "     keccak-256 : 5c179d3bfde4c521afc3d3944357db5ee881a69c237d67c9aa79aa7a027c40ea\n"
    "     keccak-384 : 42ab62494c57c7789ebfec9330a8fef25d7257808a640f03ce54d47f843e155eafd2cc79d633380f13ca69d726a6ff5a\n"
    "     keccak-512 : 2e957873dabc7b900d091f4f238e6d8aa87e77804e6be03a9e72e150e600c4a48ae9c703a038433e9b237a0dd79696150f5ed72b0aca933617009e5eee5cacbe\n"
    "            md2 : a90201383bcc37675c363e2a6549d0b6\n"
    "            md4 : 6a0e86dd59f27acf0dbaf3c2942d5783\n"
    "            md5 : 83acb6e67e50e31db6ed341dd2de1595\n"
    "        md6-128 : f380e3356f690c536e3d81d8b080a16c\n"
    "        md6-256 : 5e3a11d8d5d3540278d57aa4a366e28d1310f3740d419f01572c302a613d738c\n"
    "        md6-384 : 6f83e9846f5b6424aef4b9837601c691990ac0dbbcc33ed01c9db2bb3369835420db2278b24b5130f86e952b71483c9d\n"
    "        md6-512 : 8fe808ac8cb830f655296f0a9788832606f9e43e0226492bbf100963bdcef1ffca820c1183775fadc3645a772108322bda0c030a6a6ca84cafda5604037fab59\n"
    "    murmur3-128 : 46659e2ec0f3c75bf39e43a41adb5d4f\n"
    "     murmur3-32 : 5589d599\n"
    "     RipeMD-128 : 3ef49aa6285775057773a8ae8ef478ce\n"
    "     RipeMD-160 : c8297aad716979548921b2e8e26ca8f20061dbef\n"
    "     RipeMD-256 : d9143a5a5eb6508434090cff7e8037aa9a198feb5adf4854620e3d15cdd3f490\n"
    "     RipeMD-320 : 18f1c6d1e1ff4c73efaf112dec5d798fb6c057b8c58992ceb0a7589dfe98abe86f25cac1bb514e2f\n"
    "           sha1 : 23833462f55515a900e016db2eb943fb474c19f6\n"
    "         sha224 : a9ab1c5b26ddfea1cf0cc71c44363662af955b7bbf076d70af3ff9c2\n"
    "         sha256 : 620bfdaa346b088fb49998d92f19a7eaf6bfc2fb0aee015753966da1028cb731\n"
    "       sha3-128 : f2f1a7e794999f0d447a96ca5c351e6f\n"
    "       sha3-224 : 6f733daaa9696d60dd5c543b365a9ce953ea3ae5ef71a9c6040eca63\n"
    "       sha3-256 : aac68691d102829ac973f5b44c26165aa4e29cd498aff642a08944645d6ca5bd\n"
    "       sha3-384 : c6d45f444a995d9aee6f989b3cce12f3a94fa58c4a49218ad3f0405f9be1df2a848c008684b9d9e5f342d27978624846\n"
    "       sha3-512 : 5d6289e2eb89d4099552ad261115d31e1cfddf67f4997f19bd95d2436427deba817b9d4d3d107656283c602c19fa77f8c985b2a5e33d61cd0d56f3c1d61e93ea\n"
    "         sha384 : 23a8a9d42d150a471e8502ee2f4e822cb955e798882d698c5bd5aa01e43137cb566fefb1b06dced14b43c2e49758569d\n"
    "         sha512 : 75eb69a43e3bbcff322ec624ae7511cf3ad99df84b90d48b2665c70dff548c4857d4446c1eb04535bf54daa96e2cf5c3d5203d1fb43bbf4d40301bab95ac7772\n"
    "     sha512-224 : 9c9bc292d863f051a703abe5f07761a1c053d4b47ef42b8f81312e6f\n"
    "     sha512-256 : ae8e85dd4bd1cdb3be695f519ceb467248c6a4b1903b98130643b4992318a319\n"
    "   shake128-256 : da884b45ad5a2dce0cb81ffd8915e25f0e86fd956675045e3416afbe53449e17\n"
    "   shake256-512 : 5cf5c573d22f134a95b81858a20acbc5394c88ffcd9b6f68444d4cad64fd91727a69b03703601a58aa2b26c4efc421f30c76e7f1ba8cd63a1a97a6d4d3d60c3e\n"
    "     skein-1024 : f735d0c1875ab0cc26ca09d11f88ef85977768c6e11b68d51a05b5989995f34eca18b0e8fa83c95d9bbdab563f20dc6bfbd70ada1de331e486d36afccac840a45f16d985d8aa092e89461dc76f68ad0565d56bd9829fa33bdfd796df7a5dae904f47a74ac7c67805a6228991f7b6f4275466009b3257c95ac9d22ec4cff95d77\n"
    "      skein-256 : fb19884fe92105f1e4c9ec2a9200449bbfee5e64fd2f0326e72dfc5ef5e8eb94\n"
    "      skein-512 : fbdeba512f7cbfcb001ea767a142fad4a9679d899de97794bd259443cd34f0204cdf3c01ba657a518bc05ae39700154a7488766b02898d4386b17b5ac09e0734\n"
    "  skein-512-256 : 31a51b0181966db753207667feb753269c34b68f47f799889eb2d96cd7dceddd\n"
    "            sm3 : 005b4e9445a688705515a094c36e43b6ce6e441382f863b28ff7b45c9842093c\n"
    "     snefru-128 : 10c620c639d64e3bc344018ad733e518\n"
    "     snefru-256 : 1a9418857290b8d1b6236da9debd629b0a26ef5909da567ec038d84503bc31cc\n"
    "   spectral-256 : 277b289836fdc825b4060dd23b17d61f98754b4a8c38e3027e0fac8766b600e0\n"
    "   spectral-512 : 167b47a13e8a958c137ecfdfa118b97af50a259e0b6d748ae2d255e366d60bf51b18dea4b99770acb0dc179cea3734205bfc38e196c2ac6956629dc40404de1c\n"
    "   streebog-256 : 792f887671904928d2c4a748eb16551c3bf9f851bbd528a0eef41698439d1db9\n"
    "   streebog-512 : 4a536ea04ed5ff666884ad5a5af1e855f8a66efa1df76ad387749e11405916a76cb0bced42f430c450ace82ce1fcc3b1f905146413519e2d8dd325dc83fa56e7\n"
    "          tiger : debf58dbd60c818b2151176f8223c2f5bccf57861870675d\n"
    "         tiger2 : ed0eaa6a8af698084708f561dc9f8e2481514f48966ff5d1\n"
    "      whirlpool : 88bf39ce7a2c404a9e07967c238c4c1fb7aa721b60c31bc2dbd0958bb6d019cd3c5c1c7ec267e3e51792b9379cf55cc781f3b8fa0af530d07a37e291815a9923\n"
    "       xxh3-128 : 239010a41856cead2a140471f45ff181\n"
    "        xxh3-64 : 2a140471f45ff181\n"
    "          xxh32 : d13ceeff\n"
    "          xxh64 : 49d1c4f1c492ef50\n";
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
    "           sha1 : afcb97e87528305aa7bb20c6969d073175d3aecb\n";
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
    "           sha1 : 05fe405753166f125559e7c9ac558654f107c7e9\n";
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
    "           sha1 : da39a3ee5e6b4b0d3255bfef95601890afd80709\n";
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
