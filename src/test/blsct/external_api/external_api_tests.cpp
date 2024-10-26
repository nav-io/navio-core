// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/strencodings.h>
#include <blsct/wallet/txfactory.h>
#include <blsct/wallet/verification.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <txdb.h>
#include <wallet/receive.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>
#include <iostream>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(external_api_tests, BasicTestingSetup)

uint8_t hex_to_uint(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    } else {
        throw std::invalid_argument("Unexpected hex char found");
    }
}

// This test checks if there is any structural change in
// CMutableTransaction and its dependencies
BOOST_AUTO_TEST_CASE(test_cmutable_transaction_sizes)
{
    /*
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 23, .memory_only = true}, {}};

    auto wallet = std::make_unique<wallet::CWallet>(m_node.chain.get(), "", wallet::CreateMockableWalletDatabase());
    wallet->InitWalletFlags(wallet::WALLET_FLAG_BLSCT);

    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    const auto txid = Txid::FromUint256(uint256::ONE);
    COutPoint outpoint{txid, 0};

    Coin coin;
    auto out = blsct::CreateOutput(recvAddress, 1000 * COIN, "test");
    coin.nHeight = 1;
    coin.out = out.out;

    auto txf_tx = blsct::TxFactory(blsct_km);

    {
        CCoinsViewCache coins_view_cache{&base, true};
        coins_view_cache.SetBestBlock(uint256::ONE);
        coins_view_cache.AddCoin(outpoint, std::move(coin), true);
        BOOST_CHECK(coins_view_cache.Flush());
    }

    CCoinsViewCache coins_view_cache{&base, true};
    BOOST_CHECK(txf_tx.AddInput(coins_view_cache, outpoint));

    txf_tx.AddOutput(recvAddress, 900 * COIN, "test");

    auto tx = txf_tx.BuildTx();

    DataStream st{};
    TransactionSerParams params { .allow_witness = true };
    ParamsStream ps {params, st};
    tx->Serialize(ps);
    auto hex = HexStr(st);
    std::cout << hex << std::endl;
    */

    // in case there is a structural change in CMutableTransaction,
    // regenerate tx_hex with the commented-out code above
    std::string tx_hex = "220000000101000000000000000000000000000000000000000000000000000000000000000000000000ffffffff03ffffffffffffff7f010000000000000001510190de49f3c13fa8a012d7faf19a6be7ec7ef001fa450987a21a817f5b0b1fcb2183375e240429f43fd8c4ef86042a1e3c06808194ecf1d168e898aeb4a9d97c88c9f0ef9b786ec98f39b6f98f01b89c40e1b02f1f52a6a1dfd94a700523b629ea09b3b16d53caab0a5f952ecb03caa6031bedde1ddbaaba3ff25408010029a387fa824547093f8a475bb5c4838ae7e72e80b3c12f52568de311cbbe64abf318ed3e18de98b14db957e4f8ca77515339febd3b4eb637d154eddbb8c54efe6bb653b491fa0535a0ed277b7ff38d50f76e55e60ce1cdf4929455c50677cb9891216b06cd1bff58066fe7b2052d9d5b6aca088bb5e545b6ce4ff4a2a340cf2cc261331584de326c1ca8f678f88004f62b7d78449b13bcf29d0eed57610396e0de20dcf6a414de58b97a23d13b3f0e22782a0860ffb7290e18676e9b451a14a9ea98fbbaa7ba035fd169637250b443b13332473506ac9598352c3cbd70ec756f9d473047555df7560372ec66a1e7b4a5a5983f0f35fff0d5626e2ed9294e591aa8ba641cf2ab315680c96842a6816776228d977013bed24085d9901e018a9d0c40b3ad92d8306b6eace181342a5e047c0e368892158c6c38c7cfb32c014b05d7441ab40a4db2ee8ae8c0f76cc7bb4974d3ae8775debae7a1e00fe93d4bf48bfaed052a1287ae006c4a02138ade80a095765d53205573b7425a8fd28b229c8d9c066e90dc50cbb3672f917f557cb8f99fa435796ac098d617ce387cd50c131cf62c3c40ac6a01284ee824ba5a5cc72a5a1f50176cde96678baad1cd3fdc2826d196b2c2ff00ad6575ab7f42e1b45a27fcf6a3cfce7cb21fd616709efacc90ca8d2f0f1d43a6f05cfb88a2dbc879d2ae524d75ce4d12942fa9c778124df131e096a6e65430915613c3713d2ee95936f68013b42f2f3c2416d2094fbd58ae755ee1b85a632fd4853f308e4d4972d30739cce32d8b8962bd6f43f3c20f9e39347bc00f4cabeaa658114145b57c5f65efb3ac59b101a9bfb074c7908df4002a07386c10dcc94b7c274fce51d83ac76da715df1218c60b1b840761382b13528b573fe2ca87fde505b1835738390b644d1acfcb0e4f9b1c16fbe085f638d697a05d29888fa33cde007d75195ca96da004788dd1369d0a46413252d691f1a8f40f0c10db8b12f4ef2c7378ecc376d029e1f7acb42b64f5d1175fc9db80394eae6131635955e8b3363d0163d984edcb774b9548bb1fad05a1b5470795bf8b333089ee8361991695b45652b31044b6f1a3bfad8d2a1342d658a70293b97638a9dfeddfafa0a980b869872ac01de1a0b80675c7a5296862c630a8636cd29af02b82e9465dafb405211f97c85ec76e9009ec080d47e26b701aca978bb1864632e06f4c462726b7b73da4f0cd49bc5ab4d9a0d3788688c1ef1e79a404d64c8e282fe8e1f1303ea443b021ccab4cbfced6aa3f575178e651cd48acaf045cea22288893dac50499d80c6bf3cf954c1a79c52cad8be5c30b9701ee62d1acffe1dda5a7c45b89c3d933bc84d66adb1732a5c4b5a85faa44c93c080980345430be78b3bfd155d05da1ffc4f296515015ffffffffffffff7f0100000000000000015101873f9c1cef19d74c20ca6f27cbded9113506f91eaf3ec5f2462a5e2bcb3c0323c4e2608048932f0c91ffa9b6c4b889f506a20b25057ee37536fa465e9bf4b9e2dc2e998df423d7ad4957afe2a6e1003fd60444ba76bb73bcc2acc980e191328b0191a1c67a9fa3684b538d972a4e504f87beb4447e36c5c1ec70535462abf529425e365fac2448add9bb858afbb8c0351ca40f9afff677f9bdb6c1a645f554501b98f7377a79831eb944456be128fb4cab0c9731c910fa9ac795b4edaa56f80354b8040c0ecc42bbc4f9714bd2f0610bbdf9610eed33fe817375cf9aed86b6b7fd6ef375bbfbed567560157718fb03157ea38ee28c5f2902982dddfbe0db2dce848c68b3b5d6181e86a6ca111957e0e9222a22702665c757d55cc87bd69b7eb9c7818c49d1d47bfbbf210b8e44216f828a2f4193186053dfe422183df548a4ef6dbe5b86e73f77b45ea5df243b49fc9ae006ad52ae4849763ec182d0a357126493e7304fcaae4509ec2da11e2693b75c9fcacdcaa1b6d44352b5ba30ac018e817a9fb2351ae9cfc9f11e35c7f64329b991f8b99ec48b8f0045f3496603d728a4f33fa773fe98f728945bef8ba7bdde41110bb14cd4dfe5a58e0840e5595ad134be8d35de5fa988b675957200f018d7304ef7626486060d4be741a28e1f6464cf997c96ecfa7eaacaa2a4a94ada3eaeda8519b1beb7a9da5ae3a5072d76f1de388097e0011aefc2530562aa74c5d9ea3b6780845442286534513503d58f692d33a864b608b9e7f15cfdf66abab1b860818800493b92e187bfa82ed2a8e8f74b25e827b769f91143a5117a82dbd975b44975541b2c97d02e0401edff6b061f77ba53533a646674bb328a27bcd2eb65e739a765a2e3bad16094ae87f4e0ffeb7b4720edc7fa90247c12ffcccc539a87e787d87bfa2c01405f3cdbcbb843b60f6797e1f787e948ea251d662b58d3b8bd78b29df1e2f262b4f06893dcd739d20d6290f86dc19ce0800c2ca685d402f9377872d8b88de6c5e24842beb91d7bae549cd7273c55b1bf14a01c04a0825e81383b12a74e81e0a79fa10a8d70ad1aa928f7addf02ad0cca82c2df283530ef31bb623cf102fca444034c6e84cbc04a0ba75a15ff1f51cee6fbf7180bb85f61876600d3ed9a583d97018dd81aefc47a18ed8999362db8b48773fcc46924d7fab1a0893bc919674dc09dca7db6eafe4bf97c755f9015ee48fccf3d1dd5789cb99289c102b145308bfceea30990cf85bb9ee1a6587dd8a25f34bc20b136e89603469878d7ef122d82020d99a8d0d67ae6a199b5cc740262204136df29e00d92a2a94c67795ab663a3ad5aea4b923607088343f649f09de0a73deea66d19a42f4f35dbf03d536e8229062b3a4fb7a07225a32f6d4c5d4a139c978f337215da105fb085419352d20c23dc33aea84671c03ac2bbfc725271b81f75f8b326069fc264c798a10d32c21982990724fc46cdf0c25502351e0b908582a57e045b5be8628e8f87d6a1ede5a0a0d551b3896809b25345108f55f7ba74c225c65006692d67485d4cc5ee81eb2e1af8643dfb43d9a628d117edcbfa827404fda3040000000000016a00000000a61c9bbb11507a1c71fde1028f08e150e4f7efc69b69ff45f6e0afdfee105e85d2b9006e394dde9d648627d21934cfe0161be58bb288ff9c6e1d3d1285034b8d4106a5b653ea38d3cc672ab4eb943642f567819813169db474eff1f539ed494e";

    DataStream st{};
    TransactionSerParams params { .allow_witness = true };
    ParamsStream ps {params, st};

    for (size_t i = 0; i < tx_hex.length(); i += 2) {
        auto high = hex_to_uint(tx_hex[i]);
        auto low = hex_to_uint(tx_hex[i + 1]);
        ps << ((high << 4) | low);
    }

    CMutableTransaction tx;
    try {
        tx.Unserialize(ps); // should not throw an exception
    } catch(...) {
        BOOST_CHECK(false);
    }
}

BOOST_AUTO_TEST_SUITE_END()

