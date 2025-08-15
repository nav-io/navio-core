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
    // in case there is a structural change in CMutableTransaction,
    // tx_hex needs to be regenerated to reflect the structure change
    std::string tx_hex = "200000000100000000000000000000000000000000000000000000000000000000000000000503615d0200ffffffff02ffffffffffffff7f0100000000000000015101855f4e35c5fbe93bf5b8a7a2dc55420144388fd0736ce7d9c8289e793da409d89f2bf2f4f4ac9364d81922d9255c33880683ed1c387aa2555b28af1c6d2b4a2725af9551263c00962daeec3736de0724167d18579973ff9cfcaeedc9ed59036aaaa2ad79cef575dc618d14729169a88c87edb5d3303efab1109572ca4a98800d61c45d8ca9074a7beb9c5c4123e7af8054b4bce1a360c663b86e8af1f06dea120fce8d7529b90ff383fd69c7dd9a50215881df91544949b95eaeac780c133699bdb030b321c32c0efbafa29fe840fe93b01bffc47e096a4577f5ba7d6745506f5e658cbd21c0c7f4c5fc28fdb28dd1c27a8027da5ca650a48ced1c52725abc54a1bd54e9823341753de270ea7882fd54b5b7513d9184635b9dbf0812ccf769df4cb50985bfa52fa515fa7034a317b2da1453d2d919797a22e6889c8aada6fe25e2dfda8f57f57de8fc2a9fa957d264240d06b8548ad7eec8b644df2e89b9a5a1d83ecce4ca94005b7d61782743e74ed011f7cc96c634327b67cfbc954de4effa0d7884f88d27ac1c1686bad02f527975ed9f3e7b2570120dc68ad88ddd350119d00c6df24916d5fc361f20f4f4d4482711b5850b3f91c9315beb1af544d63ed7049b6a1af783e0171526ba9c31466de735527d2d1bfeaf292a73ecf0312e6e784ae18dc6949e4a452fadc0734bff7bdf56074434f7a311290ba2ec6cbe960e29829d2b8ad6fb7946e356580b5a40f9676274a8336c5eecc36a9ddb58bb81cd8d08dfda7714aa9634941a94076cbc3ed74561d9043146dc81f1ccafd4e06f98faae3da017fe07af9ac407d0b81e6e1e634e5b53f5f98728850298673e355093844d0443466fad33d233ed7c40c1788a43d4d48d63778e8cf80e9cd5d01e789637b0cae99a372dd0bc8b5dbf2bc2df9fea229d71eaebab6a9277bb3bb3ba07c14edef6a7fcdcf02e8c1e927872003b9683d3b3ff1e740d5ec8a8145361166b33da8dcda6edf5d7bf32f63d27a5b72e515e6641b672275eee06f3bd5abd6790eded07d49b9e55e5c29e136eb5ad4857f9f55b6e7be10d2002ed91244243ea0fe7b6dea43ea70eb0d3d438ae2a335ced8e1620392562a2c503d2c4b53bed0d39c3749cb032741cacd0ca73bc6d72d350184cc82a45ad8df2e3443599ba51dfd5dce328362f9032cb350f579234f36c282d4b0acdf27d6a8d66f62713adf6481c8c9f240f59a15c6e064a5c05b56e6c068801f639ee1e83003a6a8dd97d5c24b5236c30d43efa0d75709fcaba4ca72077232f537900b2697973d2a08ee405d4298d4a8afeb24f6066b9648b3265e10931756678606fc173b92525567648af5408ff6af65eece8bbe70c671f9f8b94f012dd97eb3f8efcbeae6b34fc2fa3932ffac63b68c7167eeea1b7798872c92e40c057663cd1bdd07ce887a175b0feb74c394f9232dbaf3c8bd84e5624c2b6ca3605cfe3a1acfd1c5871a54d5a5b497588916840d422eeabc75d528275e0f7db46d95654ec9453c20000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9000000008a8c3b2f2bafb7b71f9192b2b8e02df5caf27c04b535ef577c0703f820a110155984f294bc01fccaf6957b622156a97712e57526ce7ef914af67e7aea2fd3daf8a4176660300ea64be6ab6c87b1a597cb96f7d5ac0ab59fe115190bc33946ba3";

    DataStream st{ParseHex(tx_hex)};
    TransactionSerParams params { .allow_witness = true };
    ParamsStream ps {params, st};

    CMutableTransaction tx;

    try {
        tx.Unserialize(ps); // should not throw an exception
    } catch(...) {
        BOOST_CHECK(false);
    }
}

BOOST_AUTO_TEST_SUITE_END()

