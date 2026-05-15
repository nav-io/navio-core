# Copyright (c) 2024-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

target_sources(test_navio
  PRIVATE
    init_test_fixture.cpp
    wallet_test_fixture.cpp
    coinselector_tests.cpp
    db_tests.cpp
    feebumper_tests.cpp
    group_outputs_tests.cpp
    init_tests.cpp
    ismine_tests.cpp
    rpc_util_tests.cpp
    scriptpubkeyman_tests.cpp
    spend_tests.cpp
    wallet_crypto_tests.cpp
    walletdb_tests.cpp
    walletload_tests.cpp
    wallet_tests.cpp
    wallet_transaction_tests.cpp
)
