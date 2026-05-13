# Copyright (c) 2024-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

add_library(navio_wallet STATIC EXCLUDE_FROM_ALL
  coincontrol.cpp
  coinselection.cpp
  context.cpp
  crypter.cpp
  db.cpp
  dump.cpp
  external_signer_scriptpubkeyman.cpp
  feebumper.cpp
  fees.cpp
  interfaces.cpp
  load.cpp
  receive.cpp
  rpc/addresses.cpp
  rpc/backup.cpp
  rpc/coins.cpp
  rpc/encrypt.cpp
  rpc/signmessage.cpp
  rpc/spend.cpp
  rpc/transactions.cpp
  rpc/util.cpp
  rpc/wallet.cpp
  scriptpubkeyman.cpp
  spend.cpp
  sqlite.cpp
  transaction.cpp
  wallet.cpp
  walletdb.cpp
  walletutil.cpp
  # mnemonic (BIP39) sources
  ../mnemonic/mnemonic.cpp
  ../mnemonic/wordlist.cpp
)
target_link_libraries(navio_wallet
  PRIVATE
    core_interface
    navio_common
    navio_blsct_core
    navio_blsct_wallet
    SQLite3::SQLite3
    univalue
    bls_interface
    Boost::headers
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
)
