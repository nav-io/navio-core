# Copyright (c) 2024-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

add_executable(bench_navio
  bench_bitcoin.cpp
  bench.cpp
  nanobench.cpp
  addrman.cpp
  base58.cpp
  bech32.cpp
  bech32_mod.cpp
  bip324_ecdh.cpp
  block_assemble.cpp
  ccoins_caching.cpp
  chacha20.cpp
  checkblock.cpp
  checkqueue.cpp
  coin_selection.cpp
  crypto_hash.cpp
  data.cpp
  descriptors.cpp
  disconnected_transactions.cpp
  duplicate_inputs.cpp
  ellswift.cpp
  examples.cpp
  gcs_filter.cpp
  hashpadding.cpp
  load_external.cpp
  lockedpool.cpp
  logging.cpp
  mempool_eviction.cpp
  mempool_stress.cpp
  merkle_root.cpp
  peer_eviction.cpp
  poly1305.cpp
  pool.cpp
  prevector.cpp
  readblock.cpp
  rollingbloom.cpp
  rpc_blockchain.cpp
  rpc_mempool.cpp
  streams_findbyte.cpp
  strencodings.cpp
  util_time.cpp
  verify_script.cpp
  xor.cpp
)

target_link_libraries(bench_navio
  core_interface
  test_util
  navio_node
  bls_interface
  Boost::headers
)

if(ENABLE_WALLET)
  target_sources(bench_navio
    PRIVATE
      wallet_balance.cpp
      wallet_create.cpp
      wallet_create_tx.cpp
      wallet_loading.cpp
  )
  target_link_libraries(bench_navio navio_wallet)
endif()

include(InstallBinaryComponent)
install_binary_component(bench_navio INTERNAL)
