# Copyright (c) 2024-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

include(TargetDataSources)

# Mirror the autotools hexdump rule (src/Makefile.am:1601) that generates
# a C array header from a raw binary.
# Use the old unsigned-char array format because addrman_tests.cpp uses
# sizeof(asmap_raw) which requires a plain C array, not std::span.
set(ASMAP_RAW_H "${CMAKE_CURRENT_BINARY_DIR}/data/asmap.raw.h")
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/data")
add_custom_command(
  OUTPUT "${ASMAP_RAW_H}"
  COMMAND ${Python3_EXECUTABLE} -c
    "import sys; d=open(sys.argv[1],'rb').read(); f=open(sys.argv[2],'w'); f.write('static unsigned const char asmap_raw[] = {\\n'); [f.write(', '.join('0x{:02x}'.format(b) for b in d[i:i+8])+',\\n') for i in range(0,len(d),8)]; f.write('};\\n')"
    "${CMAKE_CURRENT_SOURCE_DIR}/data/asmap.raw"
    "${ASMAP_RAW_H}"
  DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/data/asmap.raw"
  COMMENT "Generating asmap.raw.h"
  VERBATIM
)

add_executable(test_navio
  main.cpp
  addrman_tests.cpp
  allocator_tests.cpp
  amount_tests.cpp
  argsman_tests.cpp
  arith_uint256_tests.cpp
  banman_tests.cpp
  base32_tests.cpp
  base58_tests.cpp
  base64_tests.cpp
  bech32_tests.cpp
  bip324_tests.cpp
  bip32_tests.cpp
  blockchain_tests.cpp
  blockencodings_tests.cpp
  blockfilter_index_tests.cpp
  blockfilter_tests.cpp
  blockmanager_tests.cpp
  bloom_tests.cpp
  blsct_signature_checker_tests.cpp
  blsct/arith/elements_tests.cpp
  blsct/arith/mcl/mcl_g1point_tests.cpp
  blsct/arith/mcl/mcl_integration_tests.cpp
  blsct/arith/mcl/mcl_scalar_tests.cpp
  blsct/bech32_mod_tests.cpp
  blsct/building_block/generator_deriver_tests.cpp
  blsct/building_block/imp_inner_prod_arg_tests.cpp
  blsct/building_block/lazy_points_tests.cpp
  blsct/common_tests.cpp
  blsct/eip_2333/bls12_381_keygen_tests.cpp
  blsct/external_api/external_api_tests.cpp
  blsct/keys_tests.cpp
  blsct/pos/pops_hardening_tests.cpp
  blsct/pos/pos_chain_tests.cpp
  blsct/pos/pos_consensus_tests.cpp
  blsct/range_proof/bulletproofs/bulletproofs_range_proof_logic_tests.cpp
  blsct/range_proof/bulletproofs/bulletproofs_range_proof_tests.cpp
  blsct/range_proof/bulletproofs/bulletproofs_range_proof_with_transcript_tests.cpp
  blsct/range_proof/bulletproofs_plus/bulletproofs_plus_range_proof_logic_tests.cpp
  blsct/range_proof/bulletproofs_plus/bulletproofs_plus_range_proof_tests.cpp
  blsct/range_proof/generators_tests.cpp
  blsct/range_proof/range_proof_common_tests.cpp
  blsct/set_mem_proof/set_mem_proof_prover_tests.cpp
  blsct/set_mem_proof/set_mem_proof_setup_tests.cpp
  blsct/set_mem_proof/set_mem_proof_tests.cpp
  blsct/signature_tests.cpp
  blsct/tokens/info_tests.cpp
  blsct/tokens/predicate_exec_tests.cpp
  blsct/sign_verify_tests.cpp
  blsct/wallet/address_tests.cpp
  blsct/wallet/chain_tests.cpp
  blsct/wallet/delegation_tests.cpp
  blsct/wallet/keyman_tests.cpp
  blsct/wallet/output_storage_tests.cpp
  blsct/wallet/txfactory_global_tests.cpp
  blsct/wallet/txfactory_tests.cpp
  blsct/wallet/validation_tests.cpp
  bswap_tests.cpp
  checkqueue_tests.cpp
  coins_tests.cpp
  coinstatsindex_tests.cpp
  compilerbug_tests.cpp
  compress_tests.cpp
  crypto_tests.cpp
  cuckoocache_tests.cpp
  dbwrapper_tests.cpp
  denialofservice_tests.cpp
  descriptor_tests.cpp
  disconnected_transactions.cpp
  flatfile_tests.cpp
  fs_tests.cpp
  getarg_tests.cpp
  hash_tests.cpp
  interfaces_tests.cpp
  key_io_tests.cpp
  key_tests.cpp
  logging_tests.cpp
  mempool_tests.cpp
  merkle_tests.cpp
  merkleblock_tests.cpp
  miner_tests.cpp
  miniscript_tests.cpp
  minisketch_tests.cpp
  mock_process.cpp
  multisig_tests.cpp
  net_tests.cpp
  netbase_tests.cpp
  pmt_tests.cpp
  policyestimator_tests.cpp
  random_tests.cpp
  rbf_tests.cpp
  rest_tests.cpp
  result_tests.cpp
  reverselock_tests.cpp
  rpc_tests.cpp
  sanity_tests.cpp
  scheduler_tests.cpp
  scriptnum_tests.cpp
  script_p2sh_tests.cpp
  script_parse_tests.cpp
  script_segwit_tests.cpp
  script_standard_tests.cpp
  script_tests.cpp
  serfloat_tests.cpp
  serialize_tests.cpp
  settings_tests.cpp
  sighash_tests.cpp
  sigopcount_tests.cpp
  skiplist_tests.cpp
  sock_tests.cpp
  span_tests.cpp
  streams_tests.cpp
  sync_tests.cpp
  system_tests.cpp
  timedata_tests.cpp
  torcontrol_tests.cpp
  transaction_tests.cpp
  translation_tests.cpp
  txindex_tests.cpp
  txpackage_tests.cpp
  txreconciliation_tests.cpp
  txrequest_tests.cpp
  txvalidationcache_tests.cpp
  txvalidation_tests.cpp
  uint256_tests.cpp
  util_tests.cpp
  util_threadnames_tests.cpp
  validation_block_tests.cpp
  validation_chainstatemanager_tests.cpp
  validation_chainstate_tests.cpp
  validation_flush_tests.cpp
  validationinterface_tests.cpp
  validation_tests.cpp
  versionbits_tests.cpp
  xoroshiro128plusplus_tests.cpp
)

target_sources(test_navio PRIVATE "${ASMAP_RAW_H}")

target_json_data_sources(test_navio
  data/base58_encode_decode.json
  data/bip341_wallet_vectors.json
  data/blockfilters.json
  data/key_io_invalid.json
  data/key_io_valid.json
  data/script_tests.json
  data/sighash.json
  data/tx_invalid.json
  data/tx_valid.json
)

target_link_libraries(test_navio
  core_interface
  test_util
  navio_cli
  navio_node
  navio_consensus
  # navio_blsct_core/wallet are pulled in transitively via navio_node ->
  # navio_common -> navio_blsct_core (all PRIVATE), but MSVC's static
  # link order doesn't pull in symbols from libs sandwiched in
  # PRIVATE-chain dependencies. List them explicitly so test_navio's
  # bls12_381_keygen_tests / bulletproofs_plus / set_mem_proof_prover
  # tests can resolve BLS12_381_KeyGen::HKDF_Extract, RangeProofLogic
  # template instantiations, etc. on Win64-native (LNK2019).
  navio_blsct_core
  $<$<BOOL:${ENABLE_WALLET}>:navio_blsct_wallet>
  minisketch
  secp256k1
  bls_interface
  Boost::headers
  libevent::extra
  $<TARGET_NAME_IF_EXISTS:USDT::headers>
)

if(ENABLE_WALLET)
  add_subdirectory(${PROJECT_SOURCE_DIR}/src/wallet/test wallet)
  target_link_libraries(test_navio navio_wallet)
endif()

function(add_boost_test source_file)
  if(NOT EXISTS ${source_file})
    return()
  endif()

  file(READ "${source_file}" source_file_content)
  string(REGEX
    MATCHALL "(BOOST_FIXTURE_TEST_SUITE|BOOST_AUTO_TEST_SUITE)\\(([A-Za-z0-9_]+)"
    test_suite_macro "${source_file_content}"
  )
  list(TRANSFORM test_suite_macro
    REPLACE "(BOOST_FIXTURE_TEST_SUITE|BOOST_AUTO_TEST_SUITE)\\(" ""
  )
  # The mock_process test suite does not contain unit tests. It is a helper
  # process invoked by system_tests via --run_test=mock_process/<case>.
  list(REMOVE_ITEM test_suite_macro "mock_process")
  foreach(test_suite_name IN LISTS test_suite_macro)
    add_test(NAME ${test_suite_name}
      COMMAND test_navio --run_test=${test_suite_name} --catch_system_error=no --log_level=test_suite -- -printtoconsole=1
    )
    set_property(TEST ${test_suite_name} PROPERTY
      SKIP_REGULAR_EXPRESSION
        "no test cases matching filter"
        "skipping script_assets_test"
    )
  endforeach()
endfunction()

function(add_all_test_targets)
  get_target_property(test_source_dir test_navio SOURCE_DIR)
  get_target_property(test_sources test_navio SOURCES)
  foreach(test_source ${test_sources})
    cmake_path(IS_RELATIVE test_source result)
    if(result)
      cmake_path(APPEND test_source_dir ${test_source} OUTPUT_VARIABLE test_source)
    endif()
    add_boost_test(${test_source})
  endforeach()
endfunction()

add_all_test_targets()
