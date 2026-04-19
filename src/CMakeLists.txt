# Copyright (c) 2024-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

include(AddWindowsResources)

configure_file(${PROJECT_SOURCE_DIR}/cmake/navio-build-config.h.in config/bitcoin-config.h USE_SOURCE_PERMISSIONS @ONLY)
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

#=============================
# Subprojects
#=============================
include(../cmake/crc32c.cmake)
include(../cmake/leveldb.cmake)
include(../cmake/minisketch.cmake)
add_subdirectory(univalue)
include(../cmake/secp256k1.cmake)
add_secp256k1(secp256k1)
include(../cmake/bls.cmake)

# Set top-level target output locations.
if(NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
endif()
if(NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
endif()
if(NOT CMAKE_ARCHIVE_OUTPUT_DIRECTORY)
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
endif()

add_custom_target(generate_build_info
  BYPRODUCTS ${PROJECT_BINARY_DIR}/src/navio-build-info.h
  COMMAND ${CMAKE_COMMAND}
    -DBUILD_INFO_HEADER_PATH=${PROJECT_BINARY_DIR}/src/navio-build-info.h
    -DSOURCE_DIR=${PROJECT_SOURCE_DIR}
    -P ${PROJECT_SOURCE_DIR}/cmake/script/GenerateBuildInfo.cmake
  COMMENT "Generating navio-build-info.h"
  VERBATIM
)
add_library(navio_clientversion STATIC
  clientversion.cpp
)
target_link_libraries(navio_clientversion
  PRIVATE
    core_interface
)
add_dependencies(navio_clientversion generate_build_info)

add_subdirectory(crypto)
add_subdirectory(util)

# blsct sources shared across multiple libraries
set(BLSCT_SOURCES
  blsct/arith/elements.cpp
  blsct/arith/mcl/mcl_g1point.cpp
  blsct/arith/mcl/mcl_scalar.cpp
  blsct/bech32_mod.cpp
  blsct/building_block/g_h_gi_hi_zero_verifier.cpp
  blsct/building_block/generator_deriver.cpp
  blsct/building_block/imp_inner_prod_arg.cpp
  blsct/building_block/lazy_point.cpp
  blsct/building_block/lazy_points.cpp
  blsct/building_block/weighted_inner_prod_arg.cpp
  blsct/chain.cpp
  blsct/common.cpp
  blsct/double_public_key.cpp
  blsct/eip_2333/bls12_381_keygen.cpp
  blsct/key_io.cpp
  blsct/pos/helpers.cpp
  blsct/pos/pos.cpp
  blsct/pos/proof.cpp
  blsct/pos/proof_logic.cpp
  blsct/private_key.cpp
  blsct/public_key.cpp
  blsct/public_keys.cpp
  blsct/range_proof/bulletproofs/amount_recovery_request.cpp
  blsct/range_proof/bulletproofs/amount_recovery_result.cpp
  blsct/range_proof/bulletproofs/range_proof.cpp
  blsct/range_proof/bulletproofs/range_proof_logic.cpp
  blsct/range_proof/bulletproofs/range_proof_with_transcript.cpp
  blsct/range_proof/bulletproofs_plus/amount_recovery_request.cpp
  blsct/range_proof/bulletproofs_plus/amount_recovery_result.cpp
  blsct/range_proof/bulletproofs_plus/range_proof.cpp
  blsct/range_proof/bulletproofs_plus/range_proof_logic.cpp
  blsct/range_proof/bulletproofs_plus/range_proof_with_transcript.cpp
  blsct/range_proof/bulletproofs_plus/util.cpp
  blsct/range_proof/common.cpp
  blsct/range_proof/generators.cpp
  blsct/range_proof/msg_amt_cipher.cpp
  blsct/range_proof/proof_base.cpp
  blsct/set_mem_proof/set_mem_proof.cpp
  blsct/set_mem_proof/set_mem_proof_prover.cpp
  blsct/set_mem_proof/set_mem_proof_setup.cpp
  blsct/signature.cpp
  blsct/tokens/info.cpp
  blsct/tokens/predicate_exec.cpp
  blsct/tokens/predicate_parser.cpp
)

set(BLSCT_WALLET_SOURCES
  blsct/wallet/address.cpp
  blsct/wallet/balance_proof.cpp
  blsct/wallet/helpers.cpp
  blsct/wallet/keyman.cpp
  blsct/wallet/keyring.cpp
  blsct/wallet/rpc.cpp
  blsct/wallet/txfactory.cpp
  blsct/wallet/txfactory_base.cpp
  blsct/wallet/txfactory_global.cpp
  blsct/wallet/unsigned_transaction.cpp
  blsct/wallet/verification.cpp
)

add_library(navio_consensus STATIC EXCLUDE_FROM_ALL
  arith_uint256.cpp
  consensus/merkle.cpp
  consensus/tx_check.cpp
  hash.cpp
  primitives/block.cpp
  primitives/transaction.cpp
  pubkey.cpp
  script/interpreter.cpp
  script/script.cpp
  script/script_error.cpp
  uint256.cpp
  ${BLSCT_SOURCES}
)
target_link_libraries(navio_consensus
  PRIVATE
    core_interface
    navio_crypto
    secp256k1
    bls_interface
)

if(WITH_ZMQ)
  add_subdirectory(zmq)
endif()

add_library(navio_common STATIC EXCLUDE_FROM_ALL
  addresstype.cpp
  base58.cpp
  bech32.cpp
  chain.cpp
  chainparams.cpp
  chainparamsbase.cpp
  coins.cpp
  common/args.cpp
  common/bloom.cpp
  common/config.cpp
  common/init.cpp
  common/interfaces.cpp
  common/run_command.cpp
  common/settings.cpp
  common/system.cpp
  common/url.cpp
  compressor.cpp
  core_read.cpp
  core_write.cpp
  deploymentinfo.cpp
  external_signer.cpp
  init/common.cpp
  kernel/chainparams.cpp
  key.cpp
  key_io.cpp
  merkleblock.cpp
  net_permissions.cpp
  net_types.cpp
  netaddress.cpp
  netbase.cpp
  outputtype.cpp
  policy/feerate.cpp
  policy/policy.cpp
  protocol.cpp
  psbt.cpp
  rpc/external_signer.cpp
  rpc/rawtransaction_util.cpp
  rpc/request.cpp
  rpc/util.cpp
  scheduler.cpp
  script/descriptor.cpp
  script/miniscript.cpp
  script/sign.cpp
  script/signingprovider.cpp
  script/solver.cpp
  warnings.cpp
  ${BLSCT_SOURCES}
  ${BLSCT_WALLET_SOURCES}
)
target_link_libraries(navio_common
  PRIVATE
    core_interface
    navio_consensus
    navio_util
    univalue
    secp256k1
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
    $<$<PLATFORM_ID:Windows>:ws2_32>
  PUBLIC
    bls_interface
)

include(InstallBinaryComponent)

if(ENABLE_WALLET)
  add_subdirectory(wallet)

  if(BUILD_WALLET_TOOL)
    add_executable(navio-wallet
      bitcoin-wallet.cpp
      init/bitcoin-wallet.cpp
      wallet/wallettool.cpp
    )
    add_windows_resources(navio-wallet bitcoin-wallet-res.rc)
    target_link_libraries(navio-wallet
      core_interface
      navio_wallet
      navio_common
      navio_util
    )
    install_binary_component(navio-wallet HAS_MANPAGE)
  endif()
endif()

add_library(navio_node STATIC EXCLUDE_FROM_ALL
  addrdb.cpp
  addrman.cpp
  banman.cpp
  bip324.cpp
  blockencodings.cpp
  blockfilter.cpp
  consensus/tx_verify.cpp
  dbwrapper.cpp
  deploymentstatus.cpp
  flatfile.cpp
  headerssync.cpp
  httprpc.cpp
  httpserver.cpp
  i2p.cpp
  index/base.cpp
  index/blockfilterindex.cpp
  index/coinstatsindex.cpp
  index/txindex.cpp
  init.cpp
  kernel/chain.cpp
  kernel/checks.cpp
  kernel/coinstats.cpp
  kernel/context.cpp
  kernel/cs_main.cpp
  kernel/disconnected_transactions.cpp
  kernel/mempool_persist.cpp
  kernel/mempool_removal_reason.cpp
  mapport.cpp
  net.cpp
  net_processing.cpp
  netgroup.cpp
  node/abort.cpp
  node/blockmanager_args.cpp
  node/blockstorage.cpp
  node/caches.cpp
  node/chainstate.cpp
  node/chainstatemanager_args.cpp
  node/coin.cpp
  node/coins_view_args.cpp
  node/connection_types.cpp
  node/context.cpp
  node/database_args.cpp
  node/eviction.cpp
  node/interface_ui.cpp
  node/interfaces.cpp
  node/kernel_notifications.cpp
  node/mempool_args.cpp
  node/mempool_persist_args.cpp
  node/miner.cpp
  node/mini_miner.cpp
  node/minisketchwrapper.cpp
  node/peerman_args.cpp
  node/psbt.cpp
  node/transaction.cpp
  node/txreconciliation.cpp
  node/utxo_snapshot.cpp
  node/validation_cache_args.cpp
  noui.cpp
  policy/fees.cpp
  policy/fees_args.cpp
  policy/packages.cpp
  policy/rbf.cpp
  policy/settings.cpp
  pow.cpp
  rest.cpp
  rpc/blockchain.cpp
  rpc/fees.cpp
  rpc/mempool.cpp
  rpc/mining.cpp
  rpc/net.cpp
  rpc/node.cpp
  rpc/output_script.cpp
  rpc/rawtransaction.cpp
  rpc/server.cpp
  rpc/server_util.cpp
  rpc/signmessage.cpp
  rpc/txoutproof.cpp
  script/sigcache.cpp
  signet.cpp
  timedata.cpp
  torcontrol.cpp
  txdb.cpp
  txmempool.cpp
  txorphanage.cpp
  txrequest.cpp
  validation.cpp
  validationinterface.cpp
  versionbits.cpp
  blsct/tokens/rpc.cpp
  blsct/range_proof/rpc.cpp
  blsct/range_proof/bulletproofs/range_proof_logic.cpp
  blsct/wallet/unsigned_transaction.cpp
  blsct/wallet/verification.cpp
  $<$<TARGET_EXISTS:navio_wallet>:wallet/init.cpp>
  $<$<NOT:$<TARGET_EXISTS:navio_wallet>>:dummywallet.cpp>
)
target_link_libraries(navio_node
  PRIVATE
    core_interface
    navio_common
    navio_util
    $<TARGET_NAME_IF_EXISTS:navio_zmq>
    leveldb
    minisketch
    univalue
    Boost::headers
    $<TARGET_NAME_IF_EXISTS:libevent::core>
    $<TARGET_NAME_IF_EXISTS:libevent::extra>
    $<TARGET_NAME_IF_EXISTS:libevent::pthreads>
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
  PUBLIC
    bls_interface
)

# naviod
if(BUILD_DAEMON)
  add_executable(naviod
    naviod.cpp
    init/naviod.cpp
  )
  add_windows_resources(naviod naviod-res.rc)
  target_link_libraries(naviod
    core_interface
    navio_node
    $<TARGET_NAME_IF_EXISTS:navio_wallet>
  )
  install_binary_component(naviod HAS_MANPAGE)
endif()

add_library(navio_cli STATIC EXCLUDE_FROM_ALL
  compat/stdin.cpp
  rpc/client.cpp
)
target_link_libraries(navio_cli
  PUBLIC
    core_interface
    univalue
)

# navio-cli
if(BUILD_CLI)
  add_executable(navio-cli bitcoin-cli.cpp)
  add_windows_resources(navio-cli bitcoin-cli-res.rc)
  target_link_libraries(navio-cli
    core_interface
    navio_cli
    navio_common
    navio_util
    libevent::core
    libevent::extra
  )
  install_binary_component(navio-cli HAS_MANPAGE)
endif()

# navio-staker
if(BUILD_STAKER)
  add_executable(navio-staker navio-staker.cpp)
  add_windows_resources(navio-staker navio-staker-res.rc)
  target_link_libraries(navio-staker
    core_interface
    navio_cli
    navio_common
    navio_consensus
    navio_util
    navio_crypto
    bls_interface
    libevent::core
    libevent::extra
  )
  install_binary_component(navio-staker HAS_MANPAGE)
endif()

# navio-tx
if(BUILD_TX)
  add_executable(navio-tx bitcoin-tx.cpp)
  add_windows_resources(navio-tx bitcoin-tx-res.rc)
  target_link_libraries(navio-tx
    core_interface
    navio_common
    navio_util
    univalue
    bls_interface
  )
  install_binary_component(navio-tx HAS_MANPAGE)
endif()

# navio-util
if(BUILD_UTIL)
  add_executable(navio-util bitcoin-util.cpp)
  add_windows_resources(navio-util bitcoin-util-res.rc)
  target_link_libraries(navio-util
    core_interface
    navio_common
    navio_util
    bls_interface
  )
  install_binary_component(navio-util HAS_MANPAGE)
endif()

# naviokernel library + navio-chainstate
if(BUILD_KERNEL_LIB)
  add_subdirectory(kernel)
  if(BUILD_UTIL_CHAINSTATE)
    add_executable(navio-chainstate
      bitcoin-chainstate.cpp
    )
    target_link_libraries(navio-chainstate
      PRIVATE
        core_interface
        naviokernel
        bls_interface
    )
    install_binary_component(navio-chainstate INTERNAL)
  endif()
endif()

# libblsct standalone library
if(BUILD_LIBBLSCT_ONLY)
  add_library(blsct STATIC
    blsct/external_api/blsct.cpp
    blsct/external_api/dummy_impl.cpp
    common/args.cpp
    common/system.cpp
    common/url.cpp
    crypto/hmac_sha256.cpp
    crypto/ripemd160.cpp
    crypto/sha256.cpp
    hash.cpp
    primitives/transaction.cpp
    rpc/util.cpp
    script/interpreter.cpp
    script/miniscript.cpp
    script/script.cpp
    script/script_error.cpp
    script/sign.cpp
    script/signingprovider.cpp
    sync.cpp
    support/cleanse.cpp
    support/lockedpool.cpp
    uint256.cpp
    util/moneystr.cpp
    util/rbf.cpp
    util/strencodings.cpp
    util/time.cpp
    wallet/coincontrol.cpp
    wallet/context.cpp
    wallet/crypter.cpp
    wallet/db.cpp
    wallet/dump.cpp
    wallet/external_signer_scriptpubkeyman.cpp
    wallet/feebumper.cpp
    wallet/fees.cpp
    wallet/interfaces.cpp
    wallet/load.cpp
    wallet/receive.cpp
    wallet/rpc/addresses.cpp
    wallet/rpc/backup.cpp
    wallet/rpc/coins.cpp
    wallet/rpc/encrypt.cpp
    wallet/rpc/spend.cpp
    wallet/rpc/signmessage.cpp
    wallet/rpc/transactions.cpp
    wallet/rpc/util.cpp
    wallet/rpc/wallet.cpp
    wallet/scriptpubkeyman.cpp
    wallet/spend.cpp
    wallet/transaction.cpp
    wallet/wallet.cpp
    wallet/walletdb.cpp
    wallet/walletutil.cpp
    wallet/coinselection.cpp
    ${BLSCT_SOURCES}
    ${BLSCT_WALLET_SOURCES}
  )
  target_compile_definitions(blsct PRIVATE LIBBLSCT)
  target_link_libraries(blsct
    PRIVATE
      core_interface
      univalue
      secp256k1
      bls_interface
  )
  set_target_properties(blsct PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()

add_subdirectory(test/util)
if(BUILD_BENCH)
  add_subdirectory(bench)
endif()

if(BUILD_TESTS)
  add_subdirectory(test)
endif()

if(BUILD_FUZZ_BINARY)
  add_subdirectory(test/fuzz)
endif()
