# Copyright (c) 2024-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

include(GNUInstallDirs)

add_library(naviokernel
  naviokernel.cpp
  chain.cpp
  checks.cpp
  chainparams.cpp
  coinstats.cpp
  context.cpp
  cs_main.cpp
  disconnected_transactions.cpp
  mempool_persist.cpp
  mempool_removal_reason.cpp
  ../arith_uint256.cpp
  ../blsct/arith/elements.cpp
  ../blsct/arith/mcl/mcl_g1point.cpp
  ../blsct/arith/mcl/mcl_scalar.cpp
  ../blsct/building_block/g_h_gi_hi_zero_verifier.cpp
  ../blsct/building_block/generator_deriver.cpp
  ../blsct/building_block/imp_inner_prod_arg.cpp
  ../blsct/building_block/lazy_point.cpp
  ../blsct/building_block/lazy_points.cpp
  ../blsct/building_block/weighted_inner_prod_arg.cpp
  ../blsct/common.cpp
  ../blsct/double_public_key.cpp
  ../blsct/pos/helpers.cpp
  ../blsct/pos/pos.cpp
  ../blsct/pos/proof.cpp
  ../blsct/pos/proof_logic.cpp
  ../blsct/private_key.cpp
  ../blsct/public_key.cpp
  ../blsct/public_keys.cpp
  ../blsct/range_proof/bulletproofs/amount_recovery_request.cpp
  ../blsct/range_proof/bulletproofs/amount_recovery_result.cpp
  ../blsct/range_proof/bulletproofs/range_proof.cpp
  ../blsct/range_proof/bulletproofs/range_proof_logic.cpp
  ../blsct/range_proof/bulletproofs/range_proof_with_transcript.cpp
  ../blsct/range_proof/bulletproofs_plus/amount_recovery_request.cpp
  ../blsct/range_proof/bulletproofs_plus/amount_recovery_result.cpp
  ../blsct/range_proof/bulletproofs_plus/range_proof.cpp
  ../blsct/range_proof/bulletproofs_plus/range_proof_logic.cpp
  ../blsct/range_proof/bulletproofs_plus/range_proof_with_transcript.cpp
  ../blsct/range_proof/bulletproofs_plus/util.cpp
  ../blsct/range_proof/common.cpp
  ../blsct/range_proof/generators.cpp
  ../blsct/range_proof/msg_amt_cipher.cpp
  ../blsct/range_proof/proof_base.cpp
  ../blsct/set_mem_proof/set_mem_proof.cpp
  ../blsct/set_mem_proof/set_mem_proof_prover.cpp
  ../blsct/set_mem_proof/set_mem_proof_setup.cpp
  ../blsct/signature.cpp
  ../blsct/tokens/predicate_exec.cpp
  ../blsct/tokens/predicate_parser.cpp
  ../blsct/wallet/txfactory_global.cpp
  ../blsct/wallet/unsigned_transaction.cpp
  ../blsct/wallet/verification.cpp
  ../chain.cpp
  ../clientversion.cpp
  ../coins.cpp
  ../compressor.cpp
  ../consensus/merkle.cpp
  ../consensus/tx_check.cpp
  ../consensus/tx_verify.cpp
  ../core_read.cpp
  ../dbwrapper.cpp
  ../deploymentinfo.cpp
  ../deploymentstatus.cpp
  ../flatfile.cpp
  ../hash.cpp
  ../key.cpp
  ../logging.cpp
  ../node/blockstorage.cpp
  ../node/chainstate.cpp
  ../node/utxo_snapshot.cpp
  ../policy/feerate.cpp
  ../policy/packages.cpp
  ../policy/policy.cpp
  ../policy/rbf.cpp
  ../policy/settings.cpp
  ../pow.cpp
  ../primitives/block.cpp
  ../primitives/transaction.cpp
  ../pubkey.cpp
  ../random.cpp
  ../randomenv.cpp
  ../scheduler.cpp
  ../script/interpreter.cpp
  ../script/script.cpp
  ../script/script_error.cpp
  ../script/sigcache.cpp
  ../script/solver.cpp
  ../signet.cpp
  ../streams.cpp
  ../support/cleanse.cpp
  ../support/lockedpool.cpp
  ../sync.cpp
  ../txdb.cpp
  ../txmempool.cpp
  ../uint256.cpp
  ../util/batchpriority.cpp
  ../util/bytevectorhash.cpp
  ../util/chaintype.cpp
  ../util/check.cpp
  ../util/exception.cpp
  ../util/fs.cpp
  ../util/fs_helpers.cpp
  ../util/hasher.cpp
  ../util/moneystr.cpp
  ../util/rbf.cpp
  ../util/serfloat.cpp
  ../util/signalinterrupt.cpp
  ../util/strencodings.cpp
  ../util/string.cpp
  ../util/syserror.cpp
  ../util/thread.cpp
  ../util/threadnames.cpp
  ../util/time.cpp
  ../util/tokenpipe.cpp
  ../validation.cpp
  ../validationinterface.cpp
  ../versionbits.cpp
  ../warnings.cpp
  $<TARGET_OBJECTS:navio_clientversion>
  $<TARGET_OBJECTS:navio_crypto>
)

target_compile_definitions(naviokernel
  PRIVATE
    BUILD_BITCOIN_INTERNAL
  PUBLIC
    $<TARGET_PROPERTY:core_interface,INTERFACE_COMPILE_DEFINITIONS>
)
target_compile_options(naviokernel
  PUBLIC
    $<TARGET_PROPERTY:core_interface,INTERFACE_COMPILE_OPTIONS>
)
# naviokernel requires default symbol visibility even when --reduce-exports is set
set_target_properties(naviokernel PROPERTIES CXX_VISIBILITY_PRESET default)

target_include_directories(naviokernel
  PRIVATE
    ${PROJECT_BINARY_DIR}/src
    ${PROJECT_SOURCE_DIR}/src
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/kernel/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(naviokernel
  PRIVATE
    leveldb
    secp256k1
    bls_interface
    Boost::headers
)

include(GNUInstallDirs)
install(TARGETS naviokernel
  EXPORT NavioKernelTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
