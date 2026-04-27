# Copyright (c) 2024-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

add_library(test_util STATIC EXCLUDE_FROM_ALL
  blockfilter.cpp
  coins.cpp
  index.cpp
  json.cpp
  logging.cpp
  mining.cpp
  net.cpp
  random.cpp
  script.cpp
  setup_common.cpp
  str.cpp
  transaction_utils.cpp
  txmempool.cpp
  validation.cpp
  $<$<BOOL:${ENABLE_WALLET}>:${PROJECT_SOURCE_DIR}/src/wallet/test/util.cpp>
)

target_link_libraries(test_util
  PRIVATE
    core_interface
    Boost::headers
    bls_interface
    $<$<BOOL:${ENABLE_WALLET}>:SQLite3::SQLite3>
  PUBLIC
    univalue
)
