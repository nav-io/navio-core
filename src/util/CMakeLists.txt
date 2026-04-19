# Copyright (c) 2024-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

add_library(navio_util STATIC EXCLUDE_FROM_ALL
  asmap.cpp
  batchpriority.cpp
  bip32.cpp
  bytevectorhash.cpp
  chaintype.cpp
  check.cpp
  error.cpp
  exception.cpp
  fees.cpp
  fs.cpp
  fs_helpers.cpp
  hasher.cpp
  message.cpp
  moneystr.cpp
  rbf.cpp
  readwritefile.cpp
  serfloat.cpp
  signalinterrupt.cpp
  sock.cpp
  spanparsing.cpp
  strencodings.cpp
  string.cpp
  syserror.cpp
  thread.cpp
  threadinterrupt.cpp
  threadnames.cpp
  time.cpp
  tokenpipe.cpp
  ../logging.cpp
  ../random.cpp
  ../randomenv.cpp
  ../streams.cpp
  ../sync.cpp
)

target_link_libraries(navio_util
  PRIVATE
    core_interface
    navio_clientversion
    navio_crypto
    $<$<PLATFORM_ID:Windows>:ws2_32>
    $<$<PLATFORM_ID:Windows>:iphlpapi>
    $<$<PLATFORM_ID:Windows>:bcrypt>
)
