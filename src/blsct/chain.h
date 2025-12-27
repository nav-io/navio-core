// Copyright (c) 2025 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_CHAIN_H
#define NAVIO_BLSCT_CHAIN_H

#include <string>

const std::string& get_chain();

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MainNet,
    TestNet,
    SigNet,
    RegTest
} BlsctChain;

void set_chain(BlsctChain chain);

#ifdef __cplusplus
} // extern "C"
#endif

#endif  // NAVIO_BLSCT_CHAIN_H

