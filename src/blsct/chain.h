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

enum Chain {
    MainNet,
    TestNet,
    SigNet,
    RegTest
};

bool set_chain(enum Chain chain);

#ifdef __cplusplus
} // extern "C"
#endif

#endif  // NAVIO_BLSCT_CHAIN_H

