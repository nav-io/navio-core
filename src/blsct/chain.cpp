// Copyright (c) 2025 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/chain.h>
#include <blsct/key_io.h>
#include <mutex>

static std::string g_chain;
static std::mutex g_chain_mutex;

const std::string& get_chain() {
    std::lock_guard<std::mutex> lock(g_chain_mutex);

    return g_chain;
}

void set_chain(BlsctChain chain)
{
    std::lock_guard<std::mutex> lock(g_chain_mutex);

    switch (chain) {
        case MainNet:
            g_chain = blsct::bech32_hrp::Main;
            break;

        case TestNet:
            g_chain = blsct::bech32_hrp::TestNet;
            break;

        case SigNet:
            g_chain = blsct::bech32_hrp::SigNet;
            break;

        case RegTest:
            g_chain = blsct::bech32_hrp::RegTest;
            break;
    }
}

