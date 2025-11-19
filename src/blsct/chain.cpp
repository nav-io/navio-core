// Copyright (c) 2025 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/chain.h>
#include <blsct/key_io.h>
#include <mutex>

static std::string g_chain;
static std::mutex g_set_chain_mutex;

const std::string& get_chain() {
    return g_chain;
}

bool set_chain(enum Chain chain)
{
    std::lock_guard<std::mutex> lock(g_set_chain_mutex);
    if (!g_chain.empty()) {
        return false;
    }

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
    return true;
}

