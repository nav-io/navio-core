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

bool set_chain(const std::string& chain) {
    static const std::array chains = {
        blsct::bech32_hrp::Mainnet,
        blsct::bech32_hrp::Testnet,
        blsct::bech32_hrp::Signet,
        blsct::bech32_hrp::Regtest,
    };

    std::lock_guard<std::mutex> lock(g_chain_mutex);

    if (std::find(chains.begin(), chains.end(), chain) == chains.end()) {
        return false;
    }
    g_chain = chain;
    return true;
}

