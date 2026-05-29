// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <aggregation/session.h>

#include <blsct/wallet/txfactory_global.h>

namespace aggregation {

int64_t SumCandidateWeight(std::span<const CTransactionRef> candidates)
{
    int64_t w = 0;
    for (const auto& c : candidates) {
        if (c) w += blsct::GetTransactionWeight(*c);
    }
    return w;
}

CAmount RequiredCandidateFee(std::span<const CTransactionRef> candidates, CAmount fee_rate)
{
    return static_cast<CAmount>(SumCandidateWeight(candidates)) * fee_rate;
}

} // namespace aggregation
