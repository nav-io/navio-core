// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rfq/matcher.h>

#include <cmath>

namespace rfq {

std::optional<RfqQuote> PickBest(const std::vector<RfqQuote>& quotes,
                                 CAmount size, double min_fill_ratio, RankBy by)
{
    const double min_fill = static_cast<double>(size) * min_fill_ratio;

    const RfqQuote* best = nullptr;
    for (const RfqQuote& q : quotes) {
        if (static_cast<double>(q.fill) < min_fill) continue; // fill filter
        if (best == nullptr) { best = &q; continue; }

        bool better = false;
        switch (by) {
        case RankBy::Price: {
            const double pq = q.Price(), pb = best->Price();
            if (pq < pb) better = true;
            else if (pq == pb && q.fill > best->fill) better = true; // tiebreak
            break;
        }
        case RankBy::Fill:
            if (q.fill > best->fill) better = true;
            else if (q.fill == best->fill && q.Price() < best->Price()) better = true;
            break;
        case RankBy::LowestCost:
            if (q.sell_cost < best->sell_cost) better = true;
            break;
        }
        if (better) best = &q;
    }

    if (best == nullptr) return std::nullopt;
    return *best;
}

} // namespace rfq
