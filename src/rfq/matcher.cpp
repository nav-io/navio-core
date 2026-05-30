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

bool MatcherRegistry::OpenRequest(const RfqRequest& req)
{
    LOCK(m_mutex);
    return m_active.emplace(req.uuid, Active{req, {}}).second;
}

bool MatcherRegistry::AddQuote(const RfqQuote& q)
{
    LOCK(m_mutex);
    auto it = m_active.find(q.uuid);
    if (it == m_active.end()) return false;
    return it->second.quotes.emplace(q.quote_id, q).second;
}

std::vector<RfqQuote> MatcherRegistry::GetQuotes(const uint256& uuid) const
{
    LOCK(m_mutex);
    std::vector<RfqQuote> out;
    auto it = m_active.find(uuid);
    if (it == m_active.end()) return out;
    out.reserve(it->second.quotes.size());
    for (const auto& [id, q] : it->second.quotes) out.push_back(q);
    return out;
}

std::optional<RfqRequest> MatcherRegistry::GetRequest(const uint256& uuid) const
{
    LOCK(m_mutex);
    auto it = m_active.find(uuid);
    if (it == m_active.end()) return std::nullopt;
    return it->second.req;
}

std::optional<RfqQuote> MatcherRegistry::GetQuote(const uint256& uuid, const uint256& quote_id) const
{
    LOCK(m_mutex);
    auto it = m_active.find(uuid);
    if (it == m_active.end()) return std::nullopt;
    auto qit = it->second.quotes.find(quote_id);
    if (qit == it->second.quotes.end()) return std::nullopt;
    return qit->second;
}

bool MatcherRegistry::Cancel(const uint256& uuid)
{
    LOCK(m_mutex);
    return m_active.erase(uuid) > 0;
}

std::vector<uint256> MatcherRegistry::ListRequests() const
{
    LOCK(m_mutex);
    std::vector<uint256> out;
    out.reserve(m_active.size());
    for (const auto& [uuid, a] : m_active) out.push_back(uuid);
    return out;
}

size_t MatcherRegistry::Size() const
{
    LOCK(m_mutex);
    return m_active.size();
}

} // namespace rfq
