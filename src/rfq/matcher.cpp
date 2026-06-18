// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rfq/matcher.h>

#include <atomic>

#include <cmath>

namespace rfq {

std::optional<RfqQuote> PickBest(const std::vector<RfqQuote>& quotes,
                                 CAmount size, double min_fill_ratio, RankBy by)
{
    const double min_fill = static_cast<double>(size) * min_fill_ratio;

    // Compare two quotes by price (sell_cost/fill, lower is better) WITHOUT
    // floating point: a/x < b/y  <=>  a*y < b*x for positive fills, by exact
    // integer cross-multiplication. Avoids the rounding that makes `==` on
    // doubles an unreliable tiebreak. Returns <0 if `a` is cheaper, 0 if equal,
    // >0 if dearer; a non-positive fill always sorts last. int64 products can
    // overflow at extreme amounts, so fall back to long double only then
    // (__int128 is unavailable on the 32-bit targets we build).
    auto cmp_price = [](const RfqQuote& a, const RfqQuote& b) -> int {
        if (a.fill <= 0 || b.fill <= 0) {
            if (a.fill <= 0 && b.fill <= 0) return 0;
            return a.fill <= 0 ? 1 : -1;
        }
        int64_t lhs, rhs;
        if (!__builtin_mul_overflow(a.sell_cost, b.fill, &lhs) &&
            !__builtin_mul_overflow(b.sell_cost, a.fill, &rhs)) {
            return lhs < rhs ? -1 : (lhs > rhs ? 1 : 0);
        }
        const long double l = static_cast<long double>(a.sell_cost) * b.fill;
        const long double r = static_cast<long double>(b.sell_cost) * a.fill;
        return l < r ? -1 : (l > r ? 1 : 0);
    };

    const RfqQuote* best = nullptr;
    for (const RfqQuote& q : quotes) {
        if (static_cast<double>(q.fill) < min_fill) continue; // fill filter
        if (best == nullptr) { best = &q; continue; }

        bool better = false;
        switch (by) {
        case RankBy::Price: {
            const int c = cmp_price(q, *best);
            if (c < 0) better = true;
            else if (c == 0 && q.fill > best->fill) better = true; // tiebreak
            break;
        }
        case RankBy::Fill:
            if (q.fill > best->fill) better = true;
            else if (q.fill == best->fill && cmp_price(q, *best) < 0) better = true;
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

void MatcherRegistry::AddPendingMatch(const RfqRequest& req, CAmount fill, CAmount sell_cost)
{
    LOCK(m_mutex);
    m_pending[req.uuid] = PendingMatch{req, fill, sell_cost};
}

std::vector<MatcherRegistry::PendingMatch> MatcherRegistry::ListPendingMatches() const
{
    LOCK(m_mutex);
    std::vector<PendingMatch> out;
    out.reserve(m_pending.size());
    for (const auto& [uuid, pm] : m_pending) out.push_back(pm);
    return out;
}

std::optional<MatcherRegistry::PendingMatch> MatcherRegistry::TakePendingMatch(const uint256& uuid)
{
    LOCK(m_mutex);
    auto it = m_pending.find(uuid);
    if (it == m_pending.end()) return std::nullopt;
    PendingMatch pm = it->second;
    m_pending.erase(it);
    return pm;
}

namespace {
std::atomic<MatcherRegistry*> g_active_matcher{nullptr};
}
void SetActiveMatcher(MatcherRegistry* matcher) { g_active_matcher.store(matcher, std::memory_order_release); }
MatcherRegistry* GetActiveMatcher() { return g_active_matcher.load(std::memory_order_acquire); }

} // namespace rfq
