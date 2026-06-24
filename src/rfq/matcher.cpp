// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rfq/matcher.h>

#include <util/overflow.h>
#include <util/time.h>

#include <algorithm>
#include <atomic>
#include <cmath>

namespace rfq {

std::optional<RfqQuote> PickBest(const std::vector<RfqQuote>& quotes,
                                 CAmount size, double min_fill_ratio, RankBy by)
{
    // Minimum required fill as an exact integer. min_fill_ratio is a fractional
    // ratio in [0,1]; round the single size*ratio product up so a partial-fill
    // floor is never under-counted, and compare q.fill as the integer it is
    // (casting each CAmount fill to double would lose precision past 2^53).
    const double ratio = std::clamp(min_fill_ratio, 0.0, 1.0);
    const CAmount min_fill = (ratio <= 0.0)
        ? 0
        : static_cast<CAmount>(std::ceil(static_cast<long double>(size) * ratio));

    // Compare two quotes by price (sell_cost/fill, lower is better) WITHOUT
    // floating point: a/x < b/y  <=>  a*y < b*x for positive fills, by exact
    // integer cross-multiplication. Avoids the rounding that makes `==` on
    // doubles an unreliable tiebreak. Returns <0 if `a` is cheaper, 0 if equal,
    // >0 if dearer; a non-positive fill always sorts last. int64 products can
    // overflow at extreme amounts, so fall back to long double only then.
    // CheckedMul is portable (no __builtin/__int128: MSVC + 32-bit safe).
    auto cmp_price = [](const RfqQuote& a, const RfqQuote& b) -> int {
        if (a.fill <= 0 || b.fill <= 0) {
            if (a.fill <= 0 && b.fill <= 0) return 0;
            return a.fill <= 0 ? 1 : -1;
        }
        const auto lhs = CheckedMul<int64_t>(a.sell_cost, b.fill);
        const auto rhs = CheckedMul<int64_t>(b.sell_cost, a.fill);
        if (lhs && rhs) {
            return *lhs < *rhs ? -1 : (*lhs > *rhs ? 1 : 0);
        }
        const long double l = static_cast<long double>(a.sell_cost) * b.fill;
        const long double r = static_cast<long double>(b.sell_cost) * a.fill;
        return l < r ? -1 : (l > r ? 1 : 0);
    };

    const RfqQuote* best = nullptr;
    for (const RfqQuote& q : quotes) {
        if (q.fill < min_fill) continue; // fill filter (exact integer compare)
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
    // Bound per-request quotes: quotes arrive from the network, so an attacker
    // could otherwise flood one open request with unbounded distinct quote_ids.
    if (it->second.quotes.size() >= MAX_QUOTES_PER_REQUEST &&
        !it->second.quotes.contains(q.quote_id)) {
        return false;
    }
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

std::optional<RfqQuote> MatcherRegistry::ClaimQuote(const uint256& uuid, const uint256& quote_id)
{
    LOCK(m_mutex);
    auto it = m_active.find(uuid);
    if (it == m_active.end()) return std::nullopt;
    auto qit = it->second.quotes.find(quote_id);
    if (qit == it->second.quotes.end()) return std::nullopt;
    RfqQuote q = qit->second;
    // Drop the whole request so a concurrent accept of the same uuid finds
    // nothing and cannot build a second conflicting taker half.
    m_active.erase(it);
    return q;
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
    // Drop any pending matches whose request collection window has closed, so
    // the map self-trims from network traffic rather than growing forever.
    const int64_t now = GetTime<std::chrono::seconds>().count();
    std::erase_if(m_pending, [now](const auto& e) { return e.second.req.expiry <= now; });
    // Hard cap as a backstop: refuse new uuids once full (existing uuids may
    // still be refreshed). Prevents a flood of distinct uuids from OOMing us.
    if (m_pending.size() >= MAX_PENDING_MATCHES && !m_pending.contains(req.uuid)) return;
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
