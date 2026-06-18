// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rfq/intent_store.h>

#include <limits>

namespace rfq {

//! Fixed-point scale for price_min: price is sell-units per buy-unit, expressed
//! as price_min / PRICE_SCALE. E.g. price_min = PRICE_SCALE/10 means 0.1 sell
//! per buy. Keeps integer math exact for typical amounts.
static constexpr int64_t PRICE_SCALE = 100000000; // 1e8

uint64_t IntentStore::Add(const TokenId& token_in, const TokenId& token_out,
                          CAmount min_size, CAmount max_size, CAmount price_min, int64_t expiry)
{
    LOCK(m_mutex);
    const uint64_t id = m_next_id++;
    m_intents[id] = Intent{id, token_in, token_out, min_size, max_size, price_min, expiry};
    return id;
}

bool IntentStore::Clear(uint64_t id)
{
    LOCK(m_mutex);
    return m_intents.erase(id) > 0;
}

std::vector<Intent> IntentStore::List() const
{
    LOCK(m_mutex);
    std::vector<Intent> out;
    out.reserve(m_intents.size());
    for (const auto& [id, intent] : m_intents) out.push_back(intent);
    return out;
}

std::optional<Match> IntentStore::TryMatch(const RfqRequest& req, int64_t now) const
{
    LOCK(m_mutex);
    for (const auto& [id, intent] : m_intents) {
        if (now >= intent.expiry) continue;
        // Maker pays out what the taker wants to buy; receives what they sell.
        if (!(intent.token_in == req.buy)) continue;
        if (!(intent.token_out == req.sell)) continue;
        if (req.size <= 0) continue;
        if (req.size < intent.min_size || req.size > intent.max_size) continue;
        // A negative price would slip past the positive-overflow guard below and
        // yield a negative sell_cost; reject it outright (also defended at the RPC).
        if (intent.price_min < 0) continue;

        // Quote at the intent's floor price. Skip intents whose scaled cost
        // does not fit in CAmount (portable: no __int128 on MSVC or 32-bit).
        if (intent.price_min > std::numeric_limits<CAmount>::max() / req.size) {
            continue;
        }
        Match m;
        m.intent_id = id;
        m.fill = req.size;
        // Round the scaled cost UP (ceil division): truncating toward zero would
        // let the maker quote fractionally below its declared price_min floor.
        // Compute the remainder separately so the +denominator never overflows.
        const CAmount scaled = req.size * intent.price_min;
        m.sell_cost = scaled / PRICE_SCALE + ((scaled % PRICE_SCALE) ? 1 : 0);
        return m;
    }
    return std::nullopt;
}

size_t IntentStore::Size() const
{
    LOCK(m_mutex);
    return m_intents.size();
}

} // namespace rfq
