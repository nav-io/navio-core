// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/privacy_score.h>

#include <tinyformat.h>
#include <univalue.h>
#include <util/check.h>

#include <bit>
#include <cmath>
#include <map>

namespace wallet {

PrivacyMilliBits Log2MilliBits(uint64_t n)
{
    Assert(n >= 1);
    const int whole{std::bit_width(n) - 1};
    const PrivacyMilliBits lower{static_cast<PrivacyMilliBits>(whole) * PRIVACY_MILLI_BITS_PER_BIT};
    if (std::has_single_bit(n)) return lower;
    // log2 of a non-power of two is irrational, so its thousandths are never
    // an exact integer for floor() to land on the wrong side of; the clamp
    // only guards against a libm off by an ulp near the bounds.
    const double milli{std::floor(std::log2(static_cast<double>(n)) * PRIVACY_MILLI_BITS_PER_BIT)};
    const PrivacyMilliBits upper{lower + PRIVACY_MILLI_BITS_PER_BIT - 1};
    if (!(milli > lower)) return lower;
    if (milli > upper) return upper;
    return static_cast<PrivacyMilliBits>(milli);
}

std::optional<PrivacyMilliBits> ComputePrivacyMilliBits(uint64_t foreign_inputs, const std::vector<std::optional<PrivacyMilliBits>>& own_inputs)
{
    // Spending none of our coins, the tx is a receive: its sender knows the coin.
    if (own_inputs.empty()) return PrivacyMilliBits{0};
    PrivacyMilliBits lowest{PRIVACY_MILLI_BITS_MAX};
    for (const auto& score : own_inputs) {
        if (!score) return std::nullopt;
        lowest = std::min(lowest, std::min(*score, PRIVACY_MILLI_BITS_MAX));
    }
    const uint64_t sources{foreign_inputs == std::numeric_limits<uint64_t>::max() ? foreign_inputs : foreign_inputs + 1};
    const PrivacyMilliBits mixed{Log2MilliBits(sources)};
    // Saturate rather than wrap: a long mixing history must not read as unknown.
    if (mixed > PRIVACY_MILLI_BITS_MAX - lowest) return PRIVACY_MILLI_BITS_MAX;
    return lowest + mixed;
}

std::optional<std::vector<size_t>> SelectFromOnePrivacyBucket(const std::vector<std::pair<CAmount, std::optional<PrivacyMilliBits>>>& coins, CAmount amount_limit)
{
    // Bucket -1 holds the unknown scores, below every known one.
    const auto bucket_of = [](const std::optional<PrivacyMilliBits>& score) -> int64_t {
        return score ? int64_t{*score / PRIVACY_MILLI_BITS_PER_BIT} : -1;
    };
    std::map<int64_t, CAmount> totals;
    // A wallet's coins add up to no more than the money supply, so the sums
    // cannot overflow.
    for (const auto& [amount, score] : coins) totals[bucket_of(score)] += amount;
    for (const auto& [bucket, total] : totals) {
        if (total <= amount_limit) continue;
        std::vector<size_t> chosen;
        CAmount added{0};
        for (size_t i = 0; i < coins.size() && added <= amount_limit; ++i) {
            if (bucket_of(coins[i].second) != bucket) continue;
            chosen.push_back(i);
            added += coins[i].first;
        }
        return chosen;
    }
    return std::nullopt;
}

UniValue PrivacyBitsToUniValue(const std::optional<PrivacyMilliBits>& score)
{
    if (!score) return UniValue{UniValue::VNULL};
    return UniValue{UniValue::VNUM, strprintf("%u.%03u", *score / PRIVACY_MILLI_BITS_PER_BIT, *score % PRIVACY_MILLI_BITS_PER_BIT)};
}

} // namespace wallet
