// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_PRIVACY_SCORE_H
#define BITCOIN_WALLET_PRIVACY_SCORE_H

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <vector>

class UniValue;

namespace wallet {

/**
 * Privacy score of a wallet coin, in thousandths of a bit (milli-bits).
 *
 * The score estimates how many bits of ambiguity an observer who knows the
 * coin's history faces about which earlier coin it came from:
 *
 *     bits(out) = log2(foreign_inputs + 1) + min(bits(own inputs of the tx))
 *
 * where foreign_inputs counts the inputs of the transaction that created the
 * coin and are not coins of this wallet. A transaction that spends none of
 * our coins (a receive, a coinbase or staking reward) scores 0: its sender
 * knows the coin. A send's change scores the lowest of the coins it spends,
 * and a served cover candidate coming back out of someone else's aggregate
 * scores the spent coin's score plus log2(other inputs + 1), which is how
 * serving covers raises scores. Every coin of ours that a transaction
 * spending one of our coins creates takes the same score, a payment to us
 * inside such an aggregate included.
 *
 * Scores are kept as fixed-point integers, never floating point, so a value
 * stored in the wallet database reads back exactly. std::nullopt means the
 * score is unknown: a coin synced before scores were recorded, or one whose
 * transaction spends such a coin.
 */
using PrivacyMilliBits = uint32_t;

//! Milli-bits per bit.
static constexpr PrivacyMilliBits PRIVACY_MILLI_BITS_PER_BIT{1000};
//! On-disk encoding of an unknown score.
static constexpr PrivacyMilliBits PRIVACY_MILLI_BITS_UNKNOWN{std::numeric_limits<uint32_t>::max()};
//! Largest score; sums saturate here so they never wrap into "unknown".
static constexpr PrivacyMilliBits PRIVACY_MILLI_BITS_MAX{PRIVACY_MILLI_BITS_UNKNOWN - 1};

//! floor(1000 * log2(n)) for n >= 1. Exact for powers of two.
PrivacyMilliBits Log2MilliBits(uint64_t n);

/**
 * The score of every coin of ours a transaction creates, given the number of
 * its inputs that are not our coins and the scores of those that are.
 * Inputs spending outputs the same transaction creates (as in a block tx the
 * staker merged a chain of sends into) are left out of both by the caller.
 */
std::optional<PrivacyMilliBits> ComputePrivacyMilliBits(uint64_t foreign_inputs, const std::vector<std::optional<PrivacyMilliBits>>& own_inputs);

//! A score as an RPC value: a number of bits with three decimals, or null if unknown.
UniValue PrivacyBitsToUniValue(const std::optional<PrivacyMilliBits>& score);

//! Encode/decode a stored score, mapping unknown to PRIVACY_MILLI_BITS_UNKNOWN.
inline PrivacyMilliBits EncodePrivacyMilliBits(const std::optional<PrivacyMilliBits>& score)
{
    return score ? std::min(*score, PRIVACY_MILLI_BITS_MAX) : PRIVACY_MILLI_BITS_UNKNOWN;
}
inline std::optional<PrivacyMilliBits> DecodePrivacyMilliBits(PrivacyMilliBits v)
{
    if (v == PRIVACY_MILLI_BITS_UNKNOWN) return std::nullopt;
    return v;
}

} // namespace wallet

#endif // BITCOIN_WALLET_PRIVACY_SCORE_H
