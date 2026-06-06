// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLSCT_POS_HELPERS_H
#define BLSCT_POS_HELPERS_H

#include <blsct/arith/mcl/mcl.h>
#include <uint256.h>
#include <arith_uint256.h>

#define MODIFIER_INTERVAL_RATIO 3

// PoPS anti-grinding: the kernel hash coarsens block time into fixed-width
// buckets so an attacker searching over candidate block times sees a 1/N-smaller
// search space. 16 s is << the 60 s target spacing, so retarget dynamics are
// unaffected in aggregate; individual attempts cost less to evaluate but the
// economic cost of waiting until a new bucket dominates.
#define POPS_TIME_GRANULARITY_SECONDS 16u

// V2 anti-grinding: maximum a PoS block's timestamp may lead the validator's
// clock. The generic MAX_FUTURE_BLOCK_TIME (2h) lets a staker pre-grind ~450
// not-yet-valid 16 s kernel buckets at once. Block time must stay in the kernel
// for liveness (advancing real time reveals fresh buckets so the chain can
// progress when a slot has no winner), so instead the future window is capped
// to a few buckets: 96 s = 6 * POPS_TIME_GRANULARITY_SECONDS. Enforced only for
// PoS blocks at/after Consensus::Params::nPoPSKernelV2Height.
static constexpr int64_t POPS_MAX_FUTURE_BLOCK_TIME = 6 * POPS_TIME_GRANULARITY_SECONDS; // 96 s

// V2 staked-commitment ring seed depth. The ring shuffle must be seeded from a
// value no single staker can grind: the previous block's hash is grindable by
// whoever produced it (they pick the next ring). The V2 seed combines the
// stake modifier (a beacon that only changes once per nModifierInterval and
// aggregates 64 historical blocks) with the hash of an ancestor this many
// blocks back, so biasing the ring requires long-range control of both the
// modifier interval and the deep anchor. 128 blocks.
static constexpr int POPS_RING_SEED_LOOKBACK = 128;

namespace blsct {
// `hardened` controls PoPS anti-grinding: when true, `time` is bucketed into
// POPS_TIME_GRANULARITY_SECONDS before hashing. When false, raw `time` is
// hashed (legacy pre-hardening behaviour). The flag comes from
// Consensus::Params::fPoPSHardened.
uint256 CalculateKernelHash(const uint32_t& prevTime, const uint64_t& stakeModifier, const uint32_t& time, bool hardened = true);

// Variant that additionally binds accumulated chain work when `hardened` is
// true. Used at consensus level to prevent "extend multiple private forks"
// grinding: each candidate fork carries a distinct nChainWork value, so
// grinding work does not carry between forks. When `hardened` is false,
// `prevChainWork` is ignored and time is not bucketed (legacy kernel).
uint256 CalculateKernelHashWithChainWork(const uint32_t& prevTime, const uint64_t& stakeModifier, const arith_uint256& prevChainWork, const uint32_t& time, bool hardened = true);

// V2 kernel: additionally binds the set-membership proof image point `phi`
// (`block.posProof.setMemProof.phi`) into the kernel hash. Activated by block
// height (Consensus::Params::nPoPSKernelV2Height).
uint256 CalculateKernelHashWithChainWork(const uint32_t& prevTime, const uint64_t& stakeModifier, const arith_uint256& prevChainWork, const uint32_t& time, const MclG1Point& phi, bool hardened = true);
} // namespace blsct

#endif // BLSCT_POS_H