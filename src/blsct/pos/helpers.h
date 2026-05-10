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
} // namespace blsct

#endif // BLSCT_POS_H