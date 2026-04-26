// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/pos/helpers.h>
#include <hash.h>

#include <iostream>
#include <util/strencodings.h>

namespace blsct {
// Bucket the staker-chosen time into POPS_TIME_GRANULARITY_SECONDS intervals.
// Restricts the effective grinding surface per slot to
// (slot_length / granularity) attempts.
static uint32_t BucketTime(const uint32_t& time)
{
    return time - (time % POPS_TIME_GRANULARITY_SECONDS);
}

uint256
CalculateKernelHash(const uint32_t& prevTime, const uint64_t& stakeModifier, const uint32_t& time, bool hardened)
{
    HashWriter ss{};

    ss << prevTime << stakeModifier << (hardened ? BucketTime(time) : time);

    return ss.GetHash();
}

uint256
CalculateKernelHashWithChainWork(const uint32_t& prevTime, const uint64_t& stakeModifier, const arith_uint256& prevChainWork, const uint32_t& time, bool hardened)
{
    if (!hardened) {
        // Legacy pre-hardening kernel: no chain-work binding, raw time.
        return CalculateKernelHash(prevTime, stakeModifier, time, /*hardened=*/false);
    }

    HashWriter ss{};

    ss << prevTime
       << stakeModifier
       << ArithToUint256(prevChainWork)
       << BucketTime(time);

    return ss.GetHash();
}
} // namespace blsct