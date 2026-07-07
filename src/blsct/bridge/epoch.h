// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_BRIDGE_EPOCH_H
#define NAVIO_BLSCT_BRIDGE_EPOCH_H

#include <consensus/params.h>

#include <cstdint>

// Epoch / committee-period arithmetic (DESIGN.md §4.2/§5). Everything is a
// pure function of the consensus parameters and a height.
//
// Epoch e spans heights [S + e·E, S + (e+1)·E − 1] where S = nBridgeHeight
// and E = nEpochBlocks; its last block is the epoch-boundary block T_e that
// checkpoints reference. Period p spans epochs [p·P, (p+1)·P − 1].
// The committee for period p is the guardian set snapshot taken at the last
// block of period p−2 (two-period lookahead); periods 0 and 1 have no
// committee.

namespace nbp {

inline bool BridgeActive(const Consensus::Params& params, int height)
{
    return params.nbp.IsActive(height);
}

inline int64_t EpochOfHeight(const Consensus::Params& params, int height)
{
    return (height - params.nbp.nBridgeHeight) / static_cast<int64_t>(params.nbp.nEpochBlocks);
}

inline int EpochBoundaryHeight(const Consensus::Params& params, int64_t epoch)
{
    return params.nbp.nBridgeHeight + static_cast<int>((epoch + 1) * params.nbp.nEpochBlocks) - 1;
}

inline bool IsEpochBoundary(const Consensus::Params& params, int height)
{
    return BridgeActive(params, height) &&
           (height - params.nbp.nBridgeHeight + 1) % static_cast<int>(params.nbp.nEpochBlocks) == 0;
}

inline int64_t PeriodOfEpoch(const Consensus::Params& params, int64_t epoch)
{
    return epoch / static_cast<int64_t>(params.nbp.nPeriodEpochs);
}

inline int64_t PeriodOfHeight(const Consensus::Params& params, int height)
{
    return PeriodOfEpoch(params, EpochOfHeight(params, height));
}

inline int64_t LastEpochOfPeriod(const Consensus::Params& params, int64_t period)
{
    return (period + 1) * static_cast<int64_t>(params.nbp.nPeriodEpochs) - 1;
}

inline bool IsLastEpochOfPeriod(const Consensus::Params& params, int64_t epoch)
{
    return epoch == LastEpochOfPeriod(params, PeriodOfEpoch(params, epoch));
}

inline int PeriodBoundaryHeight(const Consensus::Params& params, int64_t period)
{
    return EpochBoundaryHeight(params, LastEpochOfPeriod(params, period));
}

inline bool IsPeriodBoundary(const Consensus::Params& params, int height)
{
    return IsEpochBoundary(params, height) &&
           IsLastEpochOfPeriod(params, EpochOfHeight(params, height));
}

} // namespace nbp

#endif // NAVIO_BLSCT_BRIDGE_EPOCH_H
