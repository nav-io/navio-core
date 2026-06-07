// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/pos/pos.h>
#include <primitives/block.h>

namespace blsct {
// ppcoin: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}

unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    // unsigned int nProofOfStakeLimit = UintToArith256(params.posLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight + 1) % params.DifficultyAdjustmentIntervalPos() != 0) {
        // if (params.fPowAllowMinDifficultyBlocks) {
        //     // Special difficulty rule for testnet:
        //     // If the new block's timestamp is more than 2* 10 minutes
        //     // then allow mining of a min-difficulty block.
        //     if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPosTargetSpacing * 2)
        //         return nProofOfStakeLimit;
        //     else {
        //         // Return the last non-special-min-difficulty-rules-block
        //         const CBlockIndex* pindex = pindexLast;
        //         while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentIntervalPos() != 0 && pindex->nBits == nProofOfStakeLimit)
        //             pindex = pindex->pprev;
        //         return pindex->nBits;
        //     }
        // }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 15 minutes worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentIntervalPos() - 1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextTargetRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextTargetRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPosNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPosTargetTimespan / 4)
        nActualTimespan = params.nPosTargetTimespan / 4;
    if (nActualTimespan > params.nPosTargetTimespan * 4)
        nActualTimespan = params.nPosTargetTimespan * 4;

    // Retarget
    const arith_uint256 bnPosLimit = UintToArith256(params.posLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPosTargetTimespan;

    if (bnNew > bnPosLimit)
        bnNew = bnPosLimit;

    return bnNew.GetCompact();
}

// Get the last stake modifier and its generation time from a given block
bool GetLastStakeModifier(const CBlockIndex* pindex, uint64_t& nStakeModifier, int64_t& nModifierTime)
{
    AssertLockHeld(::cs_main);
    if (!pindex)
        return false; // error("GetLastStakeModifier: null pindex");
    while (pindex && pindex->pprev && !pindex->GeneratedStakeModifier())
        pindex = pindex->pprev;
    if (!pindex->GeneratedStakeModifier()) {
        nStakeModifier = 1;
        nModifierTime = pindex->GetBlockTime();
    } else {
        nStakeModifier = pindex->nStakeModifier;
        nModifierTime = pindex->GetBlockTime();
    }
    return true;
}

// Get selection interval section (in seconds)
int64_t GetStakeModifierSelectionIntervalSection(int nSection, const Consensus::Params& params)
{
    assert(nSection >= 0 && nSection < 64);
    return (params.nModifierInterval * 63 / (63 + ((63 - nSection) * (MODIFIER_INTERVAL_RATIO - 1))));
}

// Get stake modifier selection interval (in seconds)
int64_t GetStakeModifierSelectionInterval(const Consensus::Params& params)
{
    int64_t nSelectionInterval = 0;
    for (int nSection = 0; nSection < 64; nSection++)
        nSelectionInterval += GetStakeModifierSelectionIntervalSection(nSection, params);
    return nSelectionInterval;
}

std::vector<unsigned char> CalculateSetMemProofRandomness(const CBlockIndex* pindexPrev)
{
    HashWriter ss{};

    ss << pindexPrev->GetBlockHash() << pindexPrev->nStakeModifier;

    auto hash = ss.GetHash();

    return std::vector<unsigned char>(hash.begin(), hash.end());
}

std::vector<unsigned char> CalculateSetMemProofRandomnessV2(const CBlockIndex* pindexPrev, const CBlock& block)
{
    // Bind the block body into the set-membership Fiat-Shamir challenge so the
    // proof is a signature over block contents: mutating any transaction
    // changes eta_fiat_shamir, which the FS transcript consumes, so the proof
    // no longer verifies. This restores the anti-malleability property that the
    // legacy eta_phi(vtx) generator seed provided — but here it feeds ONLY the
    // challenge, not phi / the kernel hash, so it grants no grinding leverage
    // over eligibility. Still binds pindexPrev so cross-height replay is blocked.
    HashWriter ss{};

    ss << pindexPrev->GetBlockHash() << pindexPrev->nStakeModifier << TX_NO_WITNESS(block.vtx);

    auto hash = ss.GetHash();

    return std::vector<unsigned char>(hash.begin(), hash.end());
}

std::vector<unsigned char> CalculateSetMemProofRandomness(const CBlockIndex* pindexPrev, const CBlock& block, const Consensus::Params& params)
{
    const int height = pindexPrev->nHeight + 1;
    if (height >= params.nPoPSKernelV2Height) {
        return CalculateSetMemProofRandomnessV2(pindexPrev, block);
    }
    return CalculateSetMemProofRandomness(pindexPrev);
}

uint256 CalculateStakeRingSeed(const CBlockIndex* pindexPrev, const uint256& header_hash_fallback, const uint32_t& block_time, const Consensus::Params& params)
{
    const int height = pindexPrev->nHeight + 1;
    if (height < params.nPoPSKernelV2Height) {
        // Legacy: grindable header-hash seed (kept for pre-V2 blocks).
        return header_hash_fallback;
    }

    // V2 ring seed = H(stakeModifier, deep-ancestor hash, BucketTime(block_time)).
    //
    // Anti-grind: the stake modifier changes only once per nModifierInterval
    // (aggregating 64 historical blocks) and the deep ancestor (POPS_RING_SEED_
    // LOOKBACK back) is long-buried, so the producer of the previous block
    // cannot freely choose the next ring — biasing it needs long-range control
    // of a whole interval AND the deep anchor.
    //
    // Liveness: the bucketed block time advances with the wall clock, so the
    // ring re-samples every POPS_TIME_GRANULARITY_SECONDS. If every currently-
    // sampled staker is offline, real time rotates the ring until an online
    // staker's commitment is included, so the chain self-heals instead of
    // stalling. The grind this reintroduces is bounded to the few future
    // buckets allowed by POPS_MAX_FUTURE_BLOCK_TIME (the same bound the kernel
    // already lives under), not the old unbounded header grind.
    // Walk back POPS_RING_SEED_LOOKBACK blocks to the deep anchor. Do NOT use
    // CBlockIndex::GetAncestor here: it assert()s if the pprev chain is shorter
    // than the requested height (e.g. a standalone index in unit tests, or any
    // index whose ancestry is not fully linked). Walk pprev manually instead,
    // stopping at the deepest reachable ancestor (genesis on a real chain).
    // Deterministic for prover and verifier: both see the same linked chain.
    const CBlockIndex* anchor = pindexPrev;
    for (int i = 0; i < POPS_RING_SEED_LOOKBACK && anchor->pprev != nullptr; ++i) {
        anchor = anchor->pprev;
    }

    const uint32_t bucketed_time = block_time - (block_time % POPS_TIME_GRANULARITY_SECONDS);

    HashWriter ss{};
    ss << pindexPrev->nStakeModifier
       << anchor->GetBlockHash()
       << bucketed_time;
    return ss.GetHash();
}


blsct::Message
CalculateSetMemProofGeneratorSeed(const CBlockIndex* pindexPrev, const CBlock& block)
{
    HashWriter ss{};

    ss << pindexPrev->nHeight << pindexPrev->nStakeModifier << TX_NO_WITNESS(block.vtx);

    auto hash = ss.GetHash();

    return std::vector<unsigned char>(hash.begin(), hash.end());
}

blsct::Message
CalculateSetMemProofGeneratorSeedV2(const CBlockIndex* pindexPrev)
{
    // Seed the set-membership generator (which builds phi = h3*f + g2*m, with
    // g2 = Derive(base_H, 0, eta_phi)) from FIXED prior chain state only. The
    // legacy seed hashed block.vtx, letting a staker grind the block contents
    // to vary eta_phi -> g2 -> phi -> kernel_hash and so multiply their staking
    // draws. Binding to pindexPrev removes that lever entirely while still
    // tying the proof to the previous block (replay across heights is also
    // blocked independently by eta_fiat_shamir / CalculateSetMemProofRandomness).
    HashWriter ss{};

    ss << pindexPrev->nHeight << pindexPrev->nStakeModifier << pindexPrev->GetBlockHash();

    auto hash = ss.GetHash();

    return std::vector<unsigned char>(hash.begin(), hash.end());
}

blsct::Message
CalculateSetMemProofGeneratorSeed(const CBlockIndex* pindexPrev, const CBlock& block, const Consensus::Params& params)
{
    const int height = pindexPrev->nHeight + 1;
    if (height >= params.nPoPSKernelV2Height) {
        return CalculateSetMemProofGeneratorSeedV2(pindexPrev);
    }
    return CalculateSetMemProofGeneratorSeed(pindexPrev, block);
}

uint256 CalculateKernelHash(const CBlockIndex* pindexPrev, const CBlock& block, const Consensus::Params& params)
{
    // When hardened, bind accumulated chain work into the kernel hash: two
    // competing forks diverge in nChainWork as soon as they split, so a
    // grinding attack that searches for favourable (prevTime, stakeModifier,
    // time) on one branch does not carry over to a parallel private branch
    // rooted at the same ancestor. When not hardened (legacy pre-hardening
    // networks, e.g. testnet with chain state predating the rule change),
    // the chain-work binding is skipped and raw block time is hashed.
    const int height = pindexPrev->nHeight + 1;
    if (height >= params.nPoPSKernelV2Height) {
        return CalculateKernelHashWithChainWork(
            pindexPrev->nTime,
            pindexPrev->nStakeModifier,
            pindexPrev->nChainWork,
            block.nTime,
            block.posProof.setMemProof.phi,
            params.fPoPSHardened);
    }

    return CalculateKernelHashWithChainWork(
        pindexPrev->nTime,
        pindexPrev->nStakeModifier,
        pindexPrev->nChainWork,
        block.nTime,
        params.fPoPSHardened);
}
} // namespace blsct