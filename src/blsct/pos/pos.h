// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLSCT_POS_H
#define BLSCT_POS_H

#include <blsct/pos/helpers.h>
#include <chain.h>

namespace node {
class BlockManager;
}

namespace blsct {
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake);
unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params);
unsigned int CalculateNextTargetRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params);
bool GetLastStakeModifier(const CBlockIndex* pindex, uint64_t& nStakeModifier, int64_t& nModifierTime) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
int64_t GetStakeModifierSelectionIntervalSection(int nSection, const Consensus::Params& params);
int64_t GetStakeModifierSelectionInterval(const Consensus::Params& params);
std::vector<unsigned char> CalculateSetMemProofRandomness(const CBlockIndex* pindexPrev);
// V2 set-mem Fiat-Shamir randomness: additionally binds the block body
// (TX_NO_WITNESS(block.vtx)) so the membership proof is a SIGNATURE over the
// block contents (mutating any tx invalidates it). This feeds only the FS
// challenge, never phi/the kernel, so it adds no grinding leverage. Replaces
// the anti-malleability role that the legacy eta_phi(vtx) seed used to play.
std::vector<unsigned char> CalculateSetMemProofRandomnessV2(const CBlockIndex* pindexPrev, const CBlock& block);
// Height-aware dispatcher: V2 variant at/after nPoPSKernelV2Height, else legacy.
std::vector<unsigned char> CalculateSetMemProofRandomness(const CBlockIndex* pindexPrev, const CBlock& block, const Consensus::Params& params);
// Legacy (V1) generator seed: hashes block.vtx, which the staker controls.
// This is GRINDABLE — varying block.vtx changes eta_phi -> g2 -> phi ->
// kernel_hash, multiplying a staker's draws. Retained only for pre-V2 blocks.
blsct::Message CalculateSetMemProofGeneratorSeed(const CBlockIndex* pindexPrev, const CBlock& block);
// V2 generator seed: derived from fixed prior chain state only (no block.vtx),
// so it cannot be ground. Mirrors CalculateSetMemProofRandomness.
blsct::Message CalculateSetMemProofGeneratorSeedV2(const CBlockIndex* pindexPrev);
// Height-aware dispatcher: V2 seed at/after nPoPSKernelV2Height, else legacy.
blsct::Message CalculateSetMemProofGeneratorSeed(const CBlockIndex* pindexPrev, const CBlock& block, const Consensus::Params& params);
uint256 CalculateKernelHash(const CBlockIndex* pindexPrev, const CBlock& block, const Consensus::Params& params);
// Seed for the staked-commitment ring shuffle. V2 derives it from the stake
// modifier plus a deep ancestor (POPS_RING_SEED_LOOKBACK back) so no single
// staker can grind which commitments form the ring; pre-V2 uses the legacy
// header-hash seed supplied by the caller. `header_hash_fallback` is the
// grindable legacy seed (block header hash) used only before V2 activation.
uint256 CalculateStakeRingSeed(const CBlockIndex* pindexPrev, const uint256& header_hash_fallback, const uint32_t& block_time, const Consensus::Params& params);
} // namespace blsct

#endif // BLSCT_POS_H