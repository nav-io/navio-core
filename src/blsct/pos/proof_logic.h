// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_POS_PROOF_LOGIC_H
#define NAVIO_BLSCT_POS_PROOF_LOGIC_H

#include <blsct/arith/blst/blst.h>
#include <blsct/pos/proof.h>
#include <blsct/set_mem_proof/set_mem_proof.h>
#include <blsct/set_mem_proof/set_mem_proof_prover.h>
#include <chain.h>
#include <coins.h>

using Arith = Blst;
using Point = Arith::Point;
using Scalar = Arith::Scalar;
using Points = Elements<Point>;
using Prover = SetMemProofProver<Arith>;

namespace blsct {
class ProofOfStakeLogic : public blsct::ProofOfStake
{
public:
    ProofOfStakeLogic(const blsct::ProofOfStake& proof) : blsct::ProofOfStake(proof){};

    static ProofOfStake Create(const CCoinsViewCache& cache, const Scalar& m, const Scalar& f, const CBlockIndex* pindexPrev, const CBlock& block, const Consensus::Params& params);
    static bool Verify(const CCoinsViewCache& cache, const CBlockIndex* pindexPrev, const CBlock& block, const Consensus::Params& params);
    static bool Verify(const CCoinsViewCache& cache, const CBlockIndex* pindexPrev, const CBlock& block, const Consensus::Params& params, const uint256& kernel_hash);
};
} // namespace blsct

#endif // NAVIO_BLSCT_POS_PROOF_LOGIC_H