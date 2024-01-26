// Copyright (c) 2024 The Navcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/pos/pos.h>
#include <blsct/pos/proof_logic.h>

using Arith = Mcl;
using Point = Arith::Point;
using Scalar = Arith::Scalar;
using Points = Elements<Point>;
using Prover = SetMemProofProver<Arith>;

namespace blsct {
ProofOfStake ProofOfStakeLogic::Create(const CCoinsViewCache& cache, const CBlockIndex& pindexPrev, const Scalar& m, const Scalar& f)
{
    auto eta = blsct::CalculateSetMemProofRandomness(pindexPrev);

    auto stakedCommitments = cache.GetStakedCommitments().GetElements();

    auto proof = ProofOfStake(stakedCommitments, eta, m, f);

    return proof;
}

bool ProofOfStakeLogic::Verify(const CCoinsViewCache& cache, const CBlockIndex& pindexPrev) const
{
    auto eta = blsct::CalculateSetMemProofRandomness(pindexPrev);

    auto proof = ProofOfStake(setMemProof);
    auto stakedCommitments = cache.GetStakedCommitments().GetElements();

    auto res = proof.Verify(stakedCommitments, eta);

    return res;
}
} // namespace blsct