// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_BRIDGE_SPP_H
#define NAVIO_BLSCT_BRIDGE_SPP_H

#include <blsct/arith/mcl/mcl.h>
#include <blsct/common.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof.h>
#include <blsct/set_mem_proof/set_mem_proof.h>
#include <consensus/amount.h>
#include <uint256.h>

#include <optional>
#include <string>
#include <utility>
#include <vector>

// NBP stake-participation proof (SPP) — DESIGN.md §4.1, CRYPTO.md C2.
//
// A guardian proves, in zero knowledge, that it owns staked commitments in
// the current staked set whose values sum to at least its bond B, without
// revealing which coins. The construction reuses the PoPS set-membership
// proof and Bulletproofs+ range proof primitives:
//
//   * For each owned staked commitment C_i = G·v_i + H·γ_i (default-token
//     generators) the prover produces a SetMemProof that C_i ∈ stakedSet.
//     That proof's image point (tag) is
//         φ_i = G'·v_i + H'·γ_i
//     a re-blinding of the same (v_i, γ_i) under generators G',H' derived
//     from the SPP domain seed  "nbp/spp/v1" ‖ period  (distinct from the
//     PoPS kernel seed, so SPP tags are unlinkable to block-production tags).
//   * Σφ_i = G'·(Σv_i) + H'·(Σγ_i) is a Pedersen commitment to Σv_i. A
//     single Bulletproofs+ range proof over Σφ_i with min-value B proves
//     Σv_i ≥ B.
//   * Each tag φ_i is deterministic per (coin, period), so consensus rejects
//     duplicate tags within a registration period — one staked coin can back
//     at most one guardian (Sybil bound).

namespace nbp {

//! Generator/hash domain seed for a registration period. Domain-separated
//! from the PoPS kernel seed so a registration tag cannot be linked to a
//! block-production tag of the same coin (unlinkability, goal G3).
blsct::Message SppSeed(uint64_t period);

struct StakeProof {
    //! One membership proof per owned staked commitment. Each carries its
    //! own tag φ_i in `.phi`.
    std::vector<SetMemProof<Mcl>> memProofs;
    //! Per-proof Fiat–Shamir entropy (verifier must reuse the prover's).
    std::vector<Mcl::Scalar> etaFiatShamir;
    //! Range proof over Σφ_i (its Vs[0] equals Σφ_i) proving Σv_i ≥ bond.
    bulletproofs_plus::RangeProof<Mcl> sumProof;

    SERIALIZE_METHODS(StakeProof, obj)
    {
        READWRITE(obj.memProofs, obj.etaFiatShamir, obj.sumProof);
    }
};

//! Build an SPP proving the owned `coins` (each a (value, blinding) pair
//! whose commitment G·value + H·blinding is a member of `stakedSet`) sum to
//! at least `bond`. `stakedSet` must be the canonical ordered staked-commitment
//! set the verifier will use. Returns nullopt if Σvalue < bond.
std::optional<StakeProof> ProveStake(
    const std::vector<Mcl::Point>& stakedSet,
    const std::vector<std::pair<Mcl::Scalar, Mcl::Scalar>>& coins,
    CAmount bond,
    uint64_t period);

//! Tag hashes (SHA256 of each φ_i) without verifying the proof — used on the
//! DisconnectBlock path to erase the per-period duplicate-tag index entries.
std::vector<uint256> StakeProofTagHashes(const StakeProof& proof);

//! Verify an SPP against `stakedSet`, `bond` and `period`. On success fills
//! `outTagHashes` with SHA256 of each tag φ_i (for the consensus
//! duplicate-tag index) and returns true.
bool VerifyStakeProof(
    const std::vector<Mcl::Point>& stakedSet,
    CAmount bond,
    uint64_t period,
    const StakeProof& proof,
    std::vector<uint256>& outTagHashes,
    std::string& err);

} // namespace nbp

#endif // NAVIO_BLSCT_BRIDGE_SPP_H
