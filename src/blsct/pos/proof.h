// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLSCT_POS_PROOF_H
#define BLSCT_POS_PROOF_H

#include <arith_uint256.h>
#include <blsct/arith/mcl/mcl.h>
#include <blsct/arith/mcl/mcl_g1point.h>
#include <blsct/pos/helpers.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof_logic.h>
#include <blsct/set_mem_proof/set_mem_proof.h>
#include <blsct/set_mem_proof/set_mem_proof_prover.h>
#include <uint256.h>

#include <chrono>
#include <span>
#include <stdexcept>

using Arith = Mcl;
using Point = Arith::Point;
using Scalar = Arith::Scalar;
using Points = Elements<Point>;
using SetProof = SetMemProof<Arith>;
using RangeProof = bulletproofs_plus::RangeProof<Arith>;

namespace blsct {
class ProofOfStake
{
public:
    struct VerificationStats {
        size_t sampled_set_size{0};
        size_t padded_set_size{0};
        std::chrono::microseconds setmem{};
        std::chrono::microseconds range{};
        std::chrono::microseconds total{};
    };

    ProofOfStake()
    {
    }

    ProofOfStake(SetProof setMemProof, RangeProof rangeProof) : setMemProof(setMemProof), rangeProof(rangeProof)
    {
    }

    ProofOfStake(const Points& staked_commitments, const Scalar& eta_fiat_shamir, const blsct::Message& eta_phi, const Scalar& m, const Scalar& f, const uint32_t& prev_time, const uint64_t& stake_modifier, const uint32_t& time, const unsigned int& next_target, bool hardened = true);

    enum VerificationResult : uint32_t {
        NONE = 0,
        VALID = 1,
        RP_INVALID = 2,
        SM_INVALID = 3,
    };

    static std::string VerificationResultToString(const VerificationResult& res)
    {
        switch (res) {
        case VALID:
            return "Valid";
            break;
        case RP_INVALID:
            return "Invalid Range Proof";
            break;
        case SM_INVALID:
            return "Invalid Set Membership Proof";
            break;
        default:
            return "None";
        }
    }

    VerificationResult
    Verify(const Points& staked_commitments, const Scalar& eta_fiat_shamir, const blsct::Message& eta_phi, const uint256& kernelHash, const unsigned int& posTarget, VerificationStats* stats = nullptr) const;
    VerificationResult Verify(const Points& staked_commitments, const Scalar& eta_fiat_shamir, const blsct::Message& eta_phi, const uint32_t& prev_time, const uint64_t& stake_modifier, const uint32_t& time, const unsigned int& next_target, VerificationStats* stats = nullptr) const;

    bool VerifySetMembership(const Points& staked_commitments, const Scalar& eta_fiat_shamir, const blsct::Message& eta_phi, VerificationStats* stats = nullptr) const;
    bulletproofs_plus::RangeProofWithSeed<Arith> GetKernelRangeProof(const uint256& kernel_hash, const unsigned int& next_target, const blsct::Message& eta_phi) const;
    bulletproofs_plus::RangeProofWithSeed<Arith> GetKernelRangeProof(const uint64_t& min_value, const blsct::Message& eta_phi) const;

    static bool VerifyKernelHash(const RangeProof& range_proof, const uint256& kernel_hash, const unsigned int& next_target, const blsct::Message& eta_phi, const Point& phi);
    static bool VerifyKernelHash(const RangeProof& range_proof, const uint64_t& min_value, const blsct::Message& eta_phi, const Point& phi);

    static uint256 CalculateMinValue(const uint256& kernel_hash, const unsigned int& next_target);
    static uint64_t SaturateToU64(const uint256& v);

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, setMemProof);
        ::Serialize(s, Using<bulletproofs_plus::RangeProofWithoutVs<Arith>>(rangeProof));
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        // Defer the per-point prime-order subgroup check for every G1 point
        // that appears in this proof; batch-check them all via a single
        // random-linear-combination multiexp after decoding. Reduces
        // ~dozens of scalar-mul-by-r calls to one.
        MclG1Point::SubgroupCheckDeferralScope deferral;
        ::Unserialize(s, setMemProof);
        ::Unserialize(s, Using<bulletproofs_plus::RangeProofWithoutVs<Arith>>(rangeProof));
        auto collected = deferral.Take();
        if (!MclG1Point::BatchCheckSubgroup(std::span<const MclG1Point>{collected.data(), collected.size()})) {
            throw std::ios_base::failure("ProofOfStake: G1 point failed subgroup check");
        }
    }

    SetProof setMemProof;
    RangeProof rangeProof;
};
} // namespace blsct

#endif // BLSCT_POS_PROOF_H
