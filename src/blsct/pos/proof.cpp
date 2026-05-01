// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/common.h>
#include <blsct/pos/proof.h>
#include <blsct/range_proof/generators.h>
#include <util/strencodings.h>

#include <chrono>
#include <limits>

using Arith = Mcl;
using Point = Arith::Point;
using Scalar = Arith::Scalar;
using Points = Elements<Point>;
using Scalars = Elements<Scalar>;
using RangeProof = bulletproofs_plus::RangeProof<Arith>;
using RangeProver = bulletproofs_plus::RangeProofLogic<Arith>;
using SetProof = SetMemProof<Arith>;
using SetProver = SetMemProofProver<Arith>;

namespace {
bulletproofs_plus::RangeProofWithSeed<Arith> MakeKernelRangeProof(const RangeProof& range_proof, const uint64_t& min_value, const blsct::Message& eta_phi, const Point& phi)
{
    auto range_proof_with_value = range_proof;
    range_proof_with_value.Vs.Clear();
    range_proof_with_value.Vs.Add(phi);
    return bulletproofs_plus::RangeProofWithSeed<Arith>{range_proof_with_value, eta_phi, Scalar(min_value)};
}
} // namespace

namespace blsct {
ProofOfStake::ProofOfStake(const Points& staked_commitments, const Scalar& eta_fiat_shamir, const blsct::Message& eta_phi, const Scalar& m, const Scalar& f, const uint256& kernel_hash, const unsigned int& next_target)
{
    // Refuse to prove against an empty staked-commitment set. The set
    // membership proof is undefined for size 0 and `SetMemProofProver::Prove`
    // can blow up deep inside `Elements::operator[]` with an opaque
    // out-of-range exception (UINT32_MAX index, SIZE_MAX upper bound). The
    // staker observed this on testnet (147190-testnet) when its outer
    // Loop() had no exception guard and the whole process called
    // std::terminate. Surface a clear, recoverable runtime_error here so
    // callers can log and skip rather than (a) producing a meaningless
    // proof or (b) tripping a generic vector-index error users cannot
    // attribute to PoS at all. Consensus separately enforces a non-empty
    // set, so this is a strict client-side precondition, not a relaxation.
    if (staked_commitments.Size() == 0) {
        throw std::runtime_error(std::string(__func__) + ": staked_commitments must be non-empty");
    }

    range_proof::GeneratorsFactory<Mcl> gf;
    range_proof::Generators<Arith> gen = gf.GetInstance(TokenId());

    Point sigma = gen.G * m + gen.H * f;

    auto setup = SetMemProofSetup<Arith>::Get();

    setMemProof = SetProver::Prove(setup, staked_commitments, sigma, m, f, eta_fiat_shamir, eta_phi);

    uint256 min_value = CalculateMinValue(kernel_hash, next_target);
    uint64_t min_value_u64 = SaturateToU64(min_value);

    range_proof::GammaSeed<Arith> gamma_seed(Scalars({f}));
    RangeProver rp;

    rangeProof = rp.Prove(Scalars({m}), gamma_seed, {}, eta_phi, min_value_u64);

    rangeProof.Vs.Clear();
}

ProofOfStake::ProofOfStake(const Points& staked_commitments, const Scalar& eta_fiat_shamir, const blsct::Message& eta_phi, const Scalar& m, const Scalar& f, const uint32_t& prev_time, const uint64_t& stake_modifier, const uint32_t& time, const unsigned int& next_target, bool hardened)
    : ProofOfStake(staked_commitments, eta_fiat_shamir, eta_phi, m, f,
                   CalculateKernelHash(prev_time, stake_modifier, time, hardened),
                   next_target)
{
}

ProofOfStake::ProofOfStake(const Points& staked_commitments, const Scalar& eta_fiat_shamir, const blsct::Message& eta_phi, const Scalar& m, const Scalar& f, const uint32_t& prev_time, const uint64_t& stake_modifier, const arith_uint256& prev_chain_work, const uint32_t& time, const unsigned int& next_target, bool hardened)
    : ProofOfStake(staked_commitments, eta_fiat_shamir, eta_phi, m, f,
                   CalculateKernelHashWithChainWork(prev_time, stake_modifier, prev_chain_work, time, hardened),
                   next_target)
{
}

ProofOfStake::VerificationResult ProofOfStake::Verify(const Points& staked_commitments, const Scalar& eta_fiat_shamir, const blsct::Message& eta_phi, const uint32_t& prev_time, const uint64_t& stake_modifier, const uint32_t& time, const unsigned int& next_target, VerificationStats* stats) const
{
    return Verify(staked_commitments, eta_fiat_shamir, eta_phi, CalculateKernelHash(prev_time, stake_modifier, time), next_target, stats);
}

ProofOfStake::VerificationResult ProofOfStake::Verify(const Points& staked_commitments, const Scalar& eta_fiat_shamir, const blsct::Message& eta_phi, const uint256& kernel_hash, const unsigned int& next_target, VerificationStats* stats) const
{
    if (!VerifySetMembership(staked_commitments, eta_fiat_shamir, eta_phi, stats)) {
        return ProofOfStake::SM_INVALID;
    }

    using Clock = std::chrono::steady_clock;
    const auto t_after_setmem = stats ? Clock::now() : Clock::time_point{};

    // std::cout << __func__ << ": Verifying Setmem proof with"
    //           << "\n\t staked_commitments=" << staked_commitments.GetString()
    //           << "\n\t eta_fiat_shamir=" << eta_fiat_shamir.GetString()
    //           << "\n\t eta_phi=" << HexStr(eta_phi)
    //           << "\n\t setmemres=" << setmemres
    //           << "\n\n";

    auto kernelhashres = ProofOfStake::VerifyKernelHash(rangeProof, kernel_hash, next_target, eta_phi, setMemProof.phi);
    const auto t_end = stats ? Clock::now() : Clock::time_point{};
    if (stats) {
        stats->range = std::chrono::duration_cast<std::chrono::microseconds>(t_end - t_after_setmem);
        stats->total += stats->range;
    }

    if (!kernelhashres) {
        return ProofOfStake::RP_INVALID;
    }

    return ProofOfStake::VALID;
}

bool ProofOfStake::VerifySetMembership(const Points& staked_commitments, const Scalar& eta_fiat_shamir, const blsct::Message& eta_phi, VerificationStats* stats) const
{
    using Clock = std::chrono::steady_clock;
    const auto t_begin = stats ? Clock::now() : Clock::time_point{};
    const size_t sampled_set_size = staked_commitments.Size();
    const size_t padded_set_size = blsct::Common::GetFirstPowerOf2GreaterOrEqTo(sampled_set_size);
    if (stats) {
        *stats = {};
        stats->sampled_set_size = sampled_set_size;
        stats->padded_set_size = padded_set_size;
    }

    auto setup = SetMemProofSetup<Arith>::Get();
    const bool setmemres = SetProver::Verify(setup, staked_commitments, eta_fiat_shamir, eta_phi, setMemProof);

    if (stats) {
        const auto t_end = Clock::now();
        stats->setmem = std::chrono::duration_cast<std::chrono::microseconds>(t_end - t_begin);
        stats->total = stats->setmem;
    }

    return setmemres;
}

bulletproofs_plus::RangeProofWithSeed<Arith> ProofOfStake::GetKernelRangeProof(const uint256& kernel_hash, const unsigned int& next_target, const blsct::Message& eta_phi) const
{
    return GetKernelRangeProof(SaturateToU64(CalculateMinValue(kernel_hash, next_target)), eta_phi);
}

bulletproofs_plus::RangeProofWithSeed<Arith> ProofOfStake::GetKernelRangeProof(const uint64_t& min_value, const blsct::Message& eta_phi) const
{
    return MakeKernelRangeProof(rangeProof, min_value, eta_phi, setMemProof.phi);
}

bool ProofOfStake::VerifyKernelHash(const RangeProof& range_proof, const uint256& kernel_hash, const unsigned int& next_target, const blsct::Message& eta_phi, const Point& phi)
{
    auto min_value = CalculateMinValue(kernel_hash, next_target);
    uint64_t min_value_u64 = SaturateToU64(min_value);

    auto ret = VerifyKernelHash(range_proof, min_value_u64, eta_phi, phi);

    // std::cout << __func__ << ": Verifying Range proof with"
    //           << "\n\t kernel_hash=" << kernel_hash.ToString()
    //           << "\n\t next_target=" << next_target
    //           << "\n\t kernelhashres=" << ret
    //           << "\n\t min_value=" << min_value_u64
    //           << "\n\n";

    return ret;
}

bool ProofOfStake::VerifyKernelHash(const RangeProof& range_proof, const uint64_t& min_value, const blsct::Message& eta_phi, const Point& phi)
{
    RangeProver rp;
    std::vector<bulletproofs_plus::RangeProofWithSeed<Arith>> proofs;
    proofs.emplace_back(MakeKernelRangeProof(range_proof, min_value, eta_phi, phi));

    return rp.Verify(proofs);
}

uint256 ProofOfStake::CalculateMinValue(const uint256& kernel_hash, const unsigned int& next_target)
{
    if (next_target == 0) return uint256();
    return ArithToUint256(UintToArith256(kernel_hash) / arith_uint256().SetCompact(next_target));
}

// Saturate a uint256 into uint64: if any byte above the low 8 bytes is set,
// the value exceeds 2^64 - 1 and we clamp to UINT64_MAX instead of silently
// truncating. In the eligibility check this makes the range proof
// unconstructible (v < 2^64 can never satisfy v >= UINT64_MAX), which is the
// intended semantics: no representable CAmount can satisfy an impossibly tight
// target. Prior behaviour `min_value.GetUint64(0)` took the low 64 bits and
// allowed overflow to silently relax the threshold.
uint64_t ProofOfStake::SaturateToU64(const uint256& v)
{
    const unsigned char* data = v.begin();
    for (size_t i = 8; i < 32; ++i) {
        if (data[i] != 0) return std::numeric_limits<uint64_t>::max();
    }
    return v.GetUint64(0);
}
} // namespace blsct
