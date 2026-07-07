// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/bridge/spp.h>

#include <blsct/range_proof/bulletproofs_plus/range_proof_logic.h>
#include <blsct/range_proof/generators.h>
#include <blsct/set_mem_proof/set_mem_proof_prover.h>
#include <blsct/set_mem_proof/set_mem_proof_setup.h>
#include <crypto/sha256.h>
#include <logging.h>
#include <util/strencodings.h>

#include <set>

namespace nbp {

using Arith = Mcl;
using Point = Arith::Point;
using Scalar = Arith::Scalar;
using Points = Elements<Point>;
using Scalars = Elements<Scalar>;

blsct::Message SppSeed(uint64_t period)
{
    static const std::string domain{"nbp/spp/v1"};
    blsct::Message seed(domain.begin(), domain.end());
    for (int i = 7; i >= 0; --i) {
        seed.push_back(static_cast<uint8_t>((period >> (8 * i)) & 0xff));
    }
    return seed;
}

namespace {

uint256 TagHash(const Point& phi)
{
    const auto vch = phi.GetVch();
    uint256 out;
    CSHA256().Write(vch.data(), vch.size()).Finalize(out.begin());
    return out;
}

} // namespace

std::optional<StakeProof> ProveStake(
    const std::vector<Point>& stakedSet,
    const std::vector<std::pair<Scalar, Scalar>>& coins,
    CAmount bond,
    uint64_t period)
{
    if (stakedSet.empty() || coins.empty()) return std::nullopt;

    Points ys;
    for (const auto& p : stakedSet) ys.Add(p);

    const auto& setup = SetMemProofSetup<Arith>::Get();
    const blsct::Message seed = SppSeed(period);

    range_proof::GeneratorsFactory<Arith> gf;
    range_proof::Generators<Arith> defaultGen = gf.GetInstance(TokenId());

    StakeProof proof;
    Scalar sumM;
    Scalar sumF;
    Points phis;

    for (size_t i = 0; i < coins.size(); ++i) {
        const Scalar& m = coins[i].first;  // value
        const Scalar& f = coins[i].second; // blinding
        const Point sigma = defaultGen.G * m + defaultGen.H * f;

        // Per-proof Fiat–Shamir entropy: bind to the coin's own commitment
        // and index so the k proofs differ. Any value works for soundness
        // (it only salts the transcript); the verifier reuses it verbatim.
        Scalar eta = Scalar(uint256(TagHash(sigma))).GetHashWithSalt(i);
        proof.etaFiatShamir.push_back(eta);

        SetMemProof<Arith> mp = SetMemProofProver<Arith>::Prove(setup, ys, sigma, m, f, eta, seed);
        phis.Add(mp.phi);
        proof.memProofs.push_back(std::move(mp));

        sumM = sumM + m;
        sumF = sumF + f;
    }

    // Σφ_i must equal G'·ΣM + H'·ΣF under the SPP-seed generators — which is
    // exactly the commitment Bulletproofs+ builds from (ΣM, ΣF) with the same
    // seed, so proof.sumProof.Vs[0] == Σφ_i by construction.
    range_proof::GammaSeed<Arith> gammaSeed(Scalars({sumF}));
    bulletproofs_plus::RangeProofLogic<Arith> rp;
    proof.sumProof = rp.Prove(Scalars({sumM}), gammaSeed, {}, seed, Scalar(static_cast<int64_t>(bond)));

    // Sanity: the range-proof commitment matches the summed tags.
    if (proof.sumProof.Vs.Size() != 1 || proof.sumProof.Vs[0] != phis.Sum()) {
        return std::nullopt;
    }
    return proof;
}

std::vector<uint256> StakeProofTagHashes(const StakeProof& proof)
{
    std::vector<uint256> out;
    out.reserve(proof.memProofs.size());
    for (const auto& mp : proof.memProofs) out.push_back(TagHash(mp.phi));
    return out;
}

bool VerifyStakeProof(
    const std::vector<Point>& stakedSet,
    CAmount bond,
    uint64_t period,
    const StakeProof& proof,
    std::vector<uint256>& outTagHashes,
    std::string& err)
{
    if (stakedSet.empty()) {
        err = "nbp-spp-empty-set";
        return false;
    }
    if (proof.memProofs.empty() || proof.memProofs.size() != proof.etaFiatShamir.size()) {
        err = "nbp-spp-malformed";
        return false;
    }
    if (proof.sumProof.Vs.Size() != 1) {
        err = "nbp-spp-malformed";
        return false;
    }

    Points ys;
    for (const auto& p : stakedSet) ys.Add(p);

    const auto& setup = SetMemProofSetup<Arith>::Get();
    const blsct::Message seed = SppSeed(period);

    Points phis;
    std::set<std::vector<uint8_t>> seenTags;
    outTagHashes.clear();

    for (size_t i = 0; i < proof.memProofs.size(); ++i) {
        const SetMemProof<Arith>& mp = proof.memProofs[i];
        bool ok = false;
        try {
            ok = SetMemProofProver<Arith>::Verify(setup, ys, proof.etaFiatShamir[i], seed, mp);
        } catch (const std::exception&) {
            // A malformed proof or a coin absent from the set can make the
            // membership verifier throw deep in the arithmetic; treat as
            // rejection.
            ok = false;
        }
        if (!ok) {
            err = "nbp-spp-bad-membership";
            return false;
        }
        // Reject a coin used twice within the same proof.
        const auto tagVch = mp.phi.GetVch();
        if (!seenTags.insert(tagVch).second) {
            err = "nbp-spp-dup-tag";
            return false;
        }
        phis.Add(mp.phi);
        outTagHashes.push_back(TagHash(mp.phi));
    }

    // Bind the range proof's commitment to the summed membership tags: Σφ_i
    // must equal the value the range proof is taken over.
    if (proof.sumProof.Vs[0] != phis.Sum()) {
        err = "nbp-spp-sum-mismatch";
        return false;
    }

    bulletproofs_plus::RangeProofWithSeed<Arith> withSeed(
        proof.sumProof, seed, Scalar(static_cast<int64_t>(bond)));
    bulletproofs_plus::RangeProofLogic<Arith> rp;
    try {
        if (!rp.Verify(std::vector<bulletproofs_plus::RangeProofWithSeed<Arith>>{withSeed})) {
            err = "nbp-spp-bad-range";
            return false;
        }
    } catch (const std::exception&) {
        err = "nbp-spp-bad-range";
        return false;
    }
    return true;
}

} // namespace nbp
