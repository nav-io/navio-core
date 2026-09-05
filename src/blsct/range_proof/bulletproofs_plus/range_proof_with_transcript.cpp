// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/arith/mcl/mcl_g1point.h>
#include <blsct/arith/mcl/mcl_scalar.h>
#include <blsct/arith/mcl/mcl.h>
#include <blsct/building_block/fiat_shamir.h>
#include <blsct/building_block/weighted_inner_prod_arg.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof_with_transcript.h>
#include <blsct/range_proof/bulletproofs_plus/util.h>
#include <blsct/range_proof/common.h>
#include <blsct/range_proof/setup.h>
#include <blsct/common.h>
#include <hash.h>
#include <cmath>

namespace bulletproofs_plus {

template <typename T>
RangeProofWithTranscript<T> RangeProofWithTranscript<T>::Build(const RangeProofWithSeed<T>& proof)
{
    using Scalar = typename T::Scalar;

    // build transcript in the same way the prove function builds it
    HashWriter fiat_shamir{};
    Scalars es;

    // v2 domain separation: mirror RangeProofLogic::Prove — a context tag as the
    // first absorbed item, then the generator seed and min_value.
    if (proof.transcript_v2) {
        fiat_shamir << std::string("NAVIO_BULLETPROOFS_PLUS_V2");
        fiat_shamir << static_cast<uint8_t>(proof.seed.index());
        std::visit([&](const auto& s) { fiat_shamir << s; }, proof.seed);
        fiat_shamir << proof.min_value;
    }

    size_t m = blsct::Common::GetFirstPowerOf2GreaterOrEqTo(proof.Vs.Size());
    size_t n = range_proof::Setup::num_input_value_bits;
    size_t mn = m * n;

retry:
    es.Clear();

    for (size_t i = 0; i < proof.Vs.Size(); ++i) {
        fiat_shamir << proof.Vs[i];
    }

    // v2 binds the A commitment into the transcript before the y/z challenges
    // are drawn; the legacy ordering absorbs it afterwards. This must mirror the
    // prover (RangeProofLogic::Prove) exactly. See RangeProofWithSeed::
    // transcript_v2.
    if (proof.transcript_v2) {
        fiat_shamir << proof.A;
    }

    GEN_FIAT_SHAMIR_VAR(y, fiat_shamir, retry);
    GEN_FIAT_SHAMIR_VAR(z, fiat_shamir, retry);

    if (!proof.transcript_v2) {
        fiat_shamir << proof.A;
    }

    // to update hasher to expected state. generated values are not used
    static_cast<void>(Util<T>::GetYPows(y, mn, fiat_shamir));

    auto num_rounds = range_proof::Common<T>::GetNumRoundsExclLast(proof.Vs.Size()) + 1;

    size_t i = 0;
    while (true) {
        if (i == num_rounds - 1) {
            fiat_shamir << proof.A_wip;
            fiat_shamir << proof.B;
            GEN_FIAT_SHAMIR_VAR(e_last_round, fiat_shamir, retry);

            return RangeProofWithTranscript<T>(
                proof,
                y,
                z,
                e_last_round,
                es,
                m,
                n,
                mn
            );
        }

        fiat_shamir << proof.Ls[i];
        fiat_shamir << proof.Rs[i];

        GEN_FIAT_SHAMIR_VAR(e, fiat_shamir, retry);
        es.Add(e);

        ++i;
    }
}
template RangeProofWithTranscript<Mcl> RangeProofWithTranscript<Mcl>::Build(const RangeProofWithSeed<Mcl>&);

} // namespace bulletproofs_plus

// ---------------------------------------------------------------------------
// Optional supranational/blst arith backend (cmake -DWITH_BLST=ON). Mirrors
// the Mcl instantiations above 1:1; compiled out of default builds.
#ifdef NAVIO_BLSCT_ARITH_BLST
#include <blsct/arith/blst/blst.h>
namespace bulletproofs_plus {
template RangeProofWithTranscript<Blst> RangeProofWithTranscript<Blst>::Build(const RangeProofWithSeed<Blst>&);
} // namespace bulletproofs_plus
#endif // NAVIO_BLSCT_ARITH_BLST
