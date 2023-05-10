// Copyright (c) 2022 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/arith/mcl/mcl_g1point.h>
#include <blsct/arith/mcl/mcl_scalar.h>
#include <blsct/arith/mcl/mcl.h>
#include <blsct/building_block/fiat_shamir.h>
#include <blsct/building_block/imp_inner_prod_arg.h>
#include <blsct/range_proof/range_proof_with_transcript.h>
#include <blsct/range_proof/range_proof_setup.h>
#include <blsct/common.h>
#include <hash.h>

template <typename T>
RangeProofWithTranscript<T> RangeProofWithTranscript<T>::Build(const RangeProof<T>& proof) {
    using Scalar = typename T::Scalar;

    // build transcript in the same way it was built in the prove function
    CHashWriter fiat_shamir(0,0);
retry:
    for (size_t i = 0; i < proof.Vs.Size(); ++i) {
        fiat_shamir << proof.Vs[i];
    }
    fiat_shamir << proof.A;
    fiat_shamir << proof.S;

    GEN_FIAT_SHAMIR_VAR(y, fiat_shamir, retry);
    GEN_FIAT_SHAMIR_VAR(z, fiat_shamir, retry);

    fiat_shamir << proof.T1;
    fiat_shamir << proof.T2;

    GEN_FIAT_SHAMIR_VAR(x, fiat_shamir, retry);

    fiat_shamir << proof.tau_x;
    fiat_shamir << proof.mu;
    fiat_shamir << proof.t_hat;

    GEN_FIAT_SHAMIR_VAR(c_factor, fiat_shamir, retry);

    auto num_rounds = RangeProofWithTranscript<T>::RecoverNumRounds(proof.Vs.Size());
    auto maybe_xs = ImpInnerProdArg::GenAllRoundXs<T>(num_rounds, proof.Ls, proof.Rs, fiat_shamir);
    if (!maybe_xs.has_value()) goto retry;

    size_t num_input_values_power_2 = blsct::Common::GetFirstPowerOf2GreaterOrEqTo(proof.Vs.Size());
    size_t concat_input_values_in_bits = num_input_values_power_2 * RangeProofSetup::m_input_value_bits;

    return RangeProofWithTranscript<T>(
        proof,
        x,
        y,
        z,
        c_factor,
        maybe_xs.value(),
        num_input_values_power_2,
        concat_input_values_in_bits
    );
}
template RangeProofWithTranscript<Mcl> RangeProofWithTranscript<Mcl>::Build(const RangeProof<Mcl>&);

template <typename T>
size_t RangeProofWithTranscript<T>::RecoverNumRounds(const size_t& num_input_values)
{
    auto num_input_values_pow2 =
        blsct::Common::GetFirstPowerOf2GreaterOrEqTo(num_input_values);
    auto num_rounds =
        ((int) std::log2(num_input_values_pow2)) +
        RangeProofSetup::m_inupt_value_bits_log2;

    return num_rounds;
}
template size_t RangeProofWithTranscript<Mcl>::RecoverNumRounds(const size_t&);