// Copyright (c) 2022 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/arith/mcl/mcl.h>
#include <blsct/range_proof/bulletproofs_plus/amount_recovery_request.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof_with_transcript.h>

namespace bulletproofs_plus {

template <typename T>
AmountRecoveryRequest<T> AmountRecoveryRequest<T>::of(const RangeProofWithSeed<T>& proof, const range_proof::GammaSeed<T>& nonce, const size_t& id)
{
    auto proof_with_transcript = RangeProofWithTranscript<T>::Build(proof);

    AmountRecoveryRequest<T> req{
        id,
        proof.seed,
        proof_with_transcript.y,
        proof_with_transcript.z,
        proof.alpha_hat,
        proof.tau_x,
        proof.Vs,
        proof.Ls,
        proof.Rs,
        proof_with_transcript.m,
        proof_with_transcript.n,
        proof_with_transcript.mn,
        nonce,
        0};
    return req;
}
template AmountRecoveryRequest<Mcl> AmountRecoveryRequest<Mcl>::of(const RangeProofWithSeed<Mcl>&, const range_proof::GammaSeed<Mcl>&, const size_t&);

} // namespace bulletproofs_plus
