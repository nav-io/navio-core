// Copyright (c) 2022 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/arith/mcl/mcl.h>
#include <blsct/range_proof/bulletproofs/amount_recovery_request.h>
#include <blsct/range_proof/bulletproofs/range_proof_with_transcript.h>

namespace bulletproofs {

template <typename T>
AmountRecoveryRequest<T> AmountRecoveryRequest<T>::of(RangeProof<T>& proof, typename T::Point& nonce)
{
    auto proof_with_transcript = RangeProofWithTranscript<T>::Build(proof);

    AmountRecoveryRequest<T> req{
        1,
        proof_with_transcript.x,
        proof_with_transcript.z,
        proof.Vs,
        proof.Ls,
        proof.Rs,
        proof.mu,
        proof.tau_x,
        nonce};
    return req;
}
template AmountRecoveryRequest<Mcl> AmountRecoveryRequest<Mcl>::of(RangeProof<Mcl>&, Mcl::Point&);

} // namespace bulletproofs

