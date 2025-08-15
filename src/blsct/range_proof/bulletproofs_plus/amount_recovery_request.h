// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_ARITH_RANGE_PROOF_BULLETPROOFS_PLUS_AMOUNT_RECOVERY_REQUEST_H
#define NAVIO_BLSCT_ARITH_RANGE_PROOF_BULLETPROOFS_PLUS_AMOUNT_RECOVERY_REQUEST_H

#include <blsct/arith/elements.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof.h>
#include <blsct/range_proof/common.h>
#include <ctokens/tokenid.h>


namespace bulletproofs_plus {

template <typename T>
struct AmountRecoveryRequest
{
    using Scalar = typename T::Scalar;
    using Point = typename T::Point;
    using Points = Elements<Point>;

    size_t id;
    typename GeneratorDeriver<T>::Seed seed;
    Scalar y;
    Scalar z;
    Scalar alpha_hat;
    Scalar tau_x;
    Points Vs;
    Points Ls;
    Points Rs;
    size_t m;
    size_t n;
    size_t mn;
    typename range_proof::GammaSeed<T> nonce;
    Scalar min_value;

    static AmountRecoveryRequest<T> of(const RangeProofWithSeed<T>& proof,
                                       const range_proof::GammaSeed<T>& nonce,
                                       const size_t& id = 0);
};

} // namespace bulletproofs_plus

#endif // NAVIO_BLSCT_ARITH_RANGE_PROOF_BULLETPROOFS_PLUS_AMOUNT_RECOVERY_REQUEST_H