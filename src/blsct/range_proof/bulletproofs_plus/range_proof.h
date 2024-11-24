// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_RANGE_PROOF_BULLETPROOFS_PLUS_RANGE_PROOF_H
#define NAVIO_BLSCT_RANGE_PROOF_BULLETPROOFS_PLUS_RANGE_PROOF_H

#include <blsct/arith/elements.h>
#include <blsct/arith/mcl/mcl.h>
#include <blsct/arith/mcl/mcl_g1point.h>
#include <blsct/arith/mcl/mcl_scalar.h>
#include <blsct/building_block/generator_deriver.h>
#include <blsct/range_proof/proof_base.h>
#include <ctokens/tokenid.h>
#include <span.h>
#include <streams.h>

namespace bulletproofs_plus {

template <typename T>
struct RangeProof: public range_proof::ProofBase<T> {
    using Point = typename T::Point;
    using Scalar = typename T::Scalar;
    using Points = Elements<Point>;
    using Scalars = Elements<Scalar>;

    TokenId token_id;

    Point A;      // A = Gi^{aL} + Hi^{aR} + h^{alpha}; required to set up transcript
    Point A_wip;  // A in the last round of wip
    Point B;      // B in the last round of wip
    Scalar r_prime;
    Scalar s_prime;
    Scalar delta_prime;

    Scalar alpha_hat;  // used only for amount recovery

    Scalar tau_x;  // value to embed msg2

    bool operator==(const RangeProof<T>& other) const;
    bool operator!=(const RangeProof<T>& other) const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        range_proof::ProofBase<T>::Serialize(s);
        if (range_proof::ProofBase<T>::Vs.Size() > 0) {
            ::Serialize(s, A);
            ::Serialize(s, A_wip);
            ::Serialize(s, B);
            ::Serialize(s, r_prime);
            ::Serialize(s, s_prime);
            ::Serialize(s, delta_prime);
            ::Serialize(s, alpha_hat);
            ::Serialize(s, tau_x);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        range_proof::ProofBase<T>::Unserialize(s);
        if (range_proof::ProofBase<T>::Vs.Size() > 0) {
            ::Unserialize(s, A);
            ::Unserialize(s, A_wip);
            ::Unserialize(s, B);
            ::Unserialize(s, r_prime);
            ::Unserialize(s, s_prime);
            ::Unserialize(s, delta_prime);
            ::Unserialize(s, alpha_hat);
            ::Unserialize(s, tau_x);
        }
    }
};

template <typename T>
struct RangeProofWithSeed : public RangeProof<T> {
    RangeProofWithSeed(const RangeProof<T>& proof, const typename GeneratorDeriver<T>::Seed& seed, const typename T::Scalar& min_value) : RangeProof<T>(proof), seed(seed), min_value(min_value){};

    RangeProofWithSeed(const RangeProof<T>& proof, const typename GeneratorDeriver<T>::Seed& seed) : RangeProof<T>(proof), seed(seed), min_value(0){};

    RangeProofWithSeed(const RangeProof<T>& proof) : RangeProof<T>(proof), seed(TokenId()), min_value(0){};

    RangeProofWithSeed(){};

    bool operator==(const RangeProofWithSeed<T>& other) const;
    bool operator!=(const RangeProofWithSeed<T>& other) const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        RangeProof<T>::Serialize(s);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        RangeProof<T>::Unserialize(s);
    }

    // seed to derive generators
    typename GeneratorDeriver<T>::Seed seed;

    // min value for proof verification
    typename T::Scalar min_value;
};

template <typename T>
struct RangeProofWithoutVs {
    FORMATTER_METHODS(RangeProof<T>, obj)
    {
        READWRITE(Using<range_proof::ProofBaseWithoutVs<T>>(obj), obj.A, obj.A_wip, obj.B, obj.r_prime, obj.s_prime, obj.delta_prime, obj.alpha_hat, obj.tau_x);
    }
};

} // namespace bulletproofs_plus

#endif // NAVIO_BLSCT_RANGE_PROOF_BULLETPROOFS_PLUS_RANGE_PROOF_H
