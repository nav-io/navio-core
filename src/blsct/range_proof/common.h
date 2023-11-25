// Copyright (c) 2023 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVCOIN_BLSCT_RANGE_PROOF_COMMON_H
#define NAVCOIN_BLSCT_RANGE_PROOF_COMMON_H

#include <blsct/arith/elements.h>
#include <blsct/range_proof/generators.h>
#include <blsct/range_proof/proof_base.h>
#include <ctokens/tokenid.h>
#include <vector>

namespace range_proof {

template <typename T>
class Common {
public:
    using Scalar = typename T::Scalar;
    using Point = typename T::Point;
    using Scalars = Elements<Scalar>;

    Common();

    static size_t GetNumRoundsExclLast(
        const size_t& num_input_values
    );

    static void ValidateParameters(
        const Elements<Scalar>& vs,
        const std::vector<uint8_t>& message
    );

    template <typename P>
    static void ValidateProofsBySizes(
        const std::vector<P>& proofs
    );

    const Scalar& GetUint64Max() const;

    // static Point GenerateBaseG1PointH(
    //     const Point& p,
    //     size_t index,
    //     TokenId token_id
    // );

    range_proof::GeneratorsFactory<T>& Gf() const;
    const Scalar& Zero() const;
    const Scalar& One() const;
    const Scalar& Two() const;
    const Scalars& TwoPows64() const;
    const Scalar& InnerProd1x2Pows64() const;
    const Scalar& Uint64Max() const;

private:
    static range_proof::GeneratorsFactory<T>* m_gf;

    static Scalar* m_zero;
    static Scalar* m_one;
    static Scalar* m_two;
    static Scalars* m_two_pows_64;
    static Scalar* m_inner_prod_1x2_pows_64;
    static Scalar* m_uint64_max;

    inline static std::mutex m_init_mutex;
    inline static bool m_is_initialized = false;
};

}

#endif // NAVCOIN_BLSCT_RANGE_PROOF_COMMON_H
