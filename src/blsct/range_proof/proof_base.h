// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_RANGE_PROOF_PROOF_BASE_H
#define NAVIO_BLSCT_RANGE_PROOF_PROOF_BASE_H

#include <blsct/arith/elements.h>
#include <blsct/range_proof/setup.h>
#include <streams.h>

#include <bit>

namespace range_proof {

template <typename T>
struct ProofBase {
    using Point = typename T::Point;
    using Scalar = typename T::Scalar;
    using Points = Elements<Point>;

    ProofBase()= default;

    ProofBase(const Points& Vs,
              const Points& Ls,
              const Points& Rs) : Vs(Vs), Ls(Ls), Rs(Rs){};

    Points Vs;
    Points Ls;
    Points Rs;

    bool operator==(const ProofBase<T>& other) const;
    bool operator!=(const ProofBase<T>& other) const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, Vs);
        if (Vs.Size() > 0) {
            ::Serialize(s, Ls);
            ::Serialize(s, Rs);
        }
    }

    // Protocol maxima, enforced at the length prefix so an oversized or
    // inconsistent encoding is rejected before any point is decoded:
    //   - at most max_input_values value commitments,
    //   - Ls/Rs carry exactly one entry per inner-product round, of which
    //     there are at most log2(max_input_value_vec_len), and |Ls| == |Rs|.
    static constexpr uint64_t MAX_VS = range_proof::Setup::max_input_values;
    static constexpr uint64_t MAX_ROUNDS = std::bit_width(range_proof::Setup::max_input_value_vec_len) - 1;

    template <typename Stream>
    static void UnserializeLsRs(Stream& s, Points& Ls, Points& Rs)
    {
        Ls.UnserializeBounded(s, MAX_ROUNDS);
        Rs.UnserializeBounded(s, MAX_ROUNDS);
        if (Ls.Size() != Rs.Size()) {
            throw std::ios_base::failure("ProofBase: Ls/Rs size mismatch");
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        Vs.UnserializeBounded(s, MAX_VS);
        if (Vs.Size() > 0) {
            UnserializeLsRs(s, Ls, Rs);
        }
    }
};

template <typename T>
struct ProofBaseWithoutVs {
    template <typename Stream>
    void Ser(Stream& s, const ProofBase<T>& obj) const
    {
        ::Serialize(s, obj.Ls);
        ::Serialize(s, obj.Rs);
    }
    template <typename Stream>
    void Unser(Stream& s, ProofBase<T>& obj)
    {
        ProofBase<T>::UnserializeLsRs(s, obj.Ls, obj.Rs);
    }
};

} // namespace range_proof

#endif // NAVIO_BLSCT_RANGE_PROOF_PROOF_BASE_H
