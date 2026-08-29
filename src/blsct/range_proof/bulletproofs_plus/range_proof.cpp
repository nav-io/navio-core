// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/range_proof/bulletproofs_plus/range_proof.h>
#include <blsct/arith/mcl/mcl.h>

namespace bulletproofs_plus {

template <typename T>
bool RangeProof<T>::operator==(const RangeProof<T>& other) const
{
    return range_proof::ProofBase<T>::operator==(other) &&
        token_id == other.token_id &&
        A == other.A &&
        A_wip == other.A_wip &&
        B == other.B &&
        r_prime == other.r_prime &&
        s_prime == other.s_prime &&
        delta_prime == other.delta_prime &&
        alpha_hat == other.alpha_hat &&
        tau_x == other.tau_x
        ;
}
template
bool RangeProof<Mcl>::operator==(const RangeProof<Mcl>& other) const;

template <typename T>
bool RangeProof<T>::operator!=(const RangeProof<T>& other) const
{
    return !operator==(other);
}
template
bool RangeProof<Mcl>::operator!=(const RangeProof<Mcl>& other) const;

template <typename T>
bool RangeProofWithSeed<T>::operator==(const RangeProofWithSeed<T>& other) const
{
    using P = RangeProof<T>;
    auto this_parent = static_cast<const P&>(*this);
    auto other_parent = static_cast<const P&>(other);

    return this_parent == other_parent &&
           seed == other.seed;
}
template bool RangeProofWithSeed<Mcl>::operator==(const RangeProofWithSeed<Mcl>& other) const;

template <typename T>
bool RangeProofWithSeed<T>::operator!=(const RangeProofWithSeed<T>& other) const
{
    return !operator==(other);
}
template bool RangeProofWithSeed<Mcl>::operator!=(const RangeProofWithSeed<Mcl>& other) const;

} // namespace bulletproofs_plus

// ---------------------------------------------------------------------------
// Optional supranational/blst arith backend (cmake -DWITH_BLST=ON). Mirrors
// the Mcl instantiations above 1:1; compiled out of default builds.
#ifdef NAVIO_BLSCT_ARITH_BLST
#include <blsct/arith/blst/blst.h>
namespace bulletproofs_plus {
template
bool RangeProof<Blst>::operator==(const RangeProof<Blst>& other) const;
template
bool RangeProof<Blst>::operator!=(const RangeProof<Blst>& other) const;
template bool RangeProofWithSeed<Blst>::operator==(const RangeProofWithSeed<Blst>& other) const;
template bool RangeProofWithSeed<Blst>::operator!=(const RangeProofWithSeed<Blst>& other) const;
} // namespace bulletproofs_plus
#endif // NAVIO_BLSCT_ARITH_BLST
