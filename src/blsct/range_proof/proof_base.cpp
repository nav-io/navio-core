// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/range_proof/proof_base.h>
#include <blsct/arith/mcl/mcl.h>

namespace range_proof {

template <typename T>
bool ProofBase<T>::operator==(const ProofBase<T>& other) const
{
    return Vs == other.Vs && Ls == other.Ls && Rs == other.Rs;
}
template
bool ProofBase<Mcl>::operator==(const ProofBase<Mcl>& other) const;

template <typename T>
bool ProofBase<T>::operator!=(const ProofBase<T>& other) const
{
    return !operator==(other);
}
template
bool ProofBase<Mcl>::operator!=(const ProofBase<Mcl>& other) const;

} // namespace range_proof

// ---------------------------------------------------------------------------
// Optional supranational/blst arith backend (cmake -DWITH_BLST=ON). Mirrors
// the Mcl instantiations above 1:1; compiled out of default builds.
#ifdef NAVIO_BLSCT_ARITH_BLST
#include <blsct/arith/blst/blst.h>
namespace range_proof {
template
bool ProofBase<Blst>::operator==(const ProofBase<Blst>& other) const;
template
bool ProofBase<Blst>::operator!=(const ProofBase<Blst>& other) const;
} // namespace range_proof
#endif // NAVIO_BLSCT_ARITH_BLST
