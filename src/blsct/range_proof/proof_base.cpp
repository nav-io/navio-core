// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/range_proof/proof_base.h>
#include <blsct/arith/blst/blst.h>

namespace range_proof {

template <typename T>
bool ProofBase<T>::operator==(const ProofBase<T>& other) const
{
    return Vs == other.Vs && Ls == other.Ls && Rs == other.Rs;
}
template
bool ProofBase<Blst>::operator==(const ProofBase<Blst>& other) const;

template <typename T>
bool ProofBase<T>::operator!=(const ProofBase<T>& other) const
{
    return !operator==(other);
}
template
bool ProofBase<Blst>::operator!=(const ProofBase<Blst>& other) const;

} // namespace range_proof
