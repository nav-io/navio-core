// Copyright (c) 2022 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/arith/mcl/mcl.h>
#include <blsct/range_proof/bulletproofs_plus/amount_recovery_result.h>

namespace bulletproofs_plus {

template <typename T>
AmountRecoveryResult<T> AmountRecoveryResult<T>::failure()
{
    return {
        false,
        std::vector<range_proof::RecoveredData<T>>()
    };
}
template AmountRecoveryResult<Mcl> AmountRecoveryResult<Mcl>::failure();

} // namespace bulletproofs_plus

// ---------------------------------------------------------------------------
// Optional supranational/blst arith backend (cmake -DWITH_BLST=ON). Mirrors
// the Mcl instantiations above 1:1; compiled out of default builds.
#ifdef NAVIO_BLSCT_ARITH_BLST
#include <blsct/arith/blst/blst.h>
namespace bulletproofs_plus {
template AmountRecoveryResult<Blst> AmountRecoveryResult<Blst>::failure();
} // namespace bulletproofs_plus
#endif // NAVIO_BLSCT_ARITH_BLST
