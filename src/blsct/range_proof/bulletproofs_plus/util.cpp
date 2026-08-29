#include <blsct/range_proof/bulletproofs_plus/util.h>

namespace bulletproofs_plus {

template <typename T>
Elements<typename T::Scalar> Util<T>::GetYPows(
    const typename T::Scalar& y,
    const size_t& n,
    HashWriter& fiat_shamir
) {
    using Scalar = typename T::Scalar;
    using Scalars = Elements<Scalar>;

    fiat_shamir << "wipa v1";
    Scalars y_pows = Scalars::FirstNPow(y, n, 1);
    for (size_t i=0; i<y_pows.Size(); ++i) {
        fiat_shamir << y_pows[i];
    }

    Scalar y_pows_size(y_pows.Size());
    fiat_shamir << y_pows_size;

    return y_pows;
}
template Elements<Mcl::Scalar> Util<Mcl>::GetYPows(
    const Mcl::Scalar& y,
    const size_t& n,
    HashWriter& fiat_shamir
);

} // namespace bulletproofs_plus

// ---------------------------------------------------------------------------
// Optional supranational/blst arith backend (cmake -DWITH_BLST=ON). Mirrors
// the Mcl instantiations above 1:1; compiled out of default builds.
#ifdef NAVIO_BLSCT_ARITH_BLST
#include <blsct/arith/blst/blst.h>
namespace bulletproofs_plus {
template Elements<Blst::Scalar> Util<Blst>::GetYPows(
    const Blst::Scalar& y,
    const size_t& n,
    HashWriter& fiat_shamir
);
} // namespace bulletproofs_plus
#endif // NAVIO_BLSCT_ARITH_BLST
