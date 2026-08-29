#include <blsct/arith/blst/blst.h>
#include <blsct/arith/elements.h>
#include <blsct/building_block/weighted_inner_prod_arg.h>
#include <blsct/building_block/lazy_points.h>
#include <blsct/building_block/fiat_shamir.h>
#include <blsct/range_proof/setup.h>
#include <blsct/common.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof.h>
#include <blsct/range_proof/bulletproofs_plus/util.h>

template <typename T>
Elements<typename T::Point> WeightedInnerProdArg::ReduceGs(
    const Elements<typename T::Point>& gs1,
    const Elements<typename T::Point>& gs2,
    const typename T::Scalar& e,
    const typename T::Scalar& e_inv,
    const typename T::Scalar& y_inv_to_n
) {
    return gs1 * e_inv + gs2 * (e * y_inv_to_n);
}
template
Elements<Blst::Point> WeightedInnerProdArg::ReduceGs<Blst>(
    const Elements<Blst::Point>& gs1,
    const Elements<Blst::Point>& gs2,
    const typename Blst::Scalar& e,
    const typename Blst::Scalar& e_inv,
    const typename Blst::Scalar& y_inv_to_n
);

template <typename T>
Elements<typename T::Point> WeightedInnerProdArg::ReduceHs(
    const Elements<typename T::Point>& hs1,
    const Elements<typename T::Point>& hs2,
    const typename T::Scalar& e,
    const typename T::Scalar& e_inv
) {
    return hs1 * e + hs2 * e_inv;
}
template
Elements<Blst::Point> WeightedInnerProdArg::ReduceHs<Blst>(
    const Elements<Blst::Point>& hs1,
    const Elements<Blst::Point>& hs2,
    const typename Blst::Scalar& e,
    const typename Blst::Scalar& e_inv
);

template <typename T>
typename T::Point WeightedInnerProdArg::UpdateP(
    const typename T::Point& P,
    const typename T::Point& L,
    const typename T::Point& R,
    const typename T::Scalar& e_sq,
    const typename T::Scalar& e_inv_sq
) {
    return L * e_sq + P + R * e_inv_sq;
}
template
typename Blst::Point WeightedInnerProdArg::UpdateP<Blst>(
    const typename Blst::Point& P,
    const typename Blst::Point& L,
    const typename Blst::Point& R,
    const typename Blst::Scalar& e_sq,
    const typename Blst::Scalar& e_inv_sq
);

template <typename T>
std::optional<WeightedInnerProdArgResult<T>> WeightedInnerProdArg::Run(
    const size_t& N,
    const typename T::Scalar& y,
    Elements<typename T::Point>& gs,
    Elements<typename T::Point>& hs,
    typename T::Point& g,
    typename T::Point& h,
    typename T::Point& P,
    Elements<typename T::Scalar>& a,
    Elements<typename T::Scalar>& b,
    const typename T::Scalar& alpha_src,
    HashWriter& fiat_shamir
) {
    using Scalar = typename T::Scalar;
    using Point = typename T::Point;
    using Scalars = Elements<Scalar>;
    using Points = Elements<Point>;

    Scalar alpha = alpha_src;
    const Scalars y_inv_pows = Scalars::FirstNPow(y.Invert(), N, 1);
    size_t n = N;
    WeightedInnerProdArgResult<T> res;

    auto wip = [](
        const Scalars& a,
        const Scalars& b,
        const Scalars& y_pows
    ) -> Scalar {
        return (a * (y_pows * b)).Sum();
    };

    Scalars y_pows = bulletproofs_plus::Util<T>::GetYPows(y, n, fiat_shamir);

    while (n > 0) {
        if (n == 1) {
            Scalar r = Scalar::Rand(true);
            Scalar s = Scalar::Rand(true);
            Scalar delta = Scalar::Rand(true);
            Scalar eta = Scalar::Rand(true);

            Scalars rs = Scalars::RepeatN(r, 1);
            Scalars ss = Scalars::RepeatN(s, 1);

            {
                LazyPoints<T> lp;
                lp.Add(gs, r);
                lp.Add(hs, s);
                lp.Add(g, wip(rs, b, y_pows) + wip(ss, a, y_pows));
                lp.Add(h, delta);
                res.A = lp.Sum();
            }
            {
                LazyPoints<T> lp;
                lp.Add(g, wip(rs, ss, y_pows));
                lp.Add(h, eta);
                res.B = lp.Sum();
            }

            fiat_shamir << res.A;
            fiat_shamir << res.B;

            GEN_FIAT_SHAMIR_VAR(e, fiat_shamir, retry);
            Scalar e_sq = e.Square();

            res.r_prime = r + a[0] * e;
            res.s_prime = s + b[0] * e;
            res.delta_prime =
                eta
                + delta * e
                + alpha * e_sq
                ;
            return res;
        }

        n /= 2;

        Scalars a1 = a.To(n);
        Scalars a2 = a.From(n);
        Scalars b1 = b.To(n);
        Scalars b2 = b.From(n);
        Points gs1 = gs.To(n);
        Points gs2 = gs.From(n);
        Points hs1 = hs.To(n);
        Points hs2 = hs.From(n);

        Scalar dL = Scalar::Rand(true);
        Scalar dR = Scalar::Rand(true);

        Scalars y_pows_1 = y_pows.To(n);
        Scalars y_pows_2 = y_pows.From(n);
        Scalar cL = wip(a1, b2, y_pows_1);
        Scalar cR = wip(a2, b1, y_pows_2);

        Scalar y_to_n = y_pows_1[n - 1];
        Scalar y_inv_to_n = y_to_n.Invert();

        LazyPoints<T> lp_l;
        lp_l.Add(gs2, a1 * y_inv_to_n);
        lp_l.Add(hs1, b2);
        lp_l.Add(g, cL);
        lp_l.Add(h, dL);
        Point L = lp_l.Sum();

        LazyPoints<T> lp_r;
        lp_r.Add(gs1, a2 * y_to_n);
        lp_r.Add(hs2, b1);
        lp_r.Add(g, cR);
        lp_r.Add(h, dR);
        Point R = lp_r.Sum();

        fiat_shamir << L;
        fiat_shamir << R;
        res.Ls.Add(L);
        res.Rs.Add(R);

        GEN_FIAT_SHAMIR_VAR(e, fiat_shamir, retry);
        Scalar e_sq = e.Square();
        Scalar e_inv = e.Invert();
        Scalar e_inv_sq = e_inv.Square();

        // reduce generators and inputs for the next iteration
        P = WeightedInnerProdArg::UpdateP<T>(P, L, R, e_sq, e_inv_sq);
        a = a1 * e + a2 * (y_to_n * e_inv);
        b = b1 * e_inv + b2 * e;
        gs = WeightedInnerProdArg::ReduceGs<T>(gs1, gs2, e, e_inv, y_inv_to_n);
        hs = WeightedInnerProdArg::ReduceHs<T>(hs1, hs2, e, e_inv);
        alpha = dL * e_sq + alpha + dR * e_inv_sq;
        y_pows = y_pows_1;
    }

retry:
    return std::nullopt;
}
template
std::optional<WeightedInnerProdArgResult<Blst>> WeightedInnerProdArg::Run(
    const size_t& N,
    const typename Blst::Scalar& y,
    Elements<typename Blst::Point>& gs,
    Elements<typename Blst::Point>& hs,
    typename Blst::Point& g,
    typename Blst::Point& h,
    typename Blst::Point& P,
    Elements<typename Blst::Scalar>& a,
    Elements<typename Blst::Scalar>& b,
    const typename Blst::Scalar& alpha_src,
    HashWriter& fiat_shamir
);
