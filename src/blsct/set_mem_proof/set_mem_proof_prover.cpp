// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/arith/mcl/mcl.h>
#include <blsct/building_block/fiat_shamir.h>
#include <blsct/building_block/g_h_gi_hi_zero_verifier.h>
#include <blsct/building_block/imp_inner_prod_arg.h>
#include <blsct/building_block/lazy_points.h>
#include <blsct/common.h>
#include <blsct/set_mem_proof/set_mem_proof_prover.h>
#include <crypto/common.h>
#include <hash.h>
#include <streams.h>
#include <util/strencodings.h>

#include <cmath>
#include <stdexcept>

template <typename T>
const typename SetMemProofProver<T>::Scalar& SetMemProofProver<T>::One()
{
    using Scalar = typename T::Scalar;
    static Scalar* x = nullptr;
    if (x == nullptr) {
        x = new Scalar(1);
    }
    return *x;
}
template
const typename SetMemProofProver<Mcl>::Scalar& SetMemProofProver<Mcl>::One();

template <typename T>
typename T::Scalar SetMemProofProver<T>::ComputeX(
    const SetMemProofSetup<T>& setup,
    const Scalar& omega,
    const Scalar& y,
    const Scalar& z,
    const Point& T1,
    const Point& T2
) {
    DataStream st{};
    st << omega << y << z << T1 << T2;
    auto vec = blsct::Common::DataStreamToVector(st);
    Scalar x = setup.H1(vec);
    return x;
}
template
typename Mcl::Scalar SetMemProofProver<Mcl>::ComputeX(
    const SetMemProofSetup<Mcl>& setup,
    const Scalar& omega,
    const Scalar& y,
    const Scalar& z,
    const Point& T1,
    const Point& T2
);


template <typename T>
HashWriter SetMemProofProver<T>::GenInitialFiatShamir(
    const Points& Ys,
    const Point& A1,
    const Point& A2,
    const Point& S1,
    const Point& S2,
    const Point& S3,
    const Point& phi,
    const Scalar& eta
) {
    HashWriter fiat_shamir{};
    fiat_shamir << Ys << A1 << A2 << S1 << S2 << S3 << phi << eta;
    return fiat_shamir;
}
template
HashWriter SetMemProofProver<Mcl>::GenInitialFiatShamir(
    const Points& Ys,
    const Point& A1,
    const Point& A2,
    const Point& S1,
    const Point& S2,
    const Point& S3,
    const Point& phi,
    const Scalar& eta
);

template <typename T>
typename SetMemProofProver<T>::Points SetMemProofProver<T>::ExtendYs(
    const SetMemProofSetup<T>& setup,
    const Points& Ys_src,
    const size_t& new_size
) {
    if (Ys_src.Size() > new_size) {
        throw std::runtime_error(std::string(__func__) + ": Not expecting new_size < current_size");
    }
    // Encode the padding index as a fixed 8-byte little-endian integer rather
    // than raw `size_t` bytes. sizeof(size_t) and host byte order both vary by
    // build target (8 bytes LE on the LP64 little-endian nodes that make up the
    // network, 4 bytes on ILP32, byte-swapped on big-endian), which would give
    // a different padding point on different architectures. The fixed LE-64
    // encoding is byte-for-byte identical to what LP64 LE nodes already produce.
    constexpr size_t kIndexBytes = 8;
    std::string padding_prefix = "SET_MEMBERSHIP_DUMMY";
    std::vector<uint8_t> msg(padding_prefix.begin(), padding_prefix.end());
    size_t prefix_len = msg.size();
    msg.resize(prefix_len + kIndexBytes);

    Points Ys = Ys_src;

    for (size_t i=Ys_src.Size(); i<new_size; ++i) {
        WriteLE64(&msg[prefix_len], static_cast<uint64_t>(i));
        Point padding_point = setup.H5(msg);
        Ys.Add(padding_point);
    }
    return Ys;
}
template
typename SetMemProofProver<Mcl>::Points SetMemProofProver<Mcl>::ExtendYs(
    const SetMemProofSetup<Mcl>& setup,
    const Points& Ys_src,
    const size_t& new_size
);

template <typename T>
SetMemProof<T> SetMemProofProver<T>::Prove(
    const SetMemProofSetup<T>& setup,
    const Points& Ys_src,
    const Point& sigma,
    const Scalar& m,
    const Scalar& f,
    const Scalar& eta_fiat_shamir,
    const blsct::Message& eta_phi,
    const bool transcript_v2
) {
    size_t n = blsct::Common::GetFirstPowerOf2GreaterOrEqTo(Ys_src.Size());
    if (n > setup.N) {
        throw std::runtime_error(std::string(__func__) + ": # of commitments exceeds the setup maximum");
    }
    Points Ys = ExtendYs(setup, Ys_src, n);

    // Cache Hi once: setup.hs.To(n) was previously computed three times.
    Points Hi = setup.hs.To(n);

    // Prepare Index. bL[i] = 1 if Y_i == sigma, else 0.
    // Track matches so we can exploit the sparsity of bL/bR below to avoid
    // O(n) point multiplications when computing A1 and A2.
    const Scalar scalar_zero(0);
    const Scalar scalar_one(1);
    Scalars bL;
    bL.m_vec.reserve(n);
    size_t sigma_count = 0;
    Point hi_sum_at_matches; // sum of Hi[i] over i where Y_i == sigma
    for (size_t i = 0; i < n; ++i) {
        if (Ys.m_vec[i] == sigma) {
            bL.m_vec.push_back(scalar_one);
            ++sigma_count;
            hi_sum_at_matches = hi_sum_at_matches + Hi.m_vec[i];
        } else {
            bL.m_vec.push_back(scalar_zero);
        }
    }

    // bL o bR = 0^n, bL - bR = 1^n, <bL, 1^n> = 1
    Scalars ones = Scalars::RepeatN(scalar_one, n);
    Scalars bR = bL - ones;

    // Commit 1
    Point h2 = setup.H5(Ys.GetVch());

    auto gens = setup.Gf().GetInstance(eta_phi);
    // generators are swapped to make set mem proof
    // work with proof of stake. originally in PoS paper
    // h3 = G and g2 = H
    Point g2 = gens.G;
    Point h3 = gens.H;

    // generate random scalars
    Scalar alpha = Scalar::Rand(true);
    Scalar beta = Scalar::Rand(true);
    Scalar rho = Scalar::Rand(true);
    Scalar r_alpha = Scalar::Rand(true);
    Scalar r_tau = Scalar::Rand(true);
    Scalar r_beta = Scalar::Rand(true);

    Scalars sL = Scalars::RandVec(n, true);
    Scalars sR = Scalars::RandVec(n, true);

    // (Ys * bL).Sum() == sigma * sigma_count, since bL is the indicator of
    // {i : Y_i == sigma} and every matched Y_i equals sigma. This avoids n
    // point multiplications and n point additions.
    Point ys_bL_sum;
    if (sigma_count == 1) {
        ys_bL_sum = sigma;
    } else if (sigma_count > 1) {
        ys_bL_sum = sigma * Scalar(static_cast<int64_t>(sigma_count));
    }
    Point A1 = h2 * alpha + ys_bL_sum;

    // (Hi * bR).Sum() == hi_sum_at_matches - Hi.Sum(): bR[i] = -1 except 0
    // at matched indices, so the sum collapses to a single Hi.Sum() (n
    // additions) plus the already-accumulated hi_sum_at_matches.
    Point A2 = h2 * beta + hi_sum_at_matches - Hi.Sum();

    Point S1 = h2 * r_alpha + setup.h * r_beta + setup.g * r_tau;

    // S2 originally did two independent O(n) naive scalar-mul-and-sum loops.
    // Combine them into a single 2n-element multi-scalar multiplication
    // (Pippenger via mclBnG1_mulVecMT) which is several times faster.
    LazyPoints<T> s2_terms;
    s2_terms.Add(h2, rho);
    s2_terms.Add(Ys, sL);
    s2_terms.Add(Hi, sR);
    Point S2 = s2_terms.Sum();

    Point S3 = h3 * r_tau + g2 * r_beta;

    // Set element image
    Point phi = h3 * f + g2 * m;

    // Challenge 1
    auto fiat_shamir = GenInitialFiatShamir(
        Ys, A1, A2, S1, S2, S3, phi, eta_fiat_shamir
    );

    // v2 domain separation: a context tag so this transcript cannot collide
    // with any other proof system or version. Mirror exactly in Verify.
    if (transcript_v2) {
        fiat_shamir << std::string("NAVIO_SETMEM_V2");
    }

retry: // retrying without generating fiat_shamir again to get different hashes
    GEN_FIAT_SHAMIR_VAR(y, fiat_shamir, retry);
    GEN_FIAT_SHAMIR_VAR(z, fiat_shamir, retry);
    GEN_FIAT_SHAMIR_VAR(omega, fiat_shamir, retry);

    // Commonly used constants
    Scalars y_to_n = Scalars::FirstNPow(y, n);
    Scalar z_sq = z.Square();

    // Commit 2
    Scalars l0 = bL - (ones * z);
    const Scalars& l1 = sL;
    Scalars r0 = y_to_n * (bR * omega + ones * (omega * z)) + (ones * z_sq);
    Scalars r1 = y_to_n * sR;
    Scalar t1 = (l0 * r1).Sum() + (l1 * r0).Sum();
    Scalar t2 = (l1 * r1).Sum();

    Scalar tau_1 = Scalar::Rand(true);
    Scalar tau_2 = Scalar::Rand(true);

    Point T1 = setup.g * t1 + setup.h * tau_1;
    Point T2 = setup.g * t2 + setup.h * tau_2;

    // Challenge 2
    Scalar x = ComputeX(setup, omega, y, z, T1, T2);

    // v2 binds x -- and thereby T1/T2, which x is computed over -- into the
    // transcript before c_factor and the inner-product round challenges are
    // drawn, so they can no longer be fixed independently of T1/T2. Legacy
    // ordering leaves x out of the transcript. Must mirror Verify.
    if (transcript_v2) {
        fiat_shamir << x;
    }

    // Response
    Scalar tau_x = tau_1 * x + tau_2 * x.Square();
    Scalar mu = alpha + beta * omega + rho * x;
    Scalar z_alpha = r_alpha + alpha * x;
    Scalar z_tau = r_tau + f * x;
    Scalar z_beta = r_beta + m * x;

    Scalars l = l0 + l1 * x;
    Scalars r = r0 + r1 * x;
    Scalar t = (l * r).Sum();

    // v2 also binds the prover's responses into the transcript before c_factor
    // and the inner-product round challenges are drawn, so none of them can be
    // chosen after the challenge is known. Must mirror Verify exactly: same
    // values, same order.
    if (transcript_v2) {
        fiat_shamir << t << tau_x << mu << z_alpha << z_tau << z_beta;
    }

    // Hi was already cached above (== setup.hs.To(n) and Ys.Size() == n).

    GEN_FIAT_SHAMIR_VAR(c_factor, fiat_shamir, retry);

    auto iipa_res = ImpInnerProdArg::Run<T>(
        n,
        Ys, Hi, setup.g,
        l, r,
        c_factor, y,
        fiat_shamir
    );
    if (iipa_res == std::nullopt) goto retry;

    auto proof = SetMemProof<T>(
        phi, A1,
        A2, S1, S2, S3, T1, T2,
        tau_x, mu, z_alpha, z_tau, z_beta,
        t,
        iipa_res.value().Ls,
        iipa_res.value().Rs,
        iipa_res.value().a,
        iipa_res.value().b,
        omega
    );
    return proof;
}
template
SetMemProof<Mcl> SetMemProofProver<Mcl>::Prove(
    const SetMemProofSetup<Mcl>& setup,
    const Points& Ys_src,
    const Point& sigma,
    const Scalar& m,
    const Scalar& f,
    const Scalar& eta_fiat_shamir,
    const blsct::Message& eta_phi,
    const bool transcript_v2
);

template <typename T>
bool SetMemProofProver<T>::Verify(
    const SetMemProofSetup<T>& setup,
    const Points& Ys_src,
    const Scalar& eta_fiat_shamir,
    const blsct::Message& eta_phi,
    const SetMemProof<T>& proof,
    const bool transcript_v2
) {
    using LazyPoint = LazyPoint<T>;

    if (proof.Ls.Size() != proof.Rs.Size()) return false;

    size_t n = blsct::Common::GetFirstPowerOf2GreaterOrEqTo(Ys_src.Size());
    if (n > setup.N) {
        throw std::runtime_error(std::string(__func__) + ": # of commitments exceeds the setup maximum");
    }
    // The inner product argument halves the set each round, so a proof over n
    // commitments carries exactly log2(n) (L, R) pairs. Bind the proof's own
    // length to that count: the round challenges are derived over Ls.Size()
    // (ImpInnerProdArg::GenAllRoundXs) while the accumulation below reads only
    // the first num_rounds of them, and the transcript is not drawn from again
    // afterwards -- so appended pairs enter no equation, and a padded proof
    // would verify exactly like the proof it was padded from. The range proof
    // enforces the same invariant in range_proof::Common::ValidateProofsBySizes.
    const size_t num_rounds = std::log2(n);
    if (proof.Ls.Size() != num_rounds) return false;

    Points Ys = ExtendYs(setup, Ys_src, n);

    auto fiat_shamir = GenInitialFiatShamir(
        Ys, proof.A1, proof.A2, proof.S1,
        proof.S2, proof.S3, proof.phi, eta_fiat_shamir
    );

    // v2 domain separation: mirror Prove — a context tag right after the
    // initial transcript, before any challenge is drawn.
    if (transcript_v2) {
        fiat_shamir << std::string("NAVIO_SETMEM_V2");
    }

    Point h2 = setup.H5(Ys.GetVch());

    auto gens = setup.Gf().GetInstance(eta_phi);
    // generators are swapped to make set mem proof
    // work with proof of stake. originally in PoS paper
    // h3 = G and g2 = H
    Point g2 = gens.G;
    Point h3 = gens.H;

retry:
    GEN_FIAT_SHAMIR_VAR(y, fiat_shamir, retry);
    GEN_FIAT_SHAMIR_VAR(z, fiat_shamir, retry);
    GEN_FIAT_SHAMIR_VAR(omega, fiat_shamir, retry);

    // omega is a Fiat-Shamir challenge, not a prover-chosen response. It is
    // carried in the serialized proof for convenience, but the verifier
    // recomputes it from the transcript and rejects any proof whose carried
    // omega disagrees with the derived value -- otherwise a prover-supplied
    // omega would not be constrained by the transcript.
    if (proof.omega != omega) return false;

    // Note: y_inv / y_inv_to_n used to be precomputed here but were never
    // referenced; the per-iteration y_inv_pow values come from
    // ImpInnerProdArg::LoopWithYPows below. Removing them saves one scalar
    // inversion plus n-1 scalar multiplications per Verify call.
    Scalars y_to_n = Scalars::FirstNPow(y, n);
    Scalar z_sq = z.Square();
    Scalar x = ComputeX(setup, omega, y, z, proof.T1, proof.T2);

    // v2 binds x (and thereby T1/T2) and the prover's responses into the
    // transcript before c_factor and the inner-product round challenges are
    // drawn, so none can be chosen after the challenge is known. Must mirror
    // Prove exactly: same values, same order (in Prove the responses are
    // absorbed a few lines later, but nothing else touches the transcript in
    // between, so absorbing them consecutively here is transcript-identical).
    if (transcript_v2) {
        fiat_shamir << x;
        fiat_shamir << proof.t << proof.tau_x << proof.mu << proof.z_alpha << proof.z_tau << proof.z_beta;
    }

    // v2 batch-combination weights, one per verifying equation (18)-(21). The
    // four equations are folded into a single multiscalar zero check; with a
    // fixed coefficient of 1 on each, only the SUM of their generator exponents
    // is constrained, so a scalar appearing in two equations on the same
    // generator (mu in (19) and z_alpha in (20) both land on h2) is pinned only
    // through that sum and a compensating (+d, -d) pair slips through. An
    // independent weight per equation constrains each on its own. Gated with the
    // transcript: under v1 the weight is 1 (unchanged), so no historical proof
    // is invalidated; only at/above the activation height are the equations
    // weighted. The weights come from a separate domain-separated hash over the
    // whole proof, NOT the Fiat-Shamir transcript, so c_factor and the round
    // challenges are unaffected.
    auto equation_weight = [&](const uint8_t equation_index) -> Scalar {
        HashWriter hw{};
        hw << std::string("NAVIO_SET_MEM_EQ_WEIGHT_V2");
        hw << proof;
        hw << y << z << omega << x;
        hw << equation_index;
        Scalar w = hw.GetHash();
        return w == 0 ? Scalar(1) : w; // a zero weight would drop its equation
    };
    const Scalar w18 = transcript_v2 ? equation_weight(18) : Scalar(1);
    const Scalar w19 = transcript_v2 ? equation_weight(19) : Scalar(1);
    const Scalar w20 = transcript_v2 ? equation_weight(20) : Scalar(1);
    const Scalar w21 = transcript_v2 ? equation_weight(21) : Scalar(1);

    G_H_Gi_Hi_ZeroVerifier<T> verifier(n);

    //////// (18)
    {
        // g^t * h^tau_x = g^(z^2 + omega * (z-z^2)<1^n,y^n> - z^3<1^n,1^n>) * T1^x * T2^(x^2)
        // g^(t - z^2 - omega * (z-z^2)<1^n,y^n> + z^3<1^n,1^n>) * h^tau_x = T1^x * T2^(x^2)

        // LHS (each term weighted by w18)
        verifier.AddNegativeH(w18 * proof.tau_x); // LHS (18)

        // z^2 + omega * (z-z^2)<1^n,y^n> - z^3<1^n,1^n> = t0
        Scalar t0 =
            z_sq
            + proof.omega * (z - z_sq) * y_to_n.Sum()
            - z.Cube() * n; // n = <1^n, 1^n>

        // g part of LHS with t0 exp on RHS moved to LHS
        verifier.AddNegativeG(w18 * (proof.t - t0));

        // T1^x and T2^(x^2) in RHS
        verifier.AddPoint(LazyPoint(proof.T1, w18 * x));          // T1^x
        verifier.AddPoint(LazyPoint(proof.T2, w18 * x.Square())); // T2^(x^2)
    }

    //////// (19): refer to ./verifying_equations.md for the details
    {
        // Each term weighted by w19.
        verifier.AddPoint(LazyPoint(proof.A1, w19));
        verifier.AddPoint(LazyPoint(proof.A2, w19 * proof.omega));
        verifier.AddPoint(LazyPoint(proof.S2, w19 * x));
        verifier.AddPoint(LazyPoint(h2, w19 * proof.mu.Negate()));

        GEN_FIAT_SHAMIR_VAR(c_factor, fiat_shamir, retry);

        Scalars xs;
        {
            auto maybe_xs = ImpInnerProdArg::GenAllRoundXs<T>(proof.Ls, proof.Rs, fiat_shamir);
            if (!maybe_xs.has_value()) goto retry;
            xs = maybe_xs.value();
        }
        auto x_invs = xs.Invert();
        auto gen_exps = ImpInnerProdArg::GenGeneratorExponents<T>(num_rounds, xs);

        // Gi/Hi exponents are set (not accumulated) and only equation (19)
        // touches them, so applying w19 to the set value weights this equation.
        ImpInnerProdArg::LoopWithYPows<T>(n, y,
            [&](const size_t& i, const Scalar& y_pow, const Scalar& y_inv_pow) {
                verifier.SetGiExp(i, w19 * ((proof.a * gen_exps[i]).Negate() - z));
                verifier.SetHiExp(i, w19 * (
                    (proof.b * y_inv_pow * gen_exps[n - 1 - i]).Negate()
                    + (proof.omega * z * y_pow + z_sq) * y_inv_pow
                ));
            }
        );

        for (size_t i=0; i<num_rounds; ++i) {
            verifier.AddPoint(LazyPoint(proof.Ls[i], w19 * xs[i].Square()));
            verifier.AddPoint(LazyPoint(proof.Rs[i], w19 * x_invs[i].Square()));
        }

        verifier.AddPositiveG(w19 * (proof.t - proof.a * proof.b) * c_factor);
    }

    //////// (20)
    {
        // Each term weighted by w20.
        // LHS
        verifier.AddPoint(LazyPoint(h2, w20 * proof.z_alpha.Negate()));
        verifier.AddNegativeH(w20 * proof.z_beta);
        verifier.AddNegativeG(w20 * proof.z_tau);

        // RHS
        verifier.AddPoint(LazyPoint(proof.S1, w20));
        verifier.AddPoint(LazyPoint(proof.A1, w20 * x));
    }

    //////// (21)
    {
        // Each term weighted by w21.
        // LHS
        verifier.AddPoint(LazyPoint(h3, w21 * proof.z_tau.Negate()));
        verifier.AddPoint(LazyPoint(g2, w21 * proof.z_beta.Negate()));

        // RHS
        verifier.AddPoint(LazyPoint(proof.S3, w21));
        verifier.AddPoint(LazyPoint(proof.phi, w21 * x));
    }

    return verifier.Verify(setup.g, setup.h, Ys, setup.hs.To(n));
}
template
bool SetMemProofProver<Mcl>::Verify(
    const SetMemProofSetup<Mcl>& setup,
    const Points& Ys_src,
    const Scalar& eta_fiat_shamir,
    const blsct::Message& eta_phi,
    const SetMemProof<Mcl>& proof,
    const bool transcript_v2
);
