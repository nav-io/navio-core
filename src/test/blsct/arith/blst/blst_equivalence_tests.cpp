// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Cross-backend equivalence tests for the evaluation blst arith backend:
// every consensus-relevant primitive (serialization, map/hash-to-curve,
// scalar mult, MSM, subgroup check) and the full proof systems instantiated
// with Blst must agree bit-for-bit with the production Mcl backend.
// Compiled only with -DWITH_BLST=ON.

#ifdef NAVIO_BLSCT_ARITH_BLST

#include <blsct/arith/blst/blst.h>
#include <blsct/arith/mcl/mcl.h>
#include <blsct/arith/mcl/mcl_init.h>
#include <blsct/range_proof/bulletproofs_plus/amount_recovery_request.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof_logic.h>
#include <blsct/set_mem_proof/set_mem_proof_prover.h>
#include <blsct/set_mem_proof/set_mem_proof_setup.h>
#include <ctokens/tokenid.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/string.h>

#include <boost/test/unit_test.hpp>

#include <cstring>

namespace {

BlstScalar ToBlst(const MclScalar& s) { BlstScalar b; b.SetVch(s.GetVch()); return b; }
BlstG1Point ToBlst(const MclG1Point& p) { BlstG1Point b; BOOST_REQUIRE(b.SetVch(p.GetVch())); return b; }

template <typename From, typename To>
To Transcode(const From& x)
{
    DataStream ds;
    ds << x;
    To y;
    ds >> y;
    return y;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(blst_equivalence_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(scalar_ops_match_mcl)
{
    volatile MclInit init; (void)init;
    for (int i = 0; i < 100; ++i) {
        MclScalar a = MclScalar::Rand(true), b = MclScalar::Rand(true);
        BlstScalar x = ToBlst(a), y = ToBlst(b);
        BOOST_CHECK(x.GetVch() == a.GetVch());
        BOOST_CHECK((a + b).GetVch() == (x + y).GetVch());
        BOOST_CHECK((a - b).GetVch() == (x - y).GetVch());
        BOOST_CHECK((a * b).GetVch() == (x * y).GetVch());
        BOOST_CHECK((a / b).GetVch() == (x / y).GetVch());
        BOOST_CHECK(a.Invert().GetVch() == x.Invert().GetVch());
        BOOST_CHECK(a.Negate().GetVch() == x.Negate().GetVch());
        BOOST_CHECK(a.Square().GetVch() == x.Square().GetVch());
        BOOST_CHECK(a.Cube().GetVch() == x.Cube().GetVch());
        BOOST_CHECK((a >> 64).GetVch() == (x >> 64).GetVch());
        BOOST_CHECK((a << 5).GetVch() == (x << 5).GetVch());
        BOOST_CHECK((a & b).GetVch() == (x & y).GetVch());
        BOOST_CHECK((a | b).GetVch() == (x | y).GetVch());
        BOOST_CHECK((a ^ b).GetVch() == (x ^ y).GetVch());
        BOOST_CHECK((~a).GetVch() == (~x).GetVch());
        BOOST_CHECK(a.GetUint64() == x.GetUint64());
        BOOST_CHECK(a.GetString(16) == x.GetString(16));
        BOOST_CHECK(a.GetString(10) == x.GetString(10));
        BOOST_CHECK(a.GetString(2) == x.GetString(2));
        BOOST_CHECK(a.GetVch(true) == x.GetVch(true));
        BOOST_CHECK(a.Pow(MclScalar(int64_t{77})).GetVch() == x.Pow(BlstScalar(int64_t{77})).GetVch());
        BOOST_CHECK(a.GetHashWithSalt(3) == x.GetHashWithSalt(3));
        BOOST_CHECK((a < b) == (x < y));
        for (uint8_t bit : {0, 1, 7, 200, 254, 255}) BOOST_CHECK(a.GetSeriBit(bit) == x.GetSeriBit(bit));
        BOOST_CHECK(MclScalar(a.GetString(16), 16).GetVch() == BlstScalar(x.GetString(16), 16).GetVch());
        BOOST_CHECK(MclScalar(a.GetString(10), 10).GetVch() == BlstScalar(x.GetString(10), 10).GetVch());
        uint256 h = a.GetHashWithSalt(1);
        BOOST_CHECK(MclScalar(h).GetVch() == BlstScalar(h).GetVch());
        std::vector<uint8_t> msg(h.begin(), h.end());
        BOOST_CHECK(MclScalar(msg, 5).GetVch() == BlstScalar(msg, 5).GetVch());
    }
    for (int64_t n : {int64_t{0}, int64_t{1}, int64_t{-1}, int64_t{123456789}, int64_t{-987654321}, std::numeric_limits<int64_t>::max(), std::numeric_limits<int64_t>::min()}) {
        BOOST_CHECK(MclScalar(n).GetVch() == BlstScalar(n).GetVch());
    }
    MclScalar mp; mp.SetPow2(200);
    BlstScalar bp; bp.SetPow2(200);
    BOOST_CHECK(mp.GetVch() == bp.GetVch());
    BOOST_CHECK(BlstScalar().IsZero());
    BOOST_CHECK_THROW(BlstScalar().Invert(), std::runtime_error);
    // Non-canonical encodings are rejected by Unserialize in both backends.
    std::vector<uint8_t> big(32, 0xff);
    DataStream ds; ds.write(MakeByteSpan(big));
    BlstScalar bad;
    BOOST_CHECK_THROW(ds >> bad, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(point_ops_match_mcl)
{
    volatile MclInit init; (void)init;
    BOOST_CHECK(MclG1Point::GetBasePoint().GetVch() == BlstG1Point::GetBasePoint().GetVch());
    BOOST_CHECK(MclG1Point::GetBasePoint().GetString(10) == BlstG1Point::GetBasePoint().GetString(10));
    BOOST_CHECK(MclG1Point().GetVch() == BlstG1Point().GetVch());
    BOOST_CHECK(BlstG1Point().IsZero());
    for (int i = 0; i < 50; ++i) {
        MclG1Point P = MclG1Point::Rand(), Q = MclG1Point::Rand();
        MclScalar s = MclScalar::Rand(true);
        BlstG1Point A = ToBlst(P), B = ToBlst(Q);
        BlstScalar t = ToBlst(s);
        BOOST_CHECK((P + Q).GetVch() == (A + B).GetVch());
        BOOST_CHECK((P - Q).GetVch() == (A - B).GetVch());
        BOOST_CHECK((P + P).GetVch() == (A + A).GetVch());
        BOOST_CHECK(P.Double().GetVch() == A.Double().GetVch());
        BOOST_CHECK((P * s).GetVch() == (A * t).GetVch());
        BOOST_CHECK((P - P).IsZero() && (A - A).IsZero());
        BOOST_CHECK(P.GetString(16) == A.GetString(16));
        BOOST_CHECK(P.GetHashWithSalt(9).GetVch() == A.GetHashWithSalt(9).GetVch());
        BOOST_CHECK(A.IsValid());
        BlstG1Point S; S.SetString(P.GetString(16));
        BOOST_CHECK(S == A);
        BOOST_CHECK((P < Q) == (A < B));
        uint256 h = s.GetHashWithSalt(0);
        BOOST_CHECK(MclG1Point(h).GetVch() == BlstG1Point(h).GetVch());
        std::vector<uint8_t> msg(h.begin(), h.end());
        BOOST_CHECK(MclG1Point::MapToPoint(msg, Endianness::Little).GetVch() == BlstG1Point::MapToPoint(msg, Endianness::Little).GetVch());
        BOOST_CHECK(MclG1Point::MapToPoint(msg, Endianness::Big).GetVch() == BlstG1Point::MapToPoint(msg, Endianness::Big).GetVch());
        BOOST_CHECK(MclG1Point::HashAndMap(msg).GetVch() == BlstG1Point::HashAndMap(msg).GetVch());
        std::vector<uint8_t> longmsg(msg); longmsg.insert(longmsg.end(), msg.begin(), msg.end()); longmsg.resize(64, 0x5a); // mcl's Fp setXxxEndianMod caps input at 64 bytes
        BOOST_CHECK(MclG1Point::MapToPoint(longmsg, Endianness::Little).GetVch() == BlstG1Point::MapToPoint(longmsg, Endianness::Little).GetVch());
        BOOST_CHECK(MclG1Point::MapToPoint(longmsg, Endianness::Big).GetVch() == BlstG1Point::MapToPoint(longmsg, Endianness::Big).GetVch());
        std::string str = "seed_" + ToString(i);
        BOOST_CHECK(MclG1Point::MapToPoint(str).GetVch() == BlstG1Point::MapToPoint(str).GetVch());
    }
}

BOOST_AUTO_TEST_CASE(decode_rejects_bad_and_off_subgroup_in_both)
{
    volatile MclInit init; (void)init;
    size_t off_subgroup_found = 0, bad_encoding_found = 0;
    for (uint32_t i = 0; i < 2000; ++i) {
        uint256 h = MclScalar(int64_t{i}).GetHashWithSalt(77);
        std::vector<uint8_t> enc(48, 0);
        std::memcpy(enc.data(), h.begin(), 32);
        std::memcpy(enc.data() + 32, h.begin(), 16);
        enc[0] = (enc[0] & 0x1f) | 0x80;
        MclG1Point m; BlstG1Point b;
        // mcl's blsInit() enables verifyOrderG1, so mcl's "unchecked" decode
        // already rejects off-subgroup points; blst's checks the curve only.
        const bool mu = m.SetVchUnchecked(enc), bu = b.SetVchUnchecked(enc);
        if (mu != bu) {
            BOOST_REQUIRE(bu && !mu);
            BOOST_REQUIRE(!blst_p1_in_g1(&b.GetUnderlying()));
        }
        if (!bu) { ++bad_encoding_found; continue; }
        if (mu) BOOST_CHECK(m.GetVch() == b.GetVch());
        MclG1Point mc; BlstG1Point bc;
        const bool mok = mc.SetVch(enc), bok = bc.SetVch(enc);
        BOOST_REQUIRE_EQUAL(mok, bok);
        if (!mok) ++off_subgroup_found;
        else BOOST_CHECK(mc.GetVch() == bc.GetVch());
    }
    BOOST_CHECK(off_subgroup_found > 0);
    BOOST_CHECK(bad_encoding_found > 0);
    BlstG1Point z;
    BOOST_CHECK(!z.SetVch(std::vector<uint8_t>(47, 0)));
    BOOST_CHECK(z.IsZero());
}

BOOST_AUTO_TEST_CASE(msm_matches_mcl_for_all_thread_counts)
{
    volatile MclInit init; (void)init;
    // n in [64,128) gets Pippenger window 5, which divides 255: the tiled
    // multi-threaded fold must carry the top signed-digit into an extra tile.
    for (size_t n : {1u, 2u, 31u, 32u, 64u, 100u, 127u, 300u, 1025u, 5000u}) {
        std::vector<LazyPoint<Mcl>> lm;
        std::vector<BlstG1Point> bp; std::vector<BlstScalar> bs;
        for (size_t i = 0; i < n; ++i) {
            MclG1Point P = MclG1Point::Rand(); MclScalar s = MclScalar::Rand(true);
            lm.emplace_back(P, s); bp.push_back(ToBlst(P)); bs.push_back(ToBlst(s));
        }
        auto expected = MclUtil::MultiplyLazyPoints(lm).GetVch();
        for (size_t threads : {1u, 2u, 3u, 8u, 12u, 64u}) {
            BOOST_CHECK_MESSAGE(BlstUtil::MSM(bp.data(), bs.data(), n, threads).GetVch() == expected,
                                "MSM mismatch n=" << n << " threads=" << threads);
        }
        BOOST_CHECK(MclG1Point::BatchCheckSubgroup(std::span<const MclG1Point>(&lm[0].m_base, 1)));
        BOOST_CHECK(BlstG1Point::BatchCheckSubgroup(std::span<const BlstG1Point>(bp)));
        std::vector<BlstG1Point> copy(bp);
        BlstG1Point::BatchNormalize(copy);
        for (size_t i = 0; i < n; ++i) BOOST_CHECK(copy[i] == bp[i]);
    }
}

BOOST_AUTO_TEST_CASE(range_proofs_cross_verify_and_recover)
{
    volatile MclInit init; (void)init;
    bulletproofs_plus::RangeProofLogic<Mcl> rpm;
    bulletproofs_plus::RangeProofLogic<Blst> rpb;
    std::vector<bulletproofs_plus::RangeProofWithSeed<Mcl>> mps;
    std::vector<bulletproofs_plus::RangeProofWithSeed<Blst>> bps;
    std::vector<MclG1Point> nonces;
    for (size_t i = 0; i < 4; ++i) {
        MclG1Point nonce = MclG1Point::Rand();
        nonces.push_back(nonce);
        std::vector<uint8_t> msg = {1, 2, 3, uint8_t(i)};
        if (i % 2 == 0) {
            Elements<MclScalar> vs; vs.Add(MclScalar(int64_t{500 + (int64_t)i}));
            auto raw = rpm.Prove(vs, range_proof::GammaSeed<Mcl>(nonce), msg, TokenId());
            mps.emplace_back(raw, TokenId(), MclScalar(int64_t{0}));
            bps.emplace_back(Transcode<bulletproofs_plus::RangeProof<Mcl>, bulletproofs_plus::RangeProof<Blst>>(raw), TokenId(), BlstScalar(int64_t{0}));
        } else {
            Elements<BlstScalar> vs; vs.Add(BlstScalar(int64_t{500 + (int64_t)i}));
            auto raw = rpb.Prove(vs, range_proof::GammaSeed<Blst>(ToBlst(nonce)), msg, TokenId());
            bps.emplace_back(raw, TokenId(), BlstScalar(int64_t{0}));
            mps.emplace_back(Transcode<bulletproofs_plus::RangeProof<Blst>, bulletproofs_plus::RangeProof<Mcl>>(raw), TokenId(), MclScalar(int64_t{0}));
        }
    }
    BOOST_CHECK(rpm.Verify(mps));
    BlstUtil::SetDefaultThreads(1);
    BOOST_CHECK(rpb.Verify(bps));
    BlstUtil::SetDefaultThreads(0);
    BOOST_CHECK(rpb.Verify(bps));
    BlstUtil::SetDefaultThreads(1);

    auto bad = bps; bad[1].r_prime = bad[1].r_prime + BlstScalar(int64_t{1});
    BOOST_CHECK(!rpb.Verify(bad));

    std::vector<bulletproofs_plus::AmountRecoveryRequest<Mcl>> rm;
    std::vector<bulletproofs_plus::AmountRecoveryRequest<Blst>> rb;
    for (size_t i = 0; i < 4; ++i) {
        rm.push_back(bulletproofs_plus::AmountRecoveryRequest<Mcl>::of(mps[i], range_proof::GammaSeed<Mcl>(nonces[i]), i));
        rb.push_back(bulletproofs_plus::AmountRecoveryRequest<Blst>::of(bps[i], range_proof::GammaSeed<Blst>(ToBlst(nonces[i])), i));
    }
    auto resm = rpm.RecoverAmounts(rm);
    auto resb = rpb.RecoverAmounts(rb);
    BOOST_REQUIRE(resm.is_completed && resb.is_completed);
    BOOST_REQUIRE_EQUAL(resm.amounts.size(), 4u);
    BOOST_REQUIRE_EQUAL(resb.amounts.size(), 4u);
    for (size_t i = 0; i < 4; ++i) {
        BOOST_CHECK_EQUAL(resm.amounts[i].amount, 500 + (int64_t)i);
        BOOST_CHECK_EQUAL(resb.amounts[i].amount, 500 + (int64_t)i);
        BOOST_CHECK(resm.amounts[i].gamma.GetVch() == resb.amounts[i].gamma.GetVch());
        BOOST_CHECK_EQUAL(resm.amounts[i].message, resb.amounts[i].message);
    }
}

BOOST_AUTO_TEST_CASE(set_mem_proofs_cross_verify)
{
    volatile MclInit init; (void)init;
    const auto& sm = SetMemProofSetup<Mcl>::Get();
    const auto& sb = SetMemProofSetup<Blst>::Get();
    BOOST_CHECK(sm.g.GetVch() == sb.g.GetVch());
    BOOST_CHECK(sm.h.GetVch() == sb.h.GetVch());
    BOOST_CHECK(sm.hs.GetVch() == sb.hs.GetVch());

    auto gm = sm.Gf().GetInstance(TokenId());
    auto gb = sb.Gf().GetInstance(TokenId());
    BOOST_CHECK(gm.G.GetVch() == gb.G.GetVch());
    BOOST_CHECK(gm.H.GetVch() == gb.H.GetVch());
    BOOST_CHECK(gm.Gi->GetVch() == gb.Gi->GetVch());
    BOOST_CHECK(gm.Hi->GetVch() == gb.Hi->GetVch());

    MclScalar m(int64_t{1000}), f = MclScalar::Rand(true), eta = MclScalar::Rand(true);
    blsct::Message eta_phi{9, 8, 7};
    MclG1Point sigma = gm.G * m + gm.H * f;
    Elements<MclG1Point> Ys; Ys.Add(sigma);
    for (size_t i = 1; i < 8; ++i) Ys.Add(MclG1Point::MapToPoint("y_" + ToString(i)));
    Elements<BlstG1Point> Yb; for (const auto& y : Ys.m_vec) Yb.Add(ToBlst(y));

    auto pm = SetMemProofProver<Mcl>::Prove(sm, Ys, sigma, m, f, eta, eta_phi);
    auto pb = SetMemProofProver<Blst>::Prove(sb, Yb, ToBlst(sigma), ToBlst(m), ToBlst(f), ToBlst(eta), eta_phi);
    BOOST_CHECK(SetMemProofProver<Mcl>::Verify(sm, Ys, eta, eta_phi, pm));
    BOOST_CHECK(SetMemProofProver<Blst>::Verify(sb, Yb, ToBlst(eta), eta_phi, pb));
    BOOST_CHECK(SetMemProofProver<Blst>::Verify(sb, Yb, ToBlst(eta), eta_phi, (Transcode<SetMemProof<Mcl>, SetMemProof<Blst>>(pm))));
    BOOST_CHECK(SetMemProofProver<Mcl>::Verify(sm, Ys, eta, eta_phi, (Transcode<SetMemProof<Blst>, SetMemProof<Mcl>>(pb))));
    // A different eta must be rejected by both.
    BOOST_CHECK(!SetMemProofProver<Blst>::Verify(sb, Yb, ToBlst(eta + MclScalar(int64_t{1})), eta_phi, pb));
    BOOST_CHECK(!SetMemProofProver<Mcl>::Verify(sm, Ys, eta + MclScalar(int64_t{1}), eta_phi, pm));
}

BOOST_AUTO_TEST_SUITE_END()

#endif // NAVIO_BLSCT_ARITH_BLST
