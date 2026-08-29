// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Head-to-head benchmark of the two BLS12-381 backends behind BLSCT:
//   herumi/mcl (+ herumi/bls, the production backend) vs supranational/blst
// (evaluation backend, cmake -DWITH_BLST=ON).
//
// Three layers, every pair measured on identical inputs:
//   1. Primitives: Fr arithmetic, G1 add/double/mul, (de)serialization,
//      subgroup check, map-to-curve, hash-to-curve (G1/G2), MSM at several
//      sizes, single + aggregate signature verification.
//   2. Navio full operations run through the *same* templated proof code
//      instantiated with each backend: Bulletproofs+ prove / verify (batch),
//      amount recovery (the wallet balance-recovery kernel: view-tag scan +
//      nonce + RecoverAmounts), PoS set-membership prove / verify.
//   3. Threading: each MSM / aggregate-verify / full op is reported single-
//      threaded and multi-threaded. mcl threads via OpenMP inside mulVecMT
//      (only in a -DWITH_MCL_OPENMP=ON build; otherwise "MT" == "ST") and via
//      std::async in navio's patched blsAggregateVerifyNoCheck. blst has no
//      built-in threading; BlstUtil::MSM tiles Pippenger windows across
//      std::threads and the aggregate verify merges per-thread pairing
//      contexts.
//
// Every fixture cross-checks the two backends bit-for-bit (serialized
// outputs, hash-to-curve, MSM, signatures, proof verdicts, recovered
// amounts) and throws on any mismatch, so a passing run doubles as a
// consensus-compatibility check of the blst backend. See
// doc/blsct-blst-evaluation.md for results and analysis.

#ifdef NAVIO_BLSCT_ARITH_BLST

#include <bench/bench.h>

#include <blsct/arith/blst/blst.h>
#include <blsct/arith/mcl/mcl.h>
#include <blsct/arith/mcl/mcl_init.h>
#include <blsct/range_proof/bulletproofs_plus/amount_recovery_request.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof_logic.h>
#include <blsct/set_mem_proof/set_mem_proof.h>
#include <blsct/set_mem_proof/set_mem_proof_prover.h>
#include <blsct/set_mem_proof/set_mem_proof_setup.h>
#include <ctokens/tokenid.h>
#include <hash.h>
#include <random.h>
#include <streams.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <blst.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

void Check(bool ok, const char* what)
{
    if (!ok) throw std::runtime_error(std::string("blst-vs-mcl cross-check failed: ") + what);
}

size_t HwThreads()
{
    size_t n = std::thread::hardware_concurrency();
    return n == 0 ? 1 : n;
}

constexpr const char* kG2Dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
constexpr size_t kMsgSize = 32;

BlstScalar ToBlst(const MclScalar& s) { BlstScalar b; b.SetVch(s.GetVch()); return b; }
BlstG1Point ToBlst(const MclG1Point& p) { BlstG1Point b; Check(b.SetVch(p.GetVch()), "point transport"); return b; }

template <typename From, typename To>
To Transcode(const From& x)
{
    DataStream ds;
    ds << x;
    To y;
    ds >> y;
    return y;
}

// Aligned storage for blst_pairing contexts.
struct PairingCtx {
    std::vector<uint64_t> buf;
    PairingCtx() : buf(blst_pairing_sizeof() / sizeof(uint64_t) + 1) {}
    blst_pairing* get() { return reinterpret_cast<blst_pairing*>(buf.data()); }
};

// ----------------------------------------------------------------------------
// Primitive fixture: the same random scalars / points in both backends.
// ----------------------------------------------------------------------------

struct PrimFixture {
    static constexpr size_t N = 1024;
    std::vector<MclScalar> ms;
    std::vector<BlstScalar> bs;
    std::vector<MclG1Point> mp;
    std::vector<BlstG1Point> bp;
    std::vector<std::vector<uint8_t>> msgs; // 32-byte messages
    std::vector<std::vector<uint8_t>> ser;  // compressed G1 encodings

    static const PrimFixture& Get()
    {
        static PrimFixture fx;
        return fx;
    }

private:
    PrimFixture()
    {
        volatile MclInit init;
        (void)init;
        ms.reserve(N); bs.reserve(N); mp.reserve(N); bp.reserve(N); msgs.reserve(N); ser.reserve(N);
        for (size_t i = 0; i < N; ++i) {
            ms.push_back(MclScalar::Rand(true));
            bs.push_back(ToBlst(ms.back()));
            // Build the points by scalar multiplication in BOTH backends so
            // both hold non-normalised Jacobian representations (transporting
            // through the wire format would hand blst affine points and make
            // serialize / add look artificially cheap).
            mp.push_back(MclG1Point::GetBasePoint() * ms.back());
            bp.push_back(BlstG1Point::GetBasePoint() * bs.back());
            Check(mp.back().GetVch() == bp.back().GetVch(), "point transport");
            std::vector<uint8_t> m(kMsgSize);
            GetRandBytes(m);
            msgs.push_back(m);
            ser.push_back(mp.back().GetVch());
        }
        CrossCheck();
    }

    void CrossCheck() const
    {
        // Base point.
        Check(MclG1Point::GetBasePoint().GetVch() == BlstG1Point::GetBasePoint().GetVch(), "G1 generator");
        Check(MclG1Point::GetBasePoint().GetString(10) == BlstG1Point::GetBasePoint().GetString(10), "G1 generator string");
        // Fr ops.
        for (size_t i = 0; i + 1 < 64; ++i) {
            const auto& a = ms[i]; const auto& b = ms[i + 1];
            const auto& x = bs[i]; const auto& y = bs[i + 1];
            Check((a + b).GetVch() == (x + y).GetVch(), "fr add");
            Check((a - b).GetVch() == (x - y).GetVch(), "fr sub");
            Check((a * b).GetVch() == (x * y).GetVch(), "fr mul");
            Check((a / b).GetVch() == (x / y).GetVch(), "fr div");
            Check(a.Invert().GetVch() == x.Invert().GetVch(), "fr inv");
            Check(a.Negate().GetVch() == x.Negate().GetVch(), "fr neg");
            Check(a.Square().GetVch() == x.Square().GetVch(), "fr sqr");
            Check((a >> 64).GetVch() == (x >> 64).GetVch(), "fr shr");
            Check((a << 3).GetVch() == (x << 3).GetVch(), "fr shl");
            Check((a & b).GetVch() == (x & y).GetVch(), "fr and");
            Check(a.GetString(16) == x.GetString(16), "fr hex string");
            Check(a.GetString(10) == x.GetString(10), "fr dec string");
            Check(a.GetUint64() == x.GetUint64(), "fr uint64");
            Check(a.Pow(MclScalar(int64_t{12345})).GetVch() == x.Pow(BlstScalar(int64_t{12345})).GetVch(), "fr pow");
            Check(MclScalar(int64_t{-7}).GetVch() == BlstScalar(int64_t{-7}).GetVch(), "fr negative int");
        }
        // G1 ops.
        for (size_t i = 0; i + 1 < 64; ++i) {
            const auto& P = mp[i]; const auto& Q = mp[i + 1];
            const auto& A = bp[i]; const auto& B = bp[i + 1];
            Check((P + Q).GetVch() == (A + B).GetVch(), "g1 add");
            Check((P - Q).GetVch() == (A - B).GetVch(), "g1 sub");
            Check(P.Double().GetVch() == A.Double().GetVch(), "g1 dbl");
            Check((P * ms[i]).GetVch() == (A * bs[i]).GetVch(), "g1 mul");
            Check(P.GetHashWithSalt(7).GetVch() == A.GetHashWithSalt(7).GetVch(), "g1 hash-with-salt");
            Check(P.GetString(16) == A.GetString(16), "g1 string");
            BlstG1Point S; S.SetString(P.GetString(16));
            Check(S == A, "g1 setstring");
        }
        // Identity encoding / decoding.
        Check(MclG1Point().GetVch() == BlstG1Point().GetVch(), "g1 identity encoding");
        {
            BlstG1Point z; Check(z.SetVch(MclG1Point().GetVch()) && z.IsZero(), "g1 identity decode");
        }
        // Map-to-curve and hash-to-curve.
        for (size_t i = 0; i < 64; ++i) {
            Check(MclG1Point::MapToPoint(msgs[i], Endianness::Little).GetVch() ==
                  BlstG1Point::MapToPoint(msgs[i], Endianness::Little).GetVch(), "map-to-G1 (LE)");
            Check(MclG1Point::MapToPoint(msgs[i], Endianness::Big).GetVch() ==
                  BlstG1Point::MapToPoint(msgs[i], Endianness::Big).GetVch(), "map-to-G1 (BE)");
            uint256 h; std::memcpy(h.begin(), msgs[i].data(), 32);
            Check(MclG1Point(h).GetVch() == BlstG1Point(h).GetVch(), "map-to-G1 (uint256)");
            Check(MclScalar(h).GetVch() == BlstScalar(h).GetVch(), "fr from uint256");
            Check(MclScalar(msgs[i], 3).GetVch() == BlstScalar(msgs[i], 3).GetVch(), "fr from msg+index");
            Check(MclG1Point::HashAndMap(msgs[i]).GetVch() == BlstG1Point::HashAndMap(msgs[i]).GetVch(), "hash-to-G1");
            // Long inputs (> 48 bytes) exercise the generic mod-p reduction.
            // (mcl's setXxxEndianMod accepts at most 64 bytes for Fp.)
            std::vector<uint8_t> longmsg(msgs[i]); longmsg.insert(longmsg.end(), msgs[(i + 1) % N].begin(), msgs[(i + 1) % N].end());
            Check(MclG1Point::MapToPoint(longmsg, Endianness::Little).GetVch() ==
                  BlstG1Point::MapToPoint(longmsg, Endianness::Little).GetVch(), "map-to-G1 (64 bytes, LE)");
            Check(MclG1Point::MapToPoint(longmsg, Endianness::Big).GetVch() ==
                  BlstG1Point::MapToPoint(longmsg, Endianness::Big).GetVch(), "map-to-G1 (64 bytes, BE)");
            // hash-to-G2 with the signature DST.
            mclBnG2 g2m; Check(mclBnG2_hashAndMapTo(&g2m, msgs[i].data(), msgs[i].size()) == 0, "mcl hash-to-G2");
            std::vector<uint8_t> g2ms(96); Check(mclBnG2_serialize(g2ms.data(), 96, &g2m) == 96, "mcl G2 serialize");
            blst_p2 g2b; blst_hash_to_g2(&g2b, msgs[i].data(), msgs[i].size(), reinterpret_cast<const byte*>(kG2Dst), std::strlen(kG2Dst), nullptr, 0);
            std::vector<uint8_t> g2bs(96); blst_p2_compress(g2bs.data(), &g2b);
            Check(g2ms == g2bs, "hash-to-G2");
        }
        // Decoding: mcl's blsInit() turns on verifyOrderG1, so
        // mclBnG1_deserialize already rejects off-subgroup points (i.e.
        // MclG1Point::SetVchUnchecked is "unchecked" in name only), while
        // blst_p1_uncompress checks the curve equation only. The subgroup-
        // checked SetVch must agree exactly; the unchecked one may only
        // differ on off-subgroup curve points, which blst then flags in
        // blst_p1_in_g1.
        {
            size_t off_subgroup = 0;
            for (size_t i = 0; i < N; ++i) {
                std::vector<uint8_t> enc = msgs[i]; enc.resize(48, 0);
                enc[0] = (enc[0] & 0x1f) | 0x80; // compressed, non-infinity, y-bit 0
                MclG1Point m; BlstG1Point b;
                const bool mu = m.SetVchUnchecked(enc);
                const bool bu = b.SetVchUnchecked(enc);
                if (mu != bu) {
                    Check(bu && !mu && !blst_p1_in_g1(&b.GetUnderlying()), "unchecked decode differs only on off-subgroup points");
                    ++off_subgroup;
                }
                MclG1Point mc; BlstG1Point bc;
                Check(mc.SetVch(enc) == bc.SetVch(enc), "subgroup-checked decode agreement");
                if (mu && bu) Check(m.GetVch() == b.GetVch(), "decoded point agreement");
            }
            Check(off_subgroup > 0, "expected to find off-subgroup curve points");
        }
        // MSM.
        // Includes sizes whose Pippenger window divides 255 (n in [64,128) ->
        // window 5), the case where the tiled MT fold needs the carry tile.
        for (size_t n : {1u, 2u, 17u, 33u, 64u, 100u, 256u, 700u, 1024u}) {
            std::vector<LazyPoint<Mcl>> lm; std::vector<LazyPoint<Blst>> lb;
            for (size_t i = 0; i < n; ++i) { lm.emplace_back(mp[i], ms[i]); lb.emplace_back(bp[i], bs[i]); }
            auto rm = MclUtil::MultiplyLazyPoints(lm).GetVch();
            Check(rm == BlstUtil::MSM(bp.data(), bs.data(), n, 1).GetVch(), "msm ST");
            for (size_t threads : {size_t{2}, size_t{3}, HwThreads(), size_t{64}}) {
                Check(rm == BlstUtil::MSM(bp.data(), bs.data(), n, threads).GetVch(), "msm MT");
            }
        }
        // Batch subgroup check + batch normalize.
        Check(MclG1Point::BatchCheckSubgroup(std::span<const MclG1Point>(mp.data(), 100)) &&
              BlstG1Point::BatchCheckSubgroup(std::span<const BlstG1Point>(bp.data(), 100)), "batch subgroup");
        {
            std::vector<BlstG1Point> copy(bp.begin(), bp.begin() + 100);
            BlstG1Point::BatchNormalize(copy);
            for (size_t i = 0; i < 100; ++i) Check(copy[i] == bp[i], "batch normalize");
        }
    }
};

// ----------------------------------------------------------------------------
// Signature fixture (min-pk: pk in G1, sig in G2, ETH DSTs), n keys/msgs.
// ----------------------------------------------------------------------------

struct SigFixture {
    size_t n;
    std::vector<blsSecretKey> sks;
    std::vector<blsPublicKey> pks;
    std::vector<blsSignature> sigs;
    blsSignature agg;
    std::vector<uint8_t> flat_msgs;
    // blst side
    std::vector<blst_scalar> bsks;
    std::vector<blst_p1_affine> bpks;
    std::vector<blst_p2_affine> bsigs;
    blst_p2_affine bagg;

    explicit SigFixture(size_t n_) : n(n_)
    {
        volatile MclInit init;
        (void)init;
        const auto& pf = PrimFixture::Get();
        sks.resize(n); pks.resize(n); sigs.resize(n); bsks.resize(n); bpks.resize(n); bsigs.resize(n);
        flat_msgs.resize(n * kMsgSize);
        blst_p2 bagg_j; std::memset(&bagg_j, 0, sizeof(bagg_j));
        for (size_t i = 0; i < n; ++i) {
            const auto& msg = pf.msgs[i % PrimFixture::N];
            std::memcpy(&flat_msgs[i * kMsgSize], msg.data(), kMsgSize);
            sks[i].v = pf.ms[i % PrimFixture::N].GetUnderlying();
            blsGetPublicKey(&pks[i], &sks[i]);
            blsSign(&sigs[i], &sks[i], msg.data(), msg.size());

            blst_scalar_from_fr(&bsks[i], &pf.bs[i % PrimFixture::N].GetUnderlying());
            blst_p1 pk; blst_sk_to_pk_in_g1(&pk, &bsks[i]); blst_p1_to_affine(&bpks[i], &pk);
            blst_p2 h, sig;
            blst_hash_to_g2(&h, msg.data(), msg.size(), reinterpret_cast<const byte*>(kG2Dst), std::strlen(kG2Dst), nullptr, 0);
            blst_sign_pk_in_g1(&sig, &h, &bsks[i]);
            blst_p2_to_affine(&bsigs[i], &sig);
            blst_p2_add_or_double(&bagg_j, &bagg_j, &sig);

            // Cross-check: identical public key and signature bytes.
            std::vector<uint8_t> mpk(48), bpk(48), msig(96), bsig(96);
            Check(mclBnG1_serialize(mpk.data(), 48, &pks[i].v) == 48, "mcl pk ser");
            blst_p1_affine_compress(bpk.data(), &bpks[i]);
            Check(mclBnG2_serialize(msig.data(), 96, &sigs[i].v) == 96, "mcl sig ser");
            blst_p2_affine_compress(bsig.data(), &bsigs[i]);
            Check(mpk == bpk, "public key bytes");
            Check(msig == bsig, "signature bytes");
        }
        blsAggregateSignature(&agg, sigs.data(), n);
        blst_p2_to_affine(&bagg, &bagg_j);
        {
            std::vector<uint8_t> ma(96), ba(96);
            Check(mclBnG2_serialize(ma.data(), 96, &agg.v) == 96, "mcl agg ser");
            blst_p2_affine_compress(ba.data(), &bagg);
            Check(ma == ba, "aggregate signature bytes");
        }
        Check(MclVerify1(0), "mcl verify1");
        Check(BlstVerify1(0), "blst verify1");
        Check(MclAggVerifyMT(), "mcl agg verify (MT)");
        Check(MclAggVerifyST(), "mcl agg verify (ST)");
        Check(BlstAggVerify(1), "blst agg verify (ST)");
        Check(BlstAggVerify(HwThreads()), "blst agg verify (MT)");
    }

    bool MclVerify1(size_t i) const
    {
        return blsVerify(&sigs[i], &pks[i], &flat_msgs[i * kMsgSize], kMsgSize) == 1;
    }
    bool BlstVerify1(size_t i) const
    {
        return blst_core_verify_pk_in_g1(&bpks[i], &bsigs[i], true, &flat_msgs[i * kMsgSize], kMsgSize,
                                         reinterpret_cast<const byte*>(kG2Dst), std::strlen(kG2Dst), nullptr, 0) == BLST_SUCCESS;
    }
    // navio's patched bls: hash-to-G2 + Miller loops fanned out over
    // std::async(hardware_concurrency) inside the library.
    bool MclAggVerifyMT() const
    {
        return blsAggregateVerifyNoCheck(&agg, pks.data(), flat_msgs.data(), kMsgSize, n) == 1;
    }
    // Same check, strictly single-threaded via the mcl C API:
    // e(-G1, agg) * prod e(pk_i, H(m_i)) == 1.
    bool MclAggVerifyST() const
    {
        std::vector<mclBnG1> g1(n + 1);
        std::vector<mclBnG2> g2(n + 1);
        for (size_t i = 0; i < n; ++i) {
            g1[i] = pks[i].v;
            if (mclBnG2_hashAndMapTo(&g2[i], &flat_msgs[i * kMsgSize], kMsgSize) != 0) return false;
        }
        mclBnG1_neg(&g1[n], &MclG1Point::GetBasePoint().GetUnderlying());
        g2[n] = agg.v;
        mclBnGT e;
        mclBn_millerLoopVec(&e, g1.data(), g2.data(), n + 1);
        mclBn_finalExp(&e, &e);
        return mclBnGT_isOne(&e) == 1;
    }
    bool BlstAggVerify(size_t threads) const
    {
        threads = std::max<size_t>(1, std::min(threads, n));
        std::vector<PairingCtx> ctxs(threads);
        std::vector<std::atomic<bool>> oks(threads);
        auto work = [&](size_t t) {
            blst_pairing* ctx = ctxs[t].get();
            blst_pairing_init(ctx, true, reinterpret_cast<const byte*>(kG2Dst), std::strlen(kG2Dst));
            bool ok = true;
            for (size_t i = t; i < n; i += threads) {
                if (blst_pairing_aggregate_pk_in_g1(ctx, &bpks[i], nullptr, &flat_msgs[i * kMsgSize], kMsgSize, nullptr, 0) != BLST_SUCCESS) { ok = false; break; }
            }
            blst_pairing_commit(ctx);
            oks[t].store(ok);
        };
        std::vector<std::thread> pool;
        for (size_t t = 1; t < threads; ++t) pool.emplace_back(work, t);
        work(0);
        for (auto& th : pool) th.join();
        for (size_t t = 0; t < threads; ++t) if (!oks[t].load()) return false;
        blst_pairing* ctx = ctxs[0].get();
        for (size_t t = 1; t < threads; ++t) {
            if (blst_pairing_merge(ctx, ctxs[t].get()) != BLST_SUCCESS) return false;
        }
        blst_fp12 gtsig;
        blst_aggregated_in_g2(&gtsig, &bagg);
        return blst_pairing_finalverify(ctx, &gtsig);
    }
};

// ----------------------------------------------------------------------------
// Range-proof fixture: proofs produced with each backend and transcoded to the
// other, so both verify the same bytes.
// ----------------------------------------------------------------------------

template <typename T>
using RP = bulletproofs_plus::RangeProofLogic<T>;
template <typename T>
using ProofWithSeed = bulletproofs_plus::RangeProofWithSeed<T>;

struct RPFixture {
    size_t n;
    std::vector<ProofWithSeed<Mcl>> mcl_proofs;
    std::vector<ProofWithSeed<Blst>> blst_proofs;
    // For amount recovery: nonce points (blindingKey * viewKey) as the wallet derives them.
    std::vector<MclG1Point> mcl_nonces;
    std::vector<BlstG1Point> blst_nonces;
    std::vector<int64_t> amounts;

    explicit RPFixture(size_t n_) : n(n_)
    {
        volatile MclInit init;
        (void)init;
        static RP<Mcl> rpm;
        static RP<Blst> rpb;
        for (size_t i = 0; i < n; ++i) {
            const int64_t amount = 1000 + static_cast<int64_t>(i);
            amounts.push_back(amount);
            MclG1Point nonce = MclG1Point::Rand();
            mcl_nonces.push_back(nonce);
            blst_nonces.push_back(ToBlst(nonce));
            std::vector<uint8_t> msg(8, static_cast<uint8_t>(i));

            // Alternate the proving backend so both provers are exercised and
            // each verifier sees proofs from the other.
            if (i % 2 == 0) {
                Elements<MclScalar> vs; vs.Add(MclScalar(amount));
                auto raw = rpm.Prove(vs, range_proof::GammaSeed<Mcl>(nonce), msg, TokenId());
                mcl_proofs.emplace_back(raw, TokenId(), MclScalar(int64_t{0}));
                blst_proofs.emplace_back(Transcode<bulletproofs_plus::RangeProof<Mcl>, bulletproofs_plus::RangeProof<Blst>>(raw), TokenId(), BlstScalar(int64_t{0}));
            } else {
                Elements<BlstScalar> vs; vs.Add(BlstScalar(amount));
                auto raw = rpb.Prove(vs, range_proof::GammaSeed<Blst>(blst_nonces.back()), msg, TokenId());
                blst_proofs.emplace_back(raw, TokenId(), BlstScalar(int64_t{0}));
                mcl_proofs.emplace_back(Transcode<bulletproofs_plus::RangeProof<Blst>, bulletproofs_plus::RangeProof<Mcl>>(raw), TokenId(), MclScalar(int64_t{0}));
            }
        }
        // Both backends accept every proof (from either prover).
        Check(rpm.Verify(mcl_proofs), "mcl verifies proofs");
        BlstUtil::SetDefaultThreads(1);
        Check(rpb.Verify(blst_proofs), "blst verifies proofs (ST)");
        BlstUtil::SetDefaultThreads(0);
        Check(rpb.Verify(blst_proofs), "blst verifies proofs (MT)");
        BlstUtil::SetDefaultThreads(1);
        // A corrupted proof is rejected by both.
        {
            auto bad_m = mcl_proofs; auto bad_b = blst_proofs;
            // (tau_x only carries the recoverable message; r_prime is checked.)
            bad_m[0].r_prime = bad_m[0].r_prime + MclScalar(int64_t{1});
            bad_b[0].r_prime = bad_b[0].r_prime + BlstScalar(int64_t{1});
            Check(!rpm.Verify(bad_m), "mcl rejects corrupted proof");
            Check(!rpb.Verify(bad_b), "blst rejects corrupted proof");
        }
        // Both recover the same amounts.
        auto rm = MclRecover(rpm);
        auto rb = BlstRecover(rpb);
        Check(rm.is_completed && rb.is_completed, "recovery completed");
        Check(rm.amounts.size() == n && rb.amounts.size() == n, "recovery count");
        for (size_t i = 0; i < n; ++i) {
            Check(rm.amounts[i].amount == amounts[i] && rb.amounts[i].amount == amounts[i], "recovered amount");
            Check(rm.amounts[i].gamma.GetVch() == rb.amounts[i].gamma.GetVch(), "recovered gamma");
            Check(rm.amounts[i].message == rb.amounts[i].message, "recovered message");
        }
    }

    bulletproofs_plus::AmountRecoveryResult<Mcl> MclRecover(RP<Mcl>& rp) const
    {
        std::vector<bulletproofs_plus::AmountRecoveryRequest<Mcl>> reqs;
        for (size_t i = 0; i < n; ++i) {
            reqs.push_back(bulletproofs_plus::AmountRecoveryRequest<Mcl>::of(mcl_proofs[i], range_proof::GammaSeed<Mcl>(mcl_nonces[i]), i));
        }
        return rp.RecoverAmounts(reqs);
    }
    bulletproofs_plus::AmountRecoveryResult<Blst> BlstRecover(RP<Blst>& rp) const
    {
        std::vector<bulletproofs_plus::AmountRecoveryRequest<Blst>> reqs;
        for (size_t i = 0; i < n; ++i) {
            reqs.push_back(bulletproofs_plus::AmountRecoveryRequest<Blst>::of(blst_proofs[i], range_proof::GammaSeed<Blst>(blst_nonces[i]), i));
        }
        return rp.RecoverAmounts(reqs);
    }
};

// ----------------------------------------------------------------------------
// Balance-recovery kernel: what the wallet does per block for every BLSCT
// output (KeyMan::RecoverOutputs): view tag = H(blindingKey * viewKey) for all
// outputs, nonce = blindingKey * viewKey for matches, then RecoverAmounts.
// ----------------------------------------------------------------------------

template <typename Point>
uint64_t ViewTagFromNonce(const Point& nonce)
{
    HashWriter hash{};
    hash << nonce;
    return (hash.GetHash().GetUint64(0) & 0xFFFF);
}

template <typename Point, typename Scalar>
std::vector<uint64_t> ViewTags(const std::vector<Point>& blinding_keys, const Scalar& view_key, size_t threads)
{
    const size_t n = blinding_keys.size();
    std::vector<uint64_t> tags(n);
    threads = std::max<size_t>(1, std::min(threads, n));
    std::atomic<size_t> next{0};
    auto worker = [&]() {
        for (;;) {
            size_t i = next.fetch_add(1, std::memory_order_relaxed);
            if (i >= n) return;
            tags[i] = ViewTagFromNonce(blinding_keys[i] * view_key);
        }
    };
    std::vector<std::thread> pool;
    for (size_t t = 1; t < threads; ++t) pool.emplace_back(worker);
    worker();
    for (auto& th : pool) th.join();
    return tags;
}

struct ScanFixture {
    size_t n_outputs;  // outputs scanned (view tags computed)
    size_t n_mine;     // of which are ours (amount recovery runs)
    MclScalar mcl_view; BlstScalar blst_view;
    std::vector<MclG1Point> mcl_blinding; std::vector<BlstG1Point> blst_blinding;
    std::vector<uint64_t> tags;
    RPFixture rp; // n_mine proofs with nonce == blinding * view

    ScanFixture(size_t outputs, size_t mine) : n_outputs(outputs), n_mine(mine), rp(mine)
    {
        volatile MclInit init;
        (void)init;
        mcl_view = MclScalar::Rand(true);
        blst_view = ToBlst(mcl_view);
        // Our outputs: blinding_i * view == the nonce the proof was built with.
        // Rebuild those nonces as R_i = nonce_i * view^-1 so R_i * view == nonce_i.
        MclScalar inv = mcl_view.Invert();
        for (size_t i = 0; i < n_outputs; ++i) {
            MclG1Point R = i < n_mine ? rp.mcl_nonces[i] * inv : MclG1Point::Rand();
            mcl_blinding.push_back(R);
            blst_blinding.push_back(ToBlst(R));
        }
        tags = ViewTags(mcl_blinding, mcl_view, 1);
        Check(tags == ViewTags(blst_blinding, blst_view, 1), "view tags");
        Check(tags == ViewTags(blst_blinding, blst_view, HwThreads()), "view tags MT");
        for (size_t i = 0; i < n_mine; ++i) {
            Check((mcl_blinding[i] * mcl_view) == rp.mcl_nonces[i], "nonce reconstruction");
        }
    }

    template <typename T>
    size_t Scan(size_t threads) const
    {
        static RP<T> rp_logic;
        const auto& blinding = [&]() -> const auto& { if constexpr (std::is_same_v<T, Mcl>) return mcl_blinding; else return blst_blinding; }();
        const auto& view = [&]() -> const auto& { if constexpr (std::is_same_v<T, Mcl>) return mcl_view; else return blst_view; }();
        const auto& proofs = [&]() -> const auto& { if constexpr (std::is_same_v<T, Mcl>) return rp.mcl_proofs; else return rp.blst_proofs; }();
        auto got = ViewTags(blinding, view, threads);
        std::vector<bulletproofs_plus::AmountRecoveryRequest<T>> reqs;
        for (size_t i = 0; i < n_outputs; ++i) {
            if (got[i] != tags[i]) continue;
            if (i >= n_mine) continue; // a decoy that happens to collide on the 16-bit tag
            typename T::Point nonce = blinding[i] * view;
            reqs.push_back(bulletproofs_plus::AmountRecoveryRequest<T>::of(proofs[i], range_proof::GammaSeed<T>(nonce), i));
        }
        auto res = rp_logic.RecoverAmounts(reqs);
        Check(res.amounts.size() == n_mine, "scan recovered all");
        return res.amounts.size();
    }
};

// ----------------------------------------------------------------------------
// PoS set-membership proof fixture (mirrors bench/blsct_setmem_verify.cpp).
// ----------------------------------------------------------------------------

template <typename T>
struct SetMemFixtureT {
    Elements<typename T::Point> Ys;
    typename T::Scalar m, f, eta_fiat_shamir;
    blsct::Message eta_phi{1, 2, 3};
    SetMemProof<T> proof;
    typename T::Point sigma;

    explicit SetMemFixtureT(size_t n)
    {
        volatile MclInit init;
        (void)init;
        const auto& setup = SetMemProofSetup<T>::Get();
        auto gen = setup.Gf().GetInstance(TokenId());
        m = typename T::Scalar(int64_t{1000});
        f = typename T::Scalar("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16);
        sigma = gen.G * m + gen.H * f;
        eta_fiat_shamir = typename T::Scalar(int64_t{4242});
        Ys.Add(sigma);
        for (size_t i = 1; i < n; ++i) {
            std::string seed = "bench_setmem_y_" + ToString(i);
            Ys.Add(T::Point::MapToPoint(seed, Endianness::Little));
        }
        proof = SetMemProofProver<T>::Prove(setup, Ys, sigma, m, f, eta_fiat_shamir, eta_phi);
    }
    bool Verify() const
    {
        return SetMemProofProver<T>::Verify(SetMemProofSetup<T>::Get(), Ys, eta_fiat_shamir, eta_phi, proof);
    }
};

struct SetMemFixture {
    SetMemFixtureT<Mcl> m;
    SetMemFixtureT<Blst> b;
    explicit SetMemFixture(size_t n) : m(n), b(n)
    {
        // Deterministic inputs -> identical setups, commitments and proofs.
        Check(m.sigma.GetVch() == b.sigma.GetVch(), "setmem sigma");
        Check(m.Ys.GetVch() == b.Ys.GetVch(), "setmem Ys");
        Check(SetMemProofSetup<Mcl>::Get().hs.GetVch() == SetMemProofSetup<Blst>::Get().hs.GetVch(), "setmem setup generators");
        // Transcode each proof to the other backend; both must verify.
        auto mb = Transcode<SetMemProof<Mcl>, SetMemProof<Blst>>(m.proof);
        auto bm = Transcode<SetMemProof<Blst>, SetMemProof<Mcl>>(b.proof);
        Check(m.Verify() && b.Verify(), "setmem self verify");
        Check(SetMemProofProver<Blst>::Verify(SetMemProofSetup<Blst>::Get(), b.Ys, b.eta_fiat_shamir, b.eta_phi, mb), "blst verifies mcl setmem proof");
        Check(SetMemProofProver<Mcl>::Verify(SetMemProofSetup<Mcl>::Get(), m.Ys, m.eta_fiat_shamir, m.eta_phi, bm), "mcl verifies blst setmem proof");
        BlstUtil::SetDefaultThreads(0);
        Check(b.Verify(), "blst setmem verify MT");
        BlstUtil::SetDefaultThreads(1);
    }
};

// ----------------------------------------------------------------------------
// Benchmarks
// ----------------------------------------------------------------------------

using benchmark::Bench;

// --- Fr ----------------------------------------------------------------------
#define FR_BENCH(NAME, MCL_EXPR, BLST_EXPR)                                                   \
    static void BLSCTCmp_##NAME##_mcl(Bench& bench)                                           \
    {                                                                                         \
        const auto& fx = PrimFixture::Get();                                                  \
        MclScalar acc = fx.ms[0];                                                             \
        size_t i = 0;                                                                         \
        bench.batch(1).unit("op").run([&] {                                                   \
            const MclScalar& a = fx.ms[i]; const MclScalar& b = fx.ms[(i + 1) % PrimFixture::N]; \
            (void)b; acc = (MCL_EXPR); i = (i + 1) % PrimFixture::N;                          \
            ankerl::nanobench::doNotOptimizeAway(acc);                                        \
        });                                                                                   \
    }                                                                                         \
    static void BLSCTCmp_##NAME##_blst(Bench& bench)                                          \
    {                                                                                         \
        const auto& fx = PrimFixture::Get();                                                  \
        BlstScalar acc = fx.bs[0];                                                            \
        size_t i = 0;                                                                         \
        bench.batch(1).unit("op").run([&] {                                                   \
            const BlstScalar& a = fx.bs[i]; const BlstScalar& b = fx.bs[(i + 1) % PrimFixture::N]; \
            (void)b; acc = (BLST_EXPR); i = (i + 1) % PrimFixture::N;                         \
            ankerl::nanobench::doNotOptimizeAway(acc);                                        \
        });                                                                                   \
    }                                                                                         \
    BENCHMARK(BLSCTCmp_##NAME##_mcl, benchmark::PriorityLevel::HIGH);                         \
    BENCHMARK(BLSCTCmp_##NAME##_blst, benchmark::PriorityLevel::HIGH);

FR_BENCH(FrAdd, a + b, a + b)
FR_BENCH(FrMul, a * b, a * b)
FR_BENCH(FrSqr, a.Square(), a.Square())
FR_BENCH(FrInv, a.Invert(), a.Invert())
FR_BENCH(FrSerialize, MclScalar(a.GetVch()), BlstScalar(a.GetVch()))

// --- G1 ----------------------------------------------------------------------
#define G1_BENCH(NAME, MCL_BODY, BLST_BODY)                                                   \
    static void BLSCTCmp_##NAME##_mcl(Bench& bench)                                           \
    {                                                                                         \
        const auto& fx = PrimFixture::Get();                                                  \
        size_t i = 0;                                                                         \
        bench.unit("op").run([&] {                                                            \
            const MclG1Point& P = fx.mp[i]; const MclG1Point& Q = fx.mp[(i + 1) % PrimFixture::N]; \
            const MclScalar& s = fx.ms[i]; (void)Q; (void)s;                                  \
            MCL_BODY; i = (i + 1) % PrimFixture::N;                                           \
        });                                                                                   \
    }                                                                                         \
    static void BLSCTCmp_##NAME##_blst(Bench& bench)                                          \
    {                                                                                         \
        const auto& fx = PrimFixture::Get();                                                  \
        size_t i = 0;                                                                         \
        bench.unit("op").run([&] {                                                            \
            const BlstG1Point& P = fx.bp[i]; const BlstG1Point& Q = fx.bp[(i + 1) % PrimFixture::N]; \
            const BlstScalar& s = fx.bs[i]; (void)Q; (void)s;                                 \
            BLST_BODY; i = (i + 1) % PrimFixture::N;                                          \
        });                                                                                   \
    }                                                                                         \
    BENCHMARK(BLSCTCmp_##NAME##_mcl, benchmark::PriorityLevel::HIGH);                         \
    BENCHMARK(BLSCTCmp_##NAME##_blst, benchmark::PriorityLevel::HIGH);

G1_BENCH(G1Add, { auto r = P + Q; ankerl::nanobench::doNotOptimizeAway(r); }, { auto r = P + Q; ankerl::nanobench::doNotOptimizeAway(r); })
G1_BENCH(G1Double, { auto r = P.Double(); ankerl::nanobench::doNotOptimizeAway(r); }, { auto r = P.Double(); ankerl::nanobench::doNotOptimizeAway(r); })
G1_BENCH(G1Mul, { auto r = P * s; ankerl::nanobench::doNotOptimizeAway(r); }, { auto r = P * s; ankerl::nanobench::doNotOptimizeAway(r); })
G1_BENCH(G1MulBase, { auto r = MclG1Point::GetBasePoint() * s; ankerl::nanobench::doNotOptimizeAway(r); }, { auto r = BlstG1Point::GetBasePoint() * s; ankerl::nanobench::doNotOptimizeAway(r); })
G1_BENCH(G1Serialize, { auto r = P.GetVch(); ankerl::nanobench::doNotOptimizeAway(r); }, { auto r = P.GetVch(); ankerl::nanobench::doNotOptimizeAway(r); })
G1_BENCH(G1DeserializeUnchecked, { MclG1Point r; bool ok = r.SetVchUnchecked(fx.ser[i]); ankerl::nanobench::doNotOptimizeAway(ok); }, { BlstG1Point r; bool ok = r.SetVchUnchecked(fx.ser[i]); ankerl::nanobench::doNotOptimizeAway(ok); })
G1_BENCH(G1DeserializeSubgroup, { MclG1Point r; bool ok = r.SetVch(fx.ser[i]); ankerl::nanobench::doNotOptimizeAway(ok); }, { BlstG1Point r; bool ok = r.SetVch(fx.ser[i]); ankerl::nanobench::doNotOptimizeAway(ok); })
G1_BENCH(G1SubgroupCheck, { int ok = mclBnG1_isValidOrder(&P.GetUnderlying()); ankerl::nanobench::doNotOptimizeAway(ok); }, { bool ok = blst_p1_in_g1(&P.GetUnderlying()); ankerl::nanobench::doNotOptimizeAway(ok); })
G1_BENCH(G1MapToPoint, { auto r = MclG1Point::MapToPoint(fx.msgs[i]); ankerl::nanobench::doNotOptimizeAway(r); }, { auto r = BlstG1Point::MapToPoint(fx.msgs[i]); ankerl::nanobench::doNotOptimizeAway(r); })
G1_BENCH(G1HashToCurve, { auto r = MclG1Point::HashAndMap(fx.msgs[i]); ankerl::nanobench::doNotOptimizeAway(r); }, { auto r = BlstG1Point::HashAndMap(fx.msgs[i]); ankerl::nanobench::doNotOptimizeAway(r); })
G1_BENCH(G2HashToCurve,
         { mclBnG2 r; mclBnG2_hashAndMapTo(&r, fx.msgs[i].data(), fx.msgs[i].size()); ankerl::nanobench::doNotOptimizeAway(r); },
         { blst_p2 r; blst_hash_to_g2(&r, fx.msgs[i].data(), fx.msgs[i].size(), reinterpret_cast<const byte*>(kG2Dst), std::strlen(kG2Dst), nullptr, 0); ankerl::nanobench::doNotOptimizeAway(r); })

// --- MSM ---------------------------------------------------------------------
static void MsmMcl(Bench& bench, size_t n, size_t cpuN)
{
    const auto& fx = PrimFixture::Get();
    std::vector<MclG1Point::Underlying> bases; std::vector<MclScalar::Underlying> exps;
    for (size_t i = 0; i < n; ++i) { bases.push_back(fx.mp[i % PrimFixture::N].GetUnderlying()); exps.push_back(fx.ms[i % PrimFixture::N].GetUnderlying()); }
    bench.unit("msm").run([&] {
        MclG1Point::Underlying r;
        // cpuN == 1 forces mulVec (single-threaded); cpuN == 0 lets mcl use
        // OpenMP when built with MCL_USE_OMP=1 (WITH_MCL_OPENMP=ON).
        mclBnG1_mulVecMT(&r, bases.data(), exps.data(), n, cpuN);
        ankerl::nanobench::doNotOptimizeAway(r);
    });
}
static void MsmBlst(Bench& bench, size_t n, size_t threads)
{
    const auto& fx = PrimFixture::Get();
    std::vector<BlstG1Point> bases; std::vector<BlstScalar> exps;
    for (size_t i = 0; i < n; ++i) { bases.push_back(fx.bp[i % PrimFixture::N]); exps.push_back(fx.bs[i % PrimFixture::N]); }
    bench.unit("msm").run([&] {
        auto r = BlstUtil::MSM(bases.data(), exps.data(), n, threads);
        ankerl::nanobench::doNotOptimizeAway(r);
    });
}
#define MSM_BENCH(N)                                                                          \
    static void BLSCTCmp_Msm##N##_mcl_ST(Bench& b) { MsmMcl(b, N, 1); }                       \
    static void BLSCTCmp_Msm##N##_mcl_MT(Bench& b) { MsmMcl(b, N, 0); }                       \
    static void BLSCTCmp_Msm##N##_blst_ST(Bench& b) { MsmBlst(b, N, 1); }                     \
    static void BLSCTCmp_Msm##N##_blst_MT(Bench& b) { MsmBlst(b, N, HwThreads()); }           \
    BENCHMARK(BLSCTCmp_Msm##N##_mcl_ST, benchmark::PriorityLevel::HIGH);                      \
    BENCHMARK(BLSCTCmp_Msm##N##_mcl_MT, benchmark::PriorityLevel::HIGH);                      \
    BENCHMARK(BLSCTCmp_Msm##N##_blst_ST, benchmark::PriorityLevel::HIGH);                     \
    BENCHMARK(BLSCTCmp_Msm##N##_blst_MT, benchmark::PriorityLevel::HIGH);
MSM_BENCH(16)
MSM_BENCH(64)
MSM_BENCH(150)   // ~ one 64-bit single-value range proof (2*mn + 2*log2(mn) + ~6)
MSM_BENCH(512)
MSM_BENCH(2048)  // ~ one 16-value aggregated range proof
MSM_BENCH(8192)

// --- Signatures --------------------------------------------------------------
static void BLSCTCmp_Sign_mcl(Bench& bench)
{
    SigFixture fx(1);
    bench.unit("sign").run([&] { blsSignature s; blsSign(&s, &fx.sks[0], fx.flat_msgs.data(), kMsgSize); ankerl::nanobench::doNotOptimizeAway(s); });
}
static void BLSCTCmp_Sign_blst(Bench& bench)
{
    SigFixture fx(1);
    bench.unit("sign").run([&] {
        blst_p2 h, s;
        blst_hash_to_g2(&h, fx.flat_msgs.data(), kMsgSize, reinterpret_cast<const byte*>(kG2Dst), std::strlen(kG2Dst), nullptr, 0);
        blst_sign_pk_in_g1(&s, &h, &fx.bsks[0]);
        ankerl::nanobench::doNotOptimizeAway(s);
    });
}
static void BLSCTCmp_Verify1_mcl(Bench& bench)
{
    SigFixture fx(1);
    bench.unit("verify").run([&] { bool ok = fx.MclVerify1(0); ankerl::nanobench::doNotOptimizeAway(ok); });
}
static void BLSCTCmp_Verify1_blst(Bench& bench)
{
    SigFixture fx(1);
    bench.unit("verify").run([&] { bool ok = fx.BlstVerify1(0); ankerl::nanobench::doNotOptimizeAway(ok); });
}
BENCHMARK(BLSCTCmp_Sign_mcl, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTCmp_Sign_blst, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTCmp_Verify1_mcl, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTCmp_Verify1_blst, benchmark::PriorityLevel::HIGH);

#define AGG_BENCH(N)                                                                                                   \
    static void BLSCTCmp_AggVerify##N##_mcl_ST(Bench& b) { SigFixture fx(N); b.batch(N).unit("pair").run([&] { bool ok = fx.MclAggVerifyST(); ankerl::nanobench::doNotOptimizeAway(ok); }); } \
    static void BLSCTCmp_AggVerify##N##_mcl_MT(Bench& b) { SigFixture fx(N); b.batch(N).unit("pair").run([&] { bool ok = fx.MclAggVerifyMT(); ankerl::nanobench::doNotOptimizeAway(ok); }); } \
    static void BLSCTCmp_AggVerify##N##_blst_ST(Bench& b) { SigFixture fx(N); b.batch(N).unit("pair").run([&] { bool ok = fx.BlstAggVerify(1); ankerl::nanobench::doNotOptimizeAway(ok); }); } \
    static void BLSCTCmp_AggVerify##N##_blst_MT(Bench& b) { SigFixture fx(N); b.batch(N).unit("pair").run([&] { bool ok = fx.BlstAggVerify(HwThreads()); ankerl::nanobench::doNotOptimizeAway(ok); }); } \
    BENCHMARK(BLSCTCmp_AggVerify##N##_mcl_ST, benchmark::PriorityLevel::HIGH);                                         \
    BENCHMARK(BLSCTCmp_AggVerify##N##_mcl_MT, benchmark::PriorityLevel::HIGH);                                         \
    BENCHMARK(BLSCTCmp_AggVerify##N##_blst_ST, benchmark::PriorityLevel::HIGH);                                        \
    BENCHMARK(BLSCTCmp_AggVerify##N##_blst_MT, benchmark::PriorityLevel::HIGH);
AGG_BENCH(2)
AGG_BENCH(16)
AGG_BENCH(256)
AGG_BENCH(1024)

// --- Range proofs (full navio op) --------------------------------------------
static void RPProve(Bench& bench, bool blst)
{
    RPFixture fx(1);
    static RP<Mcl> rpm; static RP<Blst> rpb;
    std::vector<uint8_t> msg(8, 1);
    bench.unit("rp-prove").run([&] {
        if (blst) {
            Elements<BlstScalar> vs; vs.Add(BlstScalar(int64_t{4242}));
            auto p = rpb.Prove(vs, range_proof::GammaSeed<Blst>(fx.blst_nonces[0]), msg, TokenId());
            ankerl::nanobench::doNotOptimizeAway(p.A);
        } else {
            Elements<MclScalar> vs; vs.Add(MclScalar(int64_t{4242}));
            auto p = rpm.Prove(vs, range_proof::GammaSeed<Mcl>(fx.mcl_nonces[0]), msg, TokenId());
            ankerl::nanobench::doNotOptimizeAway(p.A);
        }
    });
}
static void BLSCTCmp_RPProve_mcl(Bench& b) { RPProve(b, false); }
static void BLSCTCmp_RPProve_blst(Bench& b) { BlstUtil::SetDefaultThreads(1); RPProve(b, true); }
BENCHMARK(BLSCTCmp_RPProve_mcl, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTCmp_RPProve_blst, benchmark::PriorityLevel::HIGH);

// Batch verify. n == 1 is the per-proof single-threaded cost (no outer
// worker fan-out); n > 1 exercises RangeProofLogic's per-proof std::async
// workers (unless HAVE_OPENMP is defined). blst "MT" additionally tiles each
// proof's MSM across threads.
static void RPVerify(Bench& bench, size_t n, int mode /*0 mcl, 1 blst ST, 2 blst MT*/)
{
    RPFixture fx(n);
    static RP<Mcl> rpm; static RP<Blst> rpb;
    BlstUtil::SetDefaultThreads(mode == 2 ? 0 : 1);
    bench.batch(n).unit("rp-verify").run([&] {
        bool ok = mode == 0 ? rpm.Verify(fx.mcl_proofs) : rpb.Verify(fx.blst_proofs);
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
    BlstUtil::SetDefaultThreads(1);
}
#define RPV_BENCH(N)                                                                          \
    static void BLSCTCmp_RPVerify##N##_mcl(Bench& b) { RPVerify(b, N, 0); }                   \
    static void BLSCTCmp_RPVerify##N##_blst_ST(Bench& b) { RPVerify(b, N, 1); }               \
    static void BLSCTCmp_RPVerify##N##_blst_MT(Bench& b) { RPVerify(b, N, 2); }               \
    BENCHMARK(BLSCTCmp_RPVerify##N##_mcl, benchmark::PriorityLevel::HIGH);                    \
    BENCHMARK(BLSCTCmp_RPVerify##N##_blst_ST, benchmark::PriorityLevel::HIGH);                \
    BENCHMARK(BLSCTCmp_RPVerify##N##_blst_MT, benchmark::PriorityLevel::HIGH);
RPV_BENCH(1)
RPV_BENCH(4)
RPV_BENCH(16)
RPV_BENCH(32)

// --- Amount recovery / balance-recovery scan (full wallet op) ----------------
static void Recover(Bench& bench, size_t n, bool blst)
{
    RPFixture fx(n);
    static RP<Mcl> rpm; static RP<Blst> rpb;
    bench.batch(n).unit("recover").run([&] {
        if (blst) { auto r = fx.BlstRecover(rpb); ankerl::nanobench::doNotOptimizeAway(r.amounts.size()); }
        else { auto r = fx.MclRecover(rpm); ankerl::nanobench::doNotOptimizeAway(r.amounts.size()); }
    });
}
static void BLSCTCmp_RecoverAmounts16_mcl(Bench& b) { Recover(b, 16, false); }
static void BLSCTCmp_RecoverAmounts16_blst(Bench& b) { Recover(b, 16, true); }
BENCHMARK(BLSCTCmp_RecoverAmounts16_mcl, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTCmp_RecoverAmounts16_blst, benchmark::PriorityLevel::HIGH);

// A block-sized scan: 4096 candidate outputs, 16 of them ours.
static void Scan(Bench& bench, bool blst, size_t threads)
{
    static ScanFixture fx(4096, 16);
    bench.batch(fx.n_outputs).unit("output").run([&] {
        size_t got = blst ? fx.Scan<Blst>(threads) : fx.Scan<Mcl>(threads);
        ankerl::nanobench::doNotOptimizeAway(got);
    });
}
static void BLSCTCmp_BalanceScan4096_mcl_ST(Bench& b) { Scan(b, false, 1); }
static void BLSCTCmp_BalanceScan4096_mcl_MT(Bench& b) { Scan(b, false, HwThreads()); }
static void BLSCTCmp_BalanceScan4096_blst_ST(Bench& b) { Scan(b, true, 1); }
static void BLSCTCmp_BalanceScan4096_blst_MT(Bench& b) { Scan(b, true, HwThreads()); }
BENCHMARK(BLSCTCmp_BalanceScan4096_mcl_ST, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTCmp_BalanceScan4096_mcl_MT, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTCmp_BalanceScan4096_blst_ST, benchmark::PriorityLevel::HIGH);
BENCHMARK(BLSCTCmp_BalanceScan4096_blst_MT, benchmark::PriorityLevel::HIGH);

// --- PoS set-membership proof (full navio op) --------------------------------
static void SetMemVerify(Bench& bench, size_t n, int mode)
{
    SetMemFixture fx(n);
    BlstUtil::SetDefaultThreads(mode == 2 ? 0 : 1);
    bench.unit("setmem-verify").run([&] {
        bool ok = mode == 0 ? fx.m.Verify() : fx.b.Verify();
        ankerl::nanobench::doNotOptimizeAway(ok);
    });
    BlstUtil::SetDefaultThreads(1);
}
static void SetMemProve(Bench& bench, size_t n, bool blst)
{
    SetMemFixture fx(n);
    bench.unit("setmem-prove").run([&] {
        if (blst) { auto p = SetMemProofProver<Blst>::Prove(SetMemProofSetup<Blst>::Get(), fx.b.Ys, fx.b.sigma, fx.b.m, fx.b.f, fx.b.eta_fiat_shamir, fx.b.eta_phi); ankerl::nanobench::doNotOptimizeAway(p.t); }
        else { auto p = SetMemProofProver<Mcl>::Prove(SetMemProofSetup<Mcl>::Get(), fx.m.Ys, fx.m.sigma, fx.m.m, fx.m.f, fx.m.eta_fiat_shamir, fx.m.eta_phi); ankerl::nanobench::doNotOptimizeAway(p.t); }
    });
}
#define SETMEM_BENCH(N)                                                                       \
    static void BLSCTCmp_SetMemVerify##N##_mcl(Bench& b) { SetMemVerify(b, N, 0); }           \
    static void BLSCTCmp_SetMemVerify##N##_blst_ST(Bench& b) { SetMemVerify(b, N, 1); }       \
    static void BLSCTCmp_SetMemVerify##N##_blst_MT(Bench& b) { SetMemVerify(b, N, 2); }       \
    static void BLSCTCmp_SetMemProve##N##_mcl(Bench& b) { SetMemProve(b, N, false); }         \
    static void BLSCTCmp_SetMemProve##N##_blst(Bench& b) { SetMemProve(b, N, true); }         \
    BENCHMARK(BLSCTCmp_SetMemVerify##N##_mcl, benchmark::PriorityLevel::HIGH);                \
    BENCHMARK(BLSCTCmp_SetMemVerify##N##_blst_ST, benchmark::PriorityLevel::HIGH);            \
    BENCHMARK(BLSCTCmp_SetMemVerify##N##_blst_MT, benchmark::PriorityLevel::HIGH);            \
    BENCHMARK(BLSCTCmp_SetMemProve##N##_mcl, benchmark::PriorityLevel::HIGH);                 \
    BENCHMARK(BLSCTCmp_SetMemProve##N##_blst, benchmark::PriorityLevel::HIGH);
SETMEM_BENCH(4)     // smallest mainnet PoS ring seen (sample=3 padded=4)
SETMEM_BENCH(16)    // typical mainnet PoS ring (sample=16 padded=16)
SETMEM_BENCH(64)
SETMEM_BENCH(1024)

} // namespace

#endif // NAVIO_BLSCT_ARITH_BLST
