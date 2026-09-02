// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Differential accept/reject harness between the mcl and blst BLS12-381
// backends, run at the last commit where both backends exist in-tree. The
// full-chain reindex proves the backends agree on honest history; these
// tests probe the other half of the consensus surface — WHICH malformed or
// adversarial encodings are rejected — with deterministic pseudo-random
// input generation, so the run is reproducible from the commit hash alone.
//
// Everything compares the CHECKED decode paths (SetVch / Unserialize) and
// full proof verification verdicts: those are what consensus consumes. The
// known, intentional asymmetry (mcl's SetVchUnchecked still order-checks
// because blsInit() sets verifyOrderG1) is covered by the accompanying
// blst_equivalence_tests.

#ifdef NAVIO_BLSCT_ARITH_BLST

#include <blsct/arith/blst/blst.h>
#include <blsct/arith/mcl/mcl.h>
#include <blsct/arith/mcl/mcl_init.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof_logic.h>
#include <blsct/set_mem_proof/set_mem_proof.h>
#include <blsct/set_mem_proof/set_mem_proof_prover.h>
#include <blsct/set_mem_proof/set_mem_proof_setup.h>
#include <ctokens/tokenid.h>
#include <random.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <blst.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <memory>
#include <vector>

namespace {

// Deterministic generator: every run of this suite sees the same inputs.
FastRandomContext& Rng()
{
    static FastRandomContext rng{uint256S("b157d1ffe2e7a1a55e01")};
    return rng;
}

// A second deterministic stream, routed into mcl via mclBn_setRandFunc so
// that MclScalar::Rand / MclG1Point::Rand (mclBnFr_setByCSPRNG) are seeded
// too. Without this the base proofs / points / signatures each run mutates
// come from OS entropy, and the per-suite accept/reject *splits* vary
// slightly between runs (the zero-disagreements property does not). With it
// the whole harness is reproducible from the commit hash, byte for byte.
unsigned int DeterministicMclRand(void*, void* buf, unsigned int bufSize)
{
    static FastRandomContext rng{uint256S("5eeded4mc1b157")};
    auto bytes = rng.randbytes(bufSize);
    std::memcpy(buf, bytes.data(), bufSize);
    return bufSize;
}

struct SeedMclRng {
    SeedMclRng() { mclBn_setRandFunc(nullptr, DeterministicMclRand); }
    ~SeedMclRng() { mclBn_setRandFunc(nullptr, nullptr); }
};

std::vector<uint8_t> RandBytesVec(size_t n)
{
    auto b = Rng().randbytes(n);
    return std::vector<uint8_t>(b.begin(), b.end());
}

// The blst side of blsct::Signature::SetVch as shipped by the migration
// (uncompress -> curve check -> prime-order subgroup, identity permitted).
bool BlstSigDecode(const std::vector<uint8_t>& b)
{
    if (b.size() != 96) return false;
    blst_p2_affine aff{};
    if (blst_p2_uncompress(&aff, b.data()) != BLST_SUCCESS) return false;
    if (!blst_p2_affine_is_inf(&aff) && !blst_p2_affine_in_g2(&aff)) return false;
    return true;
}

// mcl master's blsct::Signature::SetVch equivalent on raw bytes.
bool MclSigDecode(const std::vector<uint8_t>& b)
{
    blsct::Signature sig;
    return sig.SetVch(b);
}

} // namespace

struct DifferentialSetup : BasicTestingSetup {
    // Order matters: MclInit must have run before mclBn_setRandFunc.
    DifferentialSetup()
    {
        volatile MclInit init;
        (void)init;
        m_seed_mcl = std::make_unique<SeedMclRng>();
    }
    std::unique_ptr<SeedMclRng> m_seed_mcl;
};

BOOST_FIXTURE_TEST_SUITE(blst_differential_tests, DifferentialSetup)

// G1 checked decode: identical accept/reject and identical decoded point on
// random, flag-forced and bit-flipped-valid 48-byte encodings.
BOOST_AUTO_TEST_CASE(g1_checked_decode_differential)
{
    volatile MclInit init;
    (void)init;
    constexpr size_t N_RANDOM = 40000;
    constexpr size_t N_FLAGGED = 40000;
    constexpr size_t N_MUTATED = 40000;

    size_t accepted = 0, rejected = 0;
    auto check_one = [&](const std::vector<uint8_t>& enc) {
        MclG1Point m;
        BlstG1Point b;
        const bool ma = m.SetVch(enc);
        const bool ba = b.SetVch(enc);
        BOOST_REQUIRE_MESSAGE(ma == ba, "G1 decode disagreement on " + HexStr(enc) +
                                            " mcl=" + ToString(ma) + " blst=" + ToString(ba));
        if (ma) {
            BOOST_REQUIRE(m.GetVch() == b.GetVch());
            ++accepted;
        } else {
            ++rejected;
        }
    };

    for (size_t i = 0; i < N_RANDOM; ++i) {
        check_one(RandBytesVec(48));
    }
    // Force serialization-flag patterns: compressed bit, infinity bit, sign
    // bit, and deliberately invalid combinations, over random payloads.
    const uint8_t flag_masks[] = {0x80, 0xa0, 0xc0, 0xe0, 0x00, 0x40, 0x20, 0xff};
    for (size_t i = 0; i < N_FLAGGED; ++i) {
        auto enc = RandBytesVec(48);
        enc[0] = (enc[0] & 0x1f) | flag_masks[i % std::size(flag_masks)];
        if (i % 5 == 0) std::fill(enc.begin() + 1, enc.end(), uint8_t{0}); // near-canonical infinity forms
        check_one(enc);
    }
    // Bit-flip valid encodings (1..4 flips).
    for (size_t i = 0; i < N_MUTATED; ++i) {
        auto enc = MclG1Point::Rand().GetVch();
        const size_t flips = 1 + (Rng().randbits(2));
        for (size_t f = 0; f < flips; ++f) {
            enc[Rng().randrange(48)] ^= uint8_t(1) << Rng().randrange(8);
        }
        check_one(enc);
    }
    BOOST_TEST_MESSAGE(strprintf("g1 decode: %d accepted, %d rejected, 0 disagreements", accepted, rejected));
    BOOST_CHECK(accepted > 0);
    BOOST_CHECK(rejected > 0);
}

// Scalar canonical decode (Unserialize): identical accept/reject; identical
// value when accepted. Includes the r-boundary.
BOOST_AUTO_TEST_CASE(scalar_canonical_decode_differential)
{
    volatile MclInit init;
    (void)init;
    // Fr modulus, big-endian.
    const std::vector<uint8_t> r_be = ParseHex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    auto check_one = [&](const std::vector<uint8_t>& enc) {
        DataStream sm{}, sb{};
        sm.write(MakeByteSpan(enc));
        sb.write(MakeByteSpan(enc));
        MclScalar m;
        BlstScalar b;
        bool ma = true, ba = true;
        try { sm >> m; } catch (const std::ios_base::failure&) { ma = false; }
        try { sb >> b; } catch (const std::ios_base::failure&) { ba = false; }
        BOOST_REQUIRE_MESSAGE(ma == ba, "scalar decode disagreement on " + HexStr(enc));
        if (ma) BOOST_REQUIRE(m.GetVch() == b.GetVch());
    };
    for (size_t i = 0; i < 100000; ++i) check_one(RandBytesVec(32));
    // Boundary values: 0, 1, r-1, r, r+1, 2^256-1.
    auto minus_one = r_be; minus_one[31] = 0x00; // r - 1
    auto plus_one = r_be;  plus_one[31] = 0x02;  // r + 1
    check_one(std::vector<uint8_t>(32, 0x00));
    { auto one = std::vector<uint8_t>(32, 0x00); one[31] = 1; check_one(one); }
    check_one(minus_one);
    check_one(r_be);
    check_one(plus_one);
    check_one(std::vector<uint8_t>(32, 0xff));
}

// G2 signature decode: mcl master's Signature::SetVch vs the blst decode the
// migration ships. Identical accept/reject on random, flag-forced and
// mutated-valid 96-byte encodings.
BOOST_AUTO_TEST_CASE(g2_signature_decode_differential)
{
    volatile MclInit init;
    (void)init;
    size_t accepted = 0, rejected = 0;
    auto check_one = [&](const std::vector<uint8_t>& enc) {
        const bool ma = MclSigDecode(enc);
        const bool ba = BlstSigDecode(enc);
        BOOST_REQUIRE_MESSAGE(ma == ba, "G2 decode disagreement on " + HexStr(enc));
        (ma ? accepted : rejected)++;
    };
    for (size_t i = 0; i < 20000; ++i) check_one(RandBytesVec(96));
    const uint8_t flag_masks[] = {0x80, 0xa0, 0xc0, 0xe0, 0x00, 0xff};
    for (size_t i = 0; i < 20000; ++i) {
        auto enc = RandBytesVec(96);
        enc[0] = (enc[0] & 0x1f) | flag_masks[i % std::size(flag_masks)];
        if (i % 5 == 0) std::fill(enc.begin() + 1, enc.end(), uint8_t{0});
        check_one(enc);
    }
    // Mutated valid signatures.
    for (size_t i = 0; i < 5000; ++i) {
        blsct::PrivateKey sk(MclScalar::Rand(true));
        auto sig = sk.SignBalance();
        auto enc = sig.GetVch();
        const size_t flips = 1 + Rng().randbits(2);
        for (size_t f = 0; f < flips; ++f) enc[Rng().randrange(96)] ^= uint8_t(1) << Rng().randrange(8);
        check_one(enc);
    }
    BOOST_TEST_MESSAGE(strprintf("g2 decode: %d accepted, %d rejected, 0 disagreements", accepted, rejected));
    BOOST_CHECK(accepted > 0);
    BOOST_CHECK(rejected > 0);
}

// Proof-level differential: byte-flip serialized proofs and require the two
// backends to agree on decode success AND the final verification verdict.
BOOST_AUTO_TEST_CASE(range_proof_mutation_differential)
{
    volatile MclInit init;
    (void)init;
    bulletproofs_plus::RangeProofLogic<Mcl> rpm;
    bulletproofs_plus::RangeProofLogic<Blst> rpb;

    size_t decode_fail = 0, verify_fail = 0, verify_ok = 0;
    for (size_t p = 0; p < 8; ++p) {
        MclG1Point nonce = MclG1Point::Rand();
        Elements<MclScalar> vs;
        vs.Add(MclScalar(int64_t(1000 + p)));
        std::vector<uint8_t> msg = {9, 9, uint8_t(p)};
        auto proof = rpm.Prove(vs, range_proof::GammaSeed<Mcl>(nonce), msg, TokenId());
        DataStream base{};
        base << proof;

        for (size_t i = 0; i < 250; ++i) {
            std::vector<uint8_t> bytes(UCharCast(base.data()), UCharCast(base.data()) + base.size());
            const size_t flips = 1 + Rng().randbits(3);
            for (size_t f = 0; f < flips; ++f) bytes[Rng().randrange(bytes.size())] ^= uint8_t(1) << Rng().randrange(8);

            DataStream sm{}, sb{};
            sm.write(MakeByteSpan(bytes));
            sb.write(MakeByteSpan(bytes));
            bulletproofs_plus::RangeProof<Mcl> pm;
            bulletproofs_plus::RangeProof<Blst> pb;
            bool ma = true, ba = true;
            try { sm >> pm; } catch (const std::exception&) { ma = false; }
            try { sb >> pb; } catch (const std::exception&) { ba = false; }
            BOOST_REQUIRE_MESSAGE(ma == ba, "range-proof decode disagreement, mutant of proof " + ToString(p));
            if (!ma) { ++decode_fail; continue; }
            bool vm = false, vb = false;
            try { vm = rpm.Verify({bulletproofs_plus::RangeProofWithSeed<Mcl>(pm, TokenId())}); } catch (const std::exception&) { vm = false; }
            try { vb = rpb.Verify({bulletproofs_plus::RangeProofWithSeed<Blst>(pb, TokenId())}); } catch (const std::exception&) { vb = false; }
            BOOST_REQUIRE_MESSAGE(vm == vb, "range-proof verify disagreement, mutant of proof " + ToString(p));
            (vm ? verify_ok : verify_fail)++;
        }
    }
    BOOST_TEST_MESSAGE(strprintf("range-proof mutants: %d decode-rejected, %d verify-rejected, %d accepted; 0 disagreements",
                                 decode_fail, verify_fail, verify_ok));
    BOOST_CHECK(decode_fail > 0);
    BOOST_CHECK(verify_fail > 0);
}

BOOST_AUTO_TEST_CASE(set_mem_proof_mutation_differential)
{
    volatile MclInit init;
    (void)init;
    const auto& sm_setup = SetMemProofSetup<Mcl>::Get();
    const auto& sb_setup = SetMemProofSetup<Blst>::Get();

    size_t decode_fail = 0, verify_fail = 0, verify_ok = 0;
    for (size_t p = 0; p < 8; ++p) {
        auto gen = sm_setup.Gf().GetInstance(TokenId());
        MclScalar m(int64_t(100 + p)), f = MclScalar::Rand(true);
        MclG1Point sigma = gen.G * m + gen.H * f;
        Elements<MclG1Point> Ys;
        Ys.Add(sigma);
        for (size_t i = 1; i < 8; ++i) Ys.Add(MclG1Point::MapToPoint("dy_" + ToString(p) + "_" + ToString(i)));
        Elements<BlstG1Point> Yb;
        for (const auto& y : Ys.m_vec) { BlstG1Point q; BOOST_REQUIRE(q.SetVch(y.GetVch())); Yb.Add(q); }
        MclScalar eta = MclScalar::Rand(true);
        BlstScalar eta_b; eta_b.SetVch(eta.GetVch());
        blsct::Message eta_phi{7, uint8_t(p)};
        auto proof = SetMemProofProver<Mcl>::Prove(sm_setup, Ys, sigma, m, f, eta, eta_phi);
        DataStream base{};
        base << proof;

        for (size_t i = 0; i < 250; ++i) {
            std::vector<uint8_t> bytes(UCharCast(base.data()), UCharCast(base.data()) + base.size());
            const size_t flips = 1 + Rng().randbits(3);
            for (size_t fl = 0; fl < flips; ++fl) bytes[Rng().randrange(bytes.size())] ^= uint8_t(1) << Rng().randrange(8);

            DataStream dm{}, db{};
            dm.write(MakeByteSpan(bytes));
            db.write(MakeByteSpan(bytes));
            SetMemProof<Mcl> pm;
            SetMemProof<Blst> pb;
            bool ma = true, ba = true;
            try { dm >> pm; } catch (const std::exception&) { ma = false; }
            try { db >> pb; } catch (const std::exception&) { ba = false; }
            BOOST_REQUIRE_MESSAGE(ma == ba, "set-mem decode disagreement, mutant of proof " + ToString(p));
            if (!ma) { ++decode_fail; continue; }
            bool vm = false, vb = false;
            try { vm = SetMemProofProver<Mcl>::Verify(sm_setup, Ys, eta, eta_phi, pm); } catch (const std::exception&) { vm = false; }
            try { vb = SetMemProofProver<Blst>::Verify(sb_setup, Yb, eta_b, eta_phi, pb); } catch (const std::exception&) { vb = false; }
            BOOST_REQUIRE_MESSAGE(vm == vb, "set-mem verify disagreement, mutant of proof " + ToString(p));
            (vm ? verify_ok : verify_fail)++;
        }
    }
    BOOST_TEST_MESSAGE(strprintf("set-mem mutants: %d decode-rejected, %d verify-rejected, %d accepted; 0 disagreements",
                                 decode_fail, verify_fail, verify_ok));
    BOOST_CHECK(decode_fail > 0);
    BOOST_CHECK(verify_fail > 0);
}

BOOST_AUTO_TEST_SUITE_END()

#endif // NAVIO_BLSCT_ARITH_BLST
