// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <p2pmsg/fmd.h>

#include <crypto/sha256.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <vector>

using namespace p2pmsg;

BOOST_FIXTURE_TEST_SUITE(p2pmsg_fmd_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(fmd_sizes_are_the_documented_wire_sizes)
{
    // These are wire constants shared with the SDK; a change here is a protocol
    // change, not an implementation detail.
    BOOST_CHECK_EQUAL(FMD_GAMMA, 24U);
    BOOST_CHECK_EQUAL(FMD_FLAG_SIZE, 83U);
    BOOST_CHECK_EQUAL(FMD_CLUE_KEY_SIZE, 1152U);

    const auto sk = FmdSecretKey::Random();
    BOOST_CHECK_EQUAL(sk.GetClueKey().ToBytes().size(), FMD_CLUE_KEY_SIZE);
    BOOST_CHECK_EQUAL(FmdFlag(sk.GetClueKey()).size(), FMD_FLAG_SIZE);
}

BOOST_AUTO_TEST_CASE(fmd_true_positive_at_every_precision)
{
    // Correctness: a flag made for this clue key matches its own detection key
    // at EVERY precision, always. Anything less and real messages get dropped.
    const auto sk = FmdSecretKey::Random();
    const auto ck = sk.GetClueKey();

    for (int trial = 0; trial < 8; ++trial) {
        const auto flag = FmdFlag(ck);
        for (size_t n = 1; n <= FMD_GAMMA; ++n) {
            BOOST_CHECK_MESSAGE(FmdTest(sk.Extract(n), flag),
                                "true positive failed at precision " << n);
        }
    }
}

BOOST_AUTO_TEST_CASE(fmd_other_recipients_match_at_the_expected_rate)
{
    // Fuzziness: someone else's flag matches with probability 2^-n. Checked at
    // low precision so the sample size stays cheap; the per-bit independence
    // that gives 2^-n is what the higher precisions inherit.
    const auto mine = FmdSecretKey::Random();
    const auto theirs = FmdSecretKey::Random();

    constexpr int kTrials = 2000;
    int matched_1 = 0;
    int matched_4 = 0;
    const auto dk1 = mine.Extract(1);
    const auto dk4 = mine.Extract(4);
    for (int i = 0; i < kTrials; ++i) {
        const auto flag = FmdFlag(theirs.GetClueKey());
        if (FmdTest(dk1, flag)) ++matched_1;
        if (FmdTest(dk4, flag)) ++matched_4;
    }

    // Expect ~1000 at 2^-1 and ~125 at 2^-4. Generous bounds: this is a
    // statistical test in a deterministic test suite, and a flaky CI failure
    // here would be worse than a loose bound.
    BOOST_CHECK_GT(matched_1, kTrials / 2 - 150);
    BOOST_CHECK_LT(matched_1, kTrials / 2 + 150);
    BOOST_CHECK_GT(matched_4, 60);
    BOOST_CHECK_LT(matched_4, 220);

    // A match at precision n implies a match at every lower precision, because
    // the bits are a prefix. The reverse is what the rate above measures.
    BOOST_CHECK_GE(matched_1, matched_4);
}

BOOST_AUTO_TEST_CASE(fmd_full_precision_effectively_never_false_positives)
{
    const auto mine = FmdSecretKey::Random();
    const auto theirs = FmdSecretKey::Random();
    const auto dk = mine.Extract(FMD_GAMMA);
    for (int i = 0; i < 200; ++i) {
        BOOST_CHECK(!FmdTest(dk, FmdFlag(theirs.GetClueKey())));
    }
}

BOOST_AUTO_TEST_CASE(fmd_detection_key_is_a_prefix_and_does_not_extend)
{
    // The x_i are INDEPENDENT. A precision-n key is the first n of them and
    // yields nothing about x_{n+1}. This is the property the compact
    // single-point clue key would have destroyed, and the reason we carry 1152
    // bytes instead of 48 -- so pin it.
    const auto sk = FmdSecretKey::Random();
    const auto dk4 = sk.Extract(4);
    const auto dk8 = sk.Extract(8);
    BOOST_CHECK_EQUAL(dk4.size(), 4U * FMD_SCALAR_SIZE);
    BOOST_CHECK_EQUAL(dk8.size(), 8U * FMD_SCALAR_SIZE);
    BOOST_CHECK(std::equal(dk4.begin(), dk4.end(), dk8.begin()));

    BOOST_CHECK(sk.Extract(0).empty());
    BOOST_CHECK(sk.Extract(FMD_GAMMA + 1).empty());
}

BOOST_AUTO_TEST_CASE(fmd_wrong_key_does_not_match_its_own_flag)
{
    const auto a = FmdSecretKey::Random();
    const auto b = FmdSecretKey::Random();
    const auto flag = FmdFlag(a.GetClueKey());
    // At full precision the odds of a coincidental match are 2^-24.
    BOOST_CHECK(FmdTest(a.Extract(FMD_GAMMA), flag));
    BOOST_CHECK(!FmdTest(b.Extract(FMD_GAMMA), flag));
}

BOOST_AUTO_TEST_CASE(fmd_flag_is_not_malleable)
{
    // The (y, m) collision binds w to every ciphertext bit. Touching any byte
    // of the flag randomises the recovered w and with it every k_i. Without
    // this the scheme would not be CCA-secure and a relay could maul a flag
    // into someone else's bucket -- which is also why the PoW header commits
    // to the flag (see PayloadHash).
    const auto sk = FmdSecretKey::Random();
    const auto dk = sk.Extract(FMD_GAMMA);
    const auto flag = FmdFlag(sk.GetClueKey());
    BOOST_CHECK(FmdTest(dk, flag));

    for (size_t i : {size_t{0}, size_t{47}, size_t{48}, size_t{79}, size_t{80}, FMD_FLAG_SIZE - 1}) {
        auto mauled = flag;
        mauled[i] ^= 0x01;
        BOOST_CHECK_MESSAGE(!FmdTest(dk, mauled), "mauled byte " << i << " still matched");
    }
}

BOOST_AUTO_TEST_CASE(fmd_test_rejects_malformed_input)
{
    const auto sk = FmdSecretKey::Random();
    const auto dk = sk.Extract(8);
    const auto flag = FmdFlag(sk.GetClueKey());

    BOOST_CHECK(!FmdTest(dk, {}));
    BOOST_CHECK(!FmdTest(dk, std::vector<uint8_t>(FMD_FLAG_SIZE - 1, 0)));
    BOOST_CHECK(!FmdTest(dk, std::vector<uint8_t>(FMD_FLAG_SIZE + 1, 0)));
    BOOST_CHECK(!FmdTest({}, flag));
    // Not a whole number of scalars.
    BOOST_CHECK(!FmdTest(std::vector<uint8_t>(33, 1), flag));
    // Beyond gamma.
    BOOST_CHECK(!FmdTest(std::vector<uint8_t>((FMD_GAMMA + 1) * FMD_SCALAR_SIZE, 1), flag));

    // u must be a valid, non-infinity G1 point. An infinity u would make
    // u^{x_i} infinity for EVERY key, so one flag would match every recipient:
    // free spam into everyone's bucket at once.
    auto inf = flag;
    std::fill(inf.begin(), inf.begin() + FMD_POINT_SIZE, uint8_t{0});
    inf[0] = 0xc0; // compressed point at infinity
    BOOST_CHECK(!FmdTest(dk, inf));

    auto garbage = flag;
    std::fill(garbage.begin(), garbage.begin() + FMD_POINT_SIZE, uint8_t{0xff});
    BOOST_CHECK(!FmdTest(dk, garbage));
}

BOOST_AUTO_TEST_CASE(fmd_clue_key_roundtrip_and_validation)
{
    const auto sk = FmdSecretKey::Random();
    const auto bytes = sk.GetClueKey().ToBytes();
    const auto parsed = FmdClueKey::FromBytes(bytes);
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK(parsed->ToBytes() == bytes);

    // A flag made from the parsed key still matches, i.e. the round trip is
    // value-preserving and not merely byte-preserving.
    BOOST_CHECK(FmdTest(sk.Extract(FMD_GAMMA), FmdFlag(*parsed)));

    BOOST_CHECK(!FmdClueKey::FromBytes({}).has_value());
    BOOST_CHECK(!FmdClueKey::FromBytes(std::vector<uint8_t>(FMD_CLUE_KEY_SIZE - 1, 0)).has_value());
    BOOST_CHECK(!FmdClueKey::FromBytes(std::vector<uint8_t>(FMD_CLUE_KEY_SIZE + 1, 0)).has_value());
    // Off-curve / non-canonical points are rejected, as is infinity.
    BOOST_CHECK(!FmdClueKey::FromBytes(std::vector<uint8_t>(FMD_CLUE_KEY_SIZE, 0xff)).has_value());
    std::vector<uint8_t> all_inf(FMD_CLUE_KEY_SIZE, 0);
    for (size_t i = 0; i < FMD_GAMMA; ++i) all_inf[i * FMD_POINT_SIZE] = 0xc0;
    BOOST_CHECK(!FmdClueKey::FromBytes(all_inf).has_value());
}

BOOST_AUTO_TEST_CASE(fmd_seed_derivation_is_deterministic_and_separated)
{
    const std::vector<uint8_t> seed(32, 0x11);
    const std::vector<uint8_t> other(32, 0x12);

    const auto a = FmdSecretKey::FromSeed(seed, 0);
    const auto b = FmdSecretKey::FromSeed(seed, 0);
    BOOST_CHECK(a.GetClueKey().ToBytes() == b.GetClueKey().ToBytes());

    // Different epoch and different seed both give different keys -- epoch
    // rotation is what bounds a detection key's lifetime.
    BOOST_CHECK(a.GetClueKey().ToBytes() != FmdSecretKey::FromSeed(seed, 1).GetClueKey().ToBytes());
    BOOST_CHECK(a.GetClueKey().ToBytes() != FmdSecretKey::FromSeed(other, 0).GetClueKey().ToBytes());

    // The gamma sub-keys within one key are distinct.
    const auto dk = a.Extract(FMD_GAMMA);
    for (size_t i = 1; i < FMD_GAMMA; ++i) {
        BOOST_CHECK(!std::equal(dk.begin(), dk.begin() + FMD_SCALAR_SIZE,
                                dk.begin() + i * FMD_SCALAR_SIZE));
    }

    BOOST_CHECK(FmdTest(a.Extract(FMD_GAMMA), FmdFlag(b.GetClueKey())));
}

// A flag's y component must be canonically encoded. SetVch() reduces mod r,
// so y and y + r parse to the same scalar; without a canonicality check a
// relay could rewrite those 32 bytes in flight and the flag would still match
// its recipient, which makes the encoding malleable.
BOOST_AUTO_TEST_CASE(fmd_rejects_non_canonical_y)
{
    const auto sk = FmdSecretKey::Random();
    const auto dk = sk.Extract(FMD_GAMMA);
    auto flag = FmdFlag(sk.GetClueKey());
    BOOST_REQUIRE(FmdTest(dk, flag));

    // y sits after the point, and is 32 bytes big-endian. Add the group order
    // to it: same scalar once reduced, different bytes on the wire.
    const auto r = ParseHex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    std::vector<uint8_t> y(flag.begin() + FMD_POINT_SIZE,
                           flag.begin() + FMD_POINT_SIZE + FMD_SCALAR_SIZE);

    unsigned carry = 0;
    std::vector<uint8_t> y_plus_r(FMD_SCALAR_SIZE);
    for (int i = FMD_SCALAR_SIZE - 1; i >= 0; --i) {
        const unsigned sum = unsigned{y[i]} + unsigned{r[i]} + carry;
        y_plus_r[i] = static_cast<uint8_t>(sum & 0xff);
        carry = sum >> 8;
    }
    // Only meaningful when it did not overflow 32 bytes; y is random, so this
    // holds unless y is very large, in which case there is nothing to test.
    if (carry == 0) {
        auto malleated = flag;
        std::copy(y_plus_r.begin(), y_plus_r.end(), malleated.begin() + FMD_POINT_SIZE);
        BOOST_CHECK(malleated != flag);
        BOOST_CHECK_MESSAGE(!FmdTest(dk, malleated),
                            "a non-canonical y was accepted, so the flag encoding is malleable");
    }
}

BOOST_AUTO_TEST_CASE(fmd_cross_implementation_vectors)
{
    // Fixed vectors shared with the TypeScript SDK (navio-p2pmsg,
    // src/bus/fmd.test.ts). They pin the two things an independent
    // implementation has to get byte-identical or the two sides silently stop
    // detecting each other's messages:
    //
    //   1. seed -> secret -> clue key derivation, including the hash inputs
    //      and the big-endian reduction mod r;
    //   2. the flag itself -- a flag produced by the SDK must Test() here.
    //
    // The reverse direction (a flag produced here, tested by the SDK) is
    // pinned by the matching vector in that file.
    const std::vector<uint8_t> seed(32, 0x11);
    const auto sk = FmdSecretKey::FromSeed(seed, 0);
    const auto ck = sk.GetClueKey().ToBytes();
    BOOST_REQUIRE_EQUAL(ck.size(), FMD_CLUE_KEY_SIZE);

    uint8_t digest[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(ck.data(), ck.size()).Finalize(digest);
    BOOST_CHECK_EQUAL(HexStr(digest),
                      "777166863266f3322a494e3d0c1a2373c5b44e8ba87c3adb97055be9061e46f4");

    BOOST_CHECK_EQUAL(
        HexStr(sk.Extract(4)),
        "204afaea8370e9197fd34c5aea2d5b555137bc9798b1c3a1acc66cd1721a41d4"
        "3b56bf844020b0b217303b899d55bf74adb03697107e51ac646997ee6fbd4b4c"
        "5c813e4193da749037945776684208ce0f238e9ebd4548eafac165457fde05b9"
        "6fdefda48d8c821baa6d0cfd690f727e6840001d852d1c7f3da6609263d43ca3");

    // A flag produced by the SDK for this clue key.
    const auto sdk_flag = ParseHex(
        "83dd79430a5c23931404f099ffd1a1c58216515582eadb6bae1848b8b950ef22"
        "c4f34eb17436a0d96cb0d29cd44b29d3665963fe3d868c9250b021ff5d115ce1"
        "e743d0c85320d55a7c170f4edb49bb97b53ffc");
    BOOST_REQUIRE_EQUAL(sdk_flag.size(), FMD_FLAG_SIZE);
    BOOST_CHECK(FmdTest(sk.Extract(FMD_GAMMA), sdk_flag));
    // And it is genuinely discriminating, not matching everything.
    BOOST_CHECK(!FmdTest(FmdSecretKey::Random().Extract(FMD_GAMMA), sdk_flag));

    // A flag produced HERE, for this same clue key, is pinned on the SDK side.
    // To regenerate that pair after a scheme change, print HexStr(FmdFlag(...))
    // and paste it into src/bus/fmd.test.ts.
    BOOST_CHECK(FmdTest(sk.Extract(FMD_GAMMA), FmdFlag(sk.GetClueKey())));
}

BOOST_AUTO_TEST_SUITE_END()
