// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for the PoPS hardening patches:
//   * ProofOfStake::SaturateToU64
//   * Time-bucket grinding mitigation in CalculateKernelHash
//   * Chain-work binding in CalculateKernelHashWithChainWork
//   * G1 subgroup check on deserialize
//
// Finality-checkpoint enforcement is covered by validation_tests.cpp.

#include <boost/test/unit_test.hpp>

#include <arith_uint256.h>
#include <blsct/arith/mcl/mcl.h>
#include <blsct/arith/mcl/mcl_g1point.h>
#include <blsct/pos/helpers.h>
#include <blsct/pos/proof.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <limits>

BOOST_FIXTURE_TEST_SUITE(pops_hardening_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(saturate_to_u64_low_value_passes_through)
{
    uint256 low;
    // low bytes: 0x00..00 00 00 00 01 00 00 00 00  -> 2^32
    low.data()[4] = 0x01;
    uint64_t got = blsct::ProofOfStake::SaturateToU64(low);
    BOOST_CHECK_EQUAL(got, (uint64_t{1} << 32));
}

BOOST_AUTO_TEST_CASE(saturate_to_u64_exactly_uint64_max_passes_through)
{
    uint256 v;
    for (size_t i = 0; i < 8; ++i) v.data()[i] = 0xff;
    uint64_t got = blsct::ProofOfStake::SaturateToU64(v);
    BOOST_CHECK_EQUAL(got, std::numeric_limits<uint64_t>::max());
}

BOOST_AUTO_TEST_CASE(saturate_to_u64_clamps_on_overflow)
{
    uint256 v;
    // Set a byte above the low 8 -> value exceeds 2^64
    v.data()[9] = 0x01;
    uint64_t got = blsct::ProofOfStake::SaturateToU64(v);
    BOOST_CHECK_EQUAL(got, std::numeric_limits<uint64_t>::max());
}

BOOST_AUTO_TEST_CASE(kernel_hash_buckets_block_time)
{
    // Two times in the same 16s bucket must produce the same kernel hash.
    // Times in different buckets must differ.
    const uint32_t prevTime = 1000000;
    const uint64_t modifier = 0xdeadbeefcafebabeULL;

    uint256 a = blsct::CalculateKernelHash(prevTime, modifier, 1234567800);
    uint256 b = blsct::CalculateKernelHash(prevTime, modifier, 1234567815);
    uint256 c = blsct::CalculateKernelHash(prevTime, modifier, 1234567816);

    BOOST_CHECK(a == b);
    BOOST_CHECK(a != c);
}

BOOST_AUTO_TEST_CASE(kernel_hash_with_chain_work_diverges_per_fork)
{
    const uint32_t prevTime = 1000000;
    const uint64_t modifier = 42;
    const uint32_t time = 1000060;

    arith_uint256 workA = UintToArith256(uint256S("01"));
    arith_uint256 workB = UintToArith256(uint256S("02"));

    uint256 hA = blsct::CalculateKernelHashWithChainWork(prevTime, modifier, workA, time);
    uint256 hB = blsct::CalculateKernelHashWithChainWork(prevTime, modifier, workB, time);
    BOOST_CHECK(hA != hB);
}

BOOST_AUTO_TEST_CASE(g1_subgroup_check_accepts_generator)
{
    MclG1Point g = MclG1Point::GetBasePoint();
    auto bytes = g.GetVch();
    MclG1Point parsed;
    BOOST_CHECK(parsed.SetVch(bytes));
}

BOOST_AUTO_TEST_CASE(g1_subgroup_check_accepts_identity)
{
    // All-zero serialization with the compressed-infinity flag should round-trip.
    MclG1Point identity;  // default-constructed is identity
    auto bytes = identity.GetVch();
    MclG1Point parsed;
    BOOST_CHECK(parsed.SetVch(bytes));
}

BOOST_AUTO_TEST_CASE(g1_subgroup_check_rejects_garbage)
{
    std::vector<uint8_t> garbage(MclG1Point::SERIALIZATION_SIZE, 0x42);
    MclG1Point p;
    BOOST_CHECK(!p.SetVch(garbage));
}

BOOST_AUTO_TEST_SUITE_END()
