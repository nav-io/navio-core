// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_UNIT_TEST

#include <test/util/setup_common.h>

#include <blsct/arith/mcl/mcl.h>
#include <blsct/wallet/delegation.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(delegation_tests, BasicTestingSetup)

using Point = MclG1Point;
using Scalar = MclScalar;

static blsct::delegation::DelegationInfo MakeInfo()
{
    blsct::delegation::DelegationInfo info;
    info.value = 1234567890;
    info.gamma = Scalar::Rand();
    info.rewardAddress = "nv1exampleaddressxyz";
    return info;
}

BOOST_AUTO_TEST_CASE(roundtrip)
{
    const Scalar delegatePriv = Scalar::Rand(true);
    const Point delegatePub = Point::GetBasePoint() * delegatePriv;

    const auto info = MakeInfo();
    const auto blob = blsct::delegation::Encrypt(info, delegatePub);

    BOOST_CHECK(blsct::delegation::IsDelegationData(blob));

    const auto decrypted = blsct::delegation::TryDecrypt(blob, delegatePriv);
    BOOST_REQUIRE(decrypted.has_value());
    BOOST_CHECK_EQUAL(decrypted->value, info.value);
    BOOST_CHECK(decrypted->gamma == info.gamma);
    BOOST_CHECK_EQUAL(decrypted->rewardAddress, info.rewardAddress);
}

BOOST_AUTO_TEST_CASE(wrong_key_fails)
{
    const Scalar delegatePriv = Scalar::Rand(true);
    const Point delegatePub = Point::GetBasePoint() * delegatePriv;
    const Scalar otherPriv = Scalar::Rand(true);

    const auto blob = blsct::delegation::Encrypt(MakeInfo(), delegatePub);
    BOOST_CHECK(!blsct::delegation::TryDecrypt(blob, otherPriv).has_value());
}

BOOST_AUTO_TEST_CASE(tampered_blob_fails)
{
    const Scalar delegatePriv = Scalar::Rand(true);
    const Point delegatePub = Point::GetBasePoint() * delegatePriv;

    auto blob = blsct::delegation::Encrypt(MakeInfo(), delegatePub);

    // Flip a bit in every region: magic, ephemeral key, ciphertext, tag.
    for (const size_t pos : {size_t{0}, size_t{10}, blob.size() / 2, blob.size() - 1}) {
        auto tampered = blob;
        tampered[pos] ^= 0x01;
        BOOST_CHECK(!blsct::delegation::TryDecrypt(tampered, delegatePriv).has_value());
    }

    // Truncated payloads must be rejected by the structural check.
    std::vector<unsigned char> truncated(blob.begin(), blob.begin() + 20);
    BOOST_CHECK(!blsct::delegation::IsDelegationData(truncated));
    BOOST_CHECK(!blsct::delegation::TryDecrypt(truncated, delegatePriv).has_value());
}

BOOST_AUTO_TEST_CASE(blobs_are_unlinkable)
{
    const Scalar delegatePriv = Scalar::Rand(true);
    const Point delegatePub = Point::GetBasePoint() * delegatePriv;

    const auto info = MakeInfo();
    const auto blob1 = blsct::delegation::Encrypt(info, delegatePub);
    const auto blob2 = blsct::delegation::Encrypt(info, delegatePub);

    // Fresh ephemeral key per encryption: identical plaintexts must not
    // produce identical blobs.
    BOOST_CHECK(blob1 != blob2);
}

BOOST_AUTO_TEST_SUITE_END()
