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

namespace {

struct Actors {
    Scalar delegatePriv;
    Point delegatePub;
    Point nonce;
    blsct::delegation::DelegationInfo info;
    blsct::delegation::DelegationRequest request;

    Actors()
    {
        delegatePriv = Scalar::Rand(true);
        delegatePub = Point::GetBasePoint() * delegatePriv;
        nonce = Point::Rand();
        info.value = 1234567890;
        info.gamma = Scalar::Rand();
        info.rewardAddress = "nv1exampleaddressxyz";
        request.delegateKey = delegatePub;
        request.rewardAddress = info.rewardAddress;
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(delegate_roundtrip)
{
    Actors a;
    const auto blob = blsct::delegation::Encrypt(a.info, a.request, a.nonce);

    BOOST_CHECK(blsct::delegation::IsDelegationData(blob));

    const auto decrypted = blsct::delegation::TryDecrypt(blob, a.delegatePriv);
    BOOST_REQUIRE(decrypted.has_value());
    BOOST_CHECK_EQUAL(decrypted->value, a.info.value);
    BOOST_CHECK(decrypted->gamma == a.info.gamma);
    BOOST_CHECK_EQUAL(decrypted->rewardAddress, a.info.rewardAddress);
}

BOOST_AUTO_TEST_CASE(owner_roundtrip)
{
    Actors a;
    const auto blob = blsct::delegation::Encrypt(a.info, a.request, a.nonce);

    const auto recovered = blsct::delegation::RecoverOwnerInfo(blob, a.nonce);
    BOOST_REQUIRE(recovered.has_value());
    BOOST_CHECK(recovered->delegateKey == a.request.delegateKey);
    BOOST_CHECK_EQUAL(recovered->rewardAddress, a.request.rewardAddress);
    BOOST_CHECK_EQUAL(recovered->GetId(), a.request.GetId());

    // A different nonce (someone else's output) must recover nothing.
    BOOST_CHECK(!blsct::delegation::RecoverOwnerInfo(blob, Point::Rand()).has_value());
}

BOOST_AUTO_TEST_CASE(wrong_key_fails)
{
    Actors a;
    const auto blob = blsct::delegation::Encrypt(a.info, a.request, a.nonce);
    BOOST_CHECK(!blsct::delegation::TryDecrypt(blob, Scalar::Rand(true)).has_value());
}

BOOST_AUTO_TEST_CASE(tampered_blob_fails)
{
    Actors a;
    auto blob = blsct::delegation::Encrypt(a.info, a.request, a.nonce);

    // Tampering with the shared prefix (magic / ephemeral key, both bound as
    // AEAD associated data) must break BOTH sections.
    for (const size_t pos : {size_t{0}, size_t{10}, size_t{52}}) {
        auto tampered = blob;
        tampered[pos] ^= 0x01;
        BOOST_CHECK(!blsct::delegation::TryDecrypt(tampered, a.delegatePriv).has_value());
        BOOST_CHECK(!blsct::delegation::RecoverOwnerInfo(tampered, a.nonce).has_value());
    }

    // Tampering inside the owner section breaks owner recovery; the delegate
    // section is independent, so no assertion on TryDecrypt here.
    {
        auto tampered = blob;
        tampered[5 + 48 + 2 + 3] ^= 0x01; // a few bytes into the owner ciphertext
        BOOST_CHECK(!blsct::delegation::RecoverOwnerInfo(tampered, a.nonce).has_value());
    }

    // Tampering with the delegate section (the blob's tail) breaks delegate
    // decryption but leaves owner recovery intact.
    {
        auto tampered = blob;
        tampered[blob.size() - 1] ^= 0x01;
        BOOST_CHECK(!blsct::delegation::TryDecrypt(tampered, a.delegatePriv).has_value());
        BOOST_CHECK(blsct::delegation::RecoverOwnerInfo(tampered, a.nonce).has_value());
    }

    // Truncated payloads must be rejected by the structural check.
    std::vector<unsigned char> truncated(blob.begin(), blob.begin() + 20);
    BOOST_CHECK(!blsct::delegation::IsDelegationData(truncated));
    BOOST_CHECK(!blsct::delegation::TryDecrypt(truncated, a.delegatePriv).has_value());
    BOOST_CHECK(!blsct::delegation::RecoverOwnerInfo(truncated, a.nonce).has_value());
}

BOOST_AUTO_TEST_CASE(blobs_are_unlinkable)
{
    Actors a;
    const auto blob1 = blsct::delegation::Encrypt(a.info, a.request, a.nonce);
    const auto blob2 = blsct::delegation::Encrypt(a.info, a.request, a.nonce);

    // Fresh ephemeral key per encryption: identical plaintexts must not
    // produce identical blobs.
    BOOST_CHECK(blob1 != blob2);
}

BOOST_AUTO_TEST_SUITE_END()
