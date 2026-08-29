// Copyright (c) 2022-2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_UNIT_TEST

#include <blsct/common.h>
#include <blsct/private_key.h>
#include <boost/test/unit_test.hpp>
#include <blst.h>
#include <cstring>
#include <streams.h>
#include <test/util/setup_common.h>

namespace blsct {

BOOST_FIXTURE_TEST_SUITE(signature_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(test_serialization_with_func_calls)
{
    PrivateKey sk(12345);
    auto sig = sk.SignBalance();
    DataStream st{};
    sig.Serialize(st);
    Signature recovered_sig;
    recovered_sig.Unserialize(st);

    BOOST_CHECK(sig == recovered_sig);
}

BOOST_AUTO_TEST_CASE(test_serialization_with_operators)
{
    PrivateKey sk(12345);
    auto sig = sk.SignBalance();
    DataStream st{};
    st << sig;
    Signature recovered_sig;
    st >> recovered_sig;

    BOOST_CHECK(sig == recovered_sig);
}

BOOST_AUTO_TEST_CASE(test_constructor)
{
    Signature s;
    BOOST_CHECK(s.IsZero());

    Signature s2;
    BOOST_CHECK(s.GetVch() == s2.GetVch());
    BOOST_CHECK(s == s2);
}

BOOST_AUTO_TEST_CASE(test_valid_signature_round_trips)
{
    // A legitimately produced signature is in the prime-order subgroup, so the
    // subgroup guard in SetVch must accept it (round-trip preserves the point).
    PrivateKey sk(67890);
    auto sig = sk.SignBalance();
    { blst_p2_affine a; blst_p2_to_affine(&a, &sig.m_data); BOOST_CHECK(blst_p2_affine_in_g2(&a)); }

    Signature restored(sig.GetVch());
    BOOST_CHECK(sig == restored);
    BOOST_CHECK(!restored.IsZero());
}

BOOST_AUTO_TEST_CASE(test_setvch_rejects_off_subgroup_point)
{
    // Signature::SetVch must reject a G2 point that lies on the curve but
    // outside the prime-order subgroup: blst_p2_uncompress validates the
    // curve equation only and the aggregate-verify path does not check the
    // subgroup again, so the guard in SetVch is the only line of defence
    // against BLS signature malleability / off-subgroup forgeries.
    PrivateKey sk(13579);
    auto sig = sk.SignBalance();

    // The produced signature is in the subgroup and survives a SetVch round
    // trip unchanged (i.e. the new guard accepts it).
    { blst_p2_affine a; blst_p2_to_affine(&a, &sig.m_data); BOOST_CHECK(blst_p2_affine_in_g2(&a)); }
    Signature restored(sig.GetVch());
    BOOST_CHECK(!restored.IsZero());
    BOOST_CHECK(sig == restored);

    // A buffer of the wrong length is rejected (cleared to identity), the
    // existing failure path that shares SetVch's clear-on-reject contract.
    Signature bad;
    bad.SetVch(std::vector<unsigned char>(10, 0xff));
    BOOST_CHECK(bad.IsZero());

    // Construct a genuine on-curve, off-subgroup G2 point by trying
    // compressed x coordinates until blst decodes one that fails in_g2 (the
    // cofactor of G2 is huge, so almost every curve point is off-subgroup).
    size_t found = 0;
    for (uint32_t i = 0; i < 4096 && found == 0; ++i) {
        std::vector<unsigned char> enc(96, 0);
        uint256 h = BlstScalar(int64_t{i}).GetHashWithSalt(99);
        std::memcpy(enc.data(), h.begin(), 32);
        std::memcpy(enc.data() + 32, h.begin(), 32);
        enc[0] = (enc[0] & 0x1f) | 0x80; // compressed, not infinity, y bit 0
        blst_p2_affine aff;
        if (blst_p2_uncompress(&aff, enc.data()) != BLST_SUCCESS) continue;
        if (blst_p2_affine_in_g2(&aff)) continue;
        ++found;
        Signature off;
        BOOST_CHECK(!off.SetVch(enc));
        BOOST_CHECK(off.IsZero());
    }
    BOOST_CHECK(found == 1);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace blsct
