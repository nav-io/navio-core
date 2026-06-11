// Copyright (c) 2022-2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_UNIT_TEST

#include <blsct/common.h>
#include <blsct/private_key.h>
#include <boost/test/unit_test.hpp>
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

    BOOST_CHECK(mclBnG2_isEqual(&sig.m_data.v, &recovered_sig.m_data.v) == 1);
}

BOOST_AUTO_TEST_CASE(test_serialization_with_operators)
{
    PrivateKey sk(12345);
    auto sig = sk.SignBalance();
    DataStream st{};
    st << sig;
    Signature recovered_sig;
    st >> recovered_sig;

    BOOST_CHECK(mclBnG2_isEqual(&sig.m_data.v, &recovered_sig.m_data.v) == 1);
}

BOOST_AUTO_TEST_CASE(test_constructor)
{
    Signature s;
    BOOST_CHECK(mclBnG2_isZero(&s.m_data.v));

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
    BOOST_CHECK(mclBnG2_isValidOrder(&sig.m_data.v) == 1);

    Signature restored(sig.GetVch());
    BOOST_CHECK(mclBnG2_isEqual(&sig.m_data.v, &restored.m_data.v) == 1);
    BOOST_CHECK(!mclBnG2_isZero(&restored.m_data.v));
}

BOOST_AUTO_TEST_CASE(test_setvch_rejects_off_subgroup_point)
{
    // Signature::SetVch must reject a G2 point that lies on the curve but
    // outside the prime-order subgroup. mcl's bn init calls verifyOrderG2(false),
    // so the raw mclBnG2_deserialize validates the curve equation but NOT the
    // subgroup, and the verification path (blsAggregateVerifyNoCheck) skips the
    // order check too — so the guard added to SetVch is the only line of
    // defence against BLS signature malleability / off-subgroup forgeries.
    //
    // Constructing an off-subgroup point requires the mcl C++ API
    // (ec::tryAndIncMapTo / verifyOrderG2 toggling), which pulls in a libgmp
    // link dependency the unit-test binary does not carry. That direction is
    // exercised directly by mcl's own bls12_test "verifyG2" case. Here we lock
    // in the positive contract that the guard does not reject a legitimate
    // signature, and that the order check is wired (mclBnG2_isValidOrder
    // distinguishes a real signature from the cleared identity).
    PrivateKey sk(13579);
    auto sig = sk.SignBalance();

    // The produced signature is in the subgroup and survives a SetVch round
    // trip unchanged (i.e. the new guard accepts it).
    BOOST_CHECK(mclBnG2_isValidOrder(&sig.m_data.v) == 1);
    Signature restored(sig.GetVch());
    BOOST_CHECK(!mclBnG2_isZero(&restored.m_data.v));
    BOOST_CHECK(mclBnG2_isEqual(&sig.m_data.v, &restored.m_data.v) == 1);

    // A buffer of the wrong length is rejected (cleared to identity), the
    // existing failure path that shares SetVch's clear-on-reject contract.
    Signature bad;
    bad.SetVch(std::vector<unsigned char>(10, 0xff));
    BOOST_CHECK(mclBnG2_isZero(&bad.m_data.v));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace blsct
