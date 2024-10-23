// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>
#include <primitives/transaction.h>

#define ASSERT_SIZE_EQ(type, size) BOOST_CHECK_EQUAL(sizeof(type), size)

BOOST_FIXTURE_TEST_SUITE(external_api_tests, BasicTestingSetup)

// This test verifies the sizes of CMutableTransaction and
// all user-defined types within it to detect any structural
// changes in the CMutableTransaction class
BOOST_AUTO_TEST_CASE(test_cmutable_transaction_sizes)
{
    ASSERT_SIZE_EQ(Txid, 32);

    ASSERT_SIZE_EQ(CTxIn, 104);
    ASSERT_SIZE_EQ(COutPoint, 36);
    ASSERT_SIZE_EQ(CScript, 32);
    ASSERT_SIZE_EQ(CScriptWitness, 24);

    ASSERT_SIZE_EQ(CTxOutBLSCTData, 1248);
    ASSERT_SIZE_EQ(MclG1Point, 144);
    ASSERT_SIZE_EQ(bulletproofs::RangeProof<Mcl>, 808);

    ASSERT_SIZE_EQ(CTxOut, 1328);
    ASSERT_SIZE_EQ(CAmount, 8);
    ASSERT_SIZE_EQ(TokenId, 40);

    ASSERT_SIZE_EQ(CMutableTransaction, 344);
    ASSERT_SIZE_EQ(blsct::Signature, 288);
}

BOOST_AUTO_TEST_SUITE_END()

