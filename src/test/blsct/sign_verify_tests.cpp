// Copyright (c) 2022-2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_UNIT_TEST

#include <blst.h>
#include <blsct/common.h>
#include <blsct/private_key.h>
#include <blsct/public_key.h>
#include <blsct/public_keys.h>
#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

namespace blsct {

BOOST_FIXTURE_TEST_SUITE(sign_verify_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(test_compatibility_bet_bls_keys_and_blsct_keys)
{
    // A BLSCT private key is a raw BLS12-381 scalar; its public key is the
    // standard BLS min-pk key sk * G1 (blst_sk_to_pk_in_g1).
    blsct::PrivateKey blsct_sk(BlstScalar(int64_t{1}));
    BOOST_CHECK(blsct_sk.GetScalar() == BlstScalar(int64_t{1}));

    blsct::PublicKey blsct_pk = blsct_sk.GetPublicKey();
    BOOST_CHECK(blsct_pk.GetG1Point() == BlstG1Point::GetBasePoint());

    blsct::PrivateKey sk2(BlstScalar(int64_t{123456789}));
    blst_scalar raw;
    blst_scalar_from_fr(&raw, &sk2.GetScalar().GetUnderlying());
    blst_p1 pk;
    blst_sk_to_pk_in_g1(&pk, &raw);
    BOOST_CHECK(sk2.GetPublicKey().GetG1Point() == BlstG1Point(pk));

    // And the signature is the standard BLS signature over the same DST.
    std::vector<uint8_t> msg = {1, 2, 3};
    auto sig = sk2.CoreSign(msg);
    blst_p2 hash, expected;
    blst_hash_to_g2(&hash, msg.data(), msg.size(), reinterpret_cast<const byte*>(BLS_SIG_G2_DST), BLS_SIG_G2_DST_LEN, nullptr, 0);
    blst_sign_pk_in_g1(&expected, &hash, &raw);
    BOOST_CHECK(blst_p2_is_equal(&sig.m_data, &expected));
}

BOOST_AUTO_TEST_CASE(test_sign_verify_balance)
{
    blsct::PrivateKey sk(1);

    auto pk = sk.GetPublicKey();
    auto sig = sk.SignBalance();

    auto res = pk.VerifyBalance(sig);
    BOOST_CHECK(res == true);
}

BOOST_AUTO_TEST_CASE(test_sign_verify_balance_batch)
{
    blsct::PrivateKey sk1(1);
    blsct::PrivateKey sk2(12345);

    std::vector<blsct::Signature> sigs{
        sk1.SignBalance(),
        sk2.SignBalance(),
    };
    const std::vector<blsct::PublicKey> pks_backing{
        sk1.GetPublicKey(),
        sk2.GetPublicKey(),
    };
    PublicKeys pks(pks_backing);
    auto aggr_sig = blsct::Signature::Aggregate(sigs);
    auto res = pks.VerifyBalanceBatch(aggr_sig);

    BOOST_CHECK(res == true);
}

BOOST_AUTO_TEST_CASE(test_sign_verify_balance_batch_bad_inputs)
{
    const std::vector<blsct::PublicKey> empty_backing;
    PublicKeys pks(empty_backing);
    blsct::Signature aggr_sig;
    BOOST_CHECK_THROW(pks.VerifyBalanceBatch(aggr_sig), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(test_augment_message)
{
    auto pk = BlstG1Point::GetBasePoint();
    std::vector<uint8_t> pk_data = pk.GetVch();
    auto msg = std::vector<uint8_t>{1, 2, 3, 4, 5};
    auto act = PublicKey(pk).AugmentMessage(msg);

    auto exp = std::vector<uint8_t>(pk_data);
    exp.insert(exp.end(), msg.begin(), msg.end());
    BOOST_CHECK(act == exp);
}

BOOST_AUTO_TEST_CASE(test_sign_verify)
{
    blsct::PrivateKey sk(1);
    auto pk = sk.GetPublicKey();
    std::vector<uint8_t> msg{'m', 's', 'g'};

    auto sig = sk.Sign(msg);
    auto res = pk.Verify(msg, sig);
    BOOST_CHECK(res == true);
}

BOOST_AUTO_TEST_CASE(test_verify_batch)
{
    blsct::PrivateKey sk1(1);
    blsct::PrivateKey sk2(12345);

    const std::vector<blsct::PublicKey> pks_backing{
        sk1.GetPublicKey(),
        sk2.GetPublicKey(),
    };
    PublicKeys pks(pks_backing);
    std::vector<std::vector<uint8_t>> msgs{
        std::vector<uint8_t>{'m', 's', 'g', '1'},
        std::vector<uint8_t>{'m', 's', 'g', '2'},
    };
    std::vector<blsct::Signature> sigs{
        sk1.Sign(msgs[0]),
        sk2.Sign(msgs[1]),
    };
    auto aggr_sig = blsct::Signature::Aggregate(sigs);

    auto res = pks.VerifyBatch(msgs, aggr_sig);
    BOOST_CHECK(res == true);
}

BOOST_AUTO_TEST_CASE(test_verify_batch_bad_inputs)
{
    blsct::Signature sig;
    {
        // empty pks
        const std::vector<PublicKey> empty_backing;
        PublicKeys empty_pks(empty_backing);
        std::vector<std::vector<uint8_t>> msgs{
            std::vector<uint8_t>{'m', 's', 'g'},
        };
        BOOST_CHECK_THROW(empty_pks.VerifyBatch(msgs, sig), std::runtime_error);
    }
    {
        // empty msgs
        const std::vector<PublicKey> pks_backing{
            PublicKey(),
        };
        PublicKeys pks(pks_backing);
        std::vector<std::vector<uint8_t>> empty_msgs;
        BOOST_CHECK_THROW(pks.VerifyBatch(empty_msgs, sig), std::runtime_error);
    }
    {
        // numbers of pks and msgs don't match
        const std::vector<PublicKey> pks_backing{
            PublicKey(),
        };
        PublicKeys pks(pks_backing);
        std::vector<std::vector<uint8_t>> msgs{
            std::vector<uint8_t>{'m', 's', 'g', '1'},
            std::vector<uint8_t>{'m', 's', 'g', '2'},
        };
        BOOST_CHECK_THROW(pks.VerifyBatch(msgs, sig), std::runtime_error);
    }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace blsct
