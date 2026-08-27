// Copyright (c) 2022 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_UNIT_TEST

#include <blsct/range_proof/bulletproofs_plus/range_proof_logic.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof_with_transcript.h>
#include <blsct/range_proof/common.h>
#include <blsct/arith/mcl/mcl.h>
#include <test/util/setup_common.h>

#include <tinyformat.h>
#include <boost/test/unit_test.hpp>
#include <util/strencodings.h>
#include <limits>

BOOST_FIXTURE_TEST_SUITE(bulletproofs_plus_range_proof_logic_tests, BasicTestingSetup)

using T = Mcl;
using Point = T::Point;
using Points = Elements<Point>;
using Scalar = T::Scalar;
using Scalars = Elements<Scalar>;
using MsgPair = std::pair<std::string, std::vector<unsigned char>>;
using RangeProofLogic = bulletproofs_plus::RangeProofLogic<T>;

struct TestCase
{
    std::string name;
    Scalars values;
    bool is_batched;  // prove function is called once for with all values
    bool should_complete_recovery;
    size_t num_amounts;
    bool verify_result;
    MsgPair msg;
    Scalar min_value;
};

static MclG1Point GenNonce()
{
    std::string nonce_str("nonce");
    MclG1Point nonce = MclG1Point::HashAndMap(std::vector<unsigned char> { nonce_str.begin(), nonce_str.end() });
    return nonce;
}

static TokenId GenTokenId()
{
    TokenId token_id(uint256(uint64_t{123}));
    return token_id;
}

static MsgPair GenMsgPair(std::string s = "spaghetti meatballs")
{
    std::vector<unsigned char> message { s.begin(), s.end() };
    return std::pair(s, message);
}

BOOST_AUTO_TEST_CASE(test_range_proof_prove_verify_one_value)
{
    auto nonce = GenNonce();
    auto msg = GenMsgPair();
    auto token_id = GenTokenId();

    Scalars vs;

    // value = 2, gamma = 3
    Scalar v1(2);
    vs.Add(v1);

    // value = 5, gamma = 7
    Scalar v2(5);
    vs.Add(v2);

    RangeProofLogic rpl;
    auto p = rpl.Prove(vs, nonce, msg.second, token_id);

    auto is_valid = rpl.Verify(
        std::vector<bulletproofs_plus::RangeProofWithSeed<T>>{bulletproofs_plus::RangeProofWithSeed<T>(p, token_id)});
    BOOST_CHECK(is_valid);
}

BOOST_AUTO_TEST_CASE(test_range_proof_recovery_one_value)
{
    auto nonce = GenNonce();
    auto msg = GenMsgPair();
    auto token_id = GenTokenId();

    Scalar one(1);
    std::vector<Scalar> vs_vec;
    vs_vec.push_back(one);

    Scalars vs;
    vs.Add(one);

    RangeProofLogic rpl;
    auto p = rpl.Prove(vs, nonce, msg.second, token_id);
    bulletproofs_plus::RangeProofWithSeed<T> proofWithSeed = {p, token_id};

    auto req = bulletproofs_plus::AmountRecoveryRequest<T>::of(proofWithSeed, nonce);
    auto reqs = std::vector<bulletproofs_plus::AmountRecoveryRequest<T>> { req };
    auto result = rpl.RecoverAmounts(reqs);

    BOOST_CHECK(result.is_completed);
    auto xs = result.amounts;
    BOOST_CHECK(xs.size() == 1);
    BOOST_CHECK(xs[0].gamma == nonce.GetHashWithSalt(100));
    BOOST_CHECK(xs[0].amount == 1);
    BOOST_CHECK(xs[0].message == msg.first);
}

static std::vector<TestCase> BuildTestCases()
{
    bulletproofs_plus::RangeProofLogic<T> rp;
    std::vector<TestCase> test_cases;

    for (auto& lower_bound : {Scalar(0), Scalar(100)}) {
        Scalar one(1);
        Scalar two(2);
        Scalar upper_bound = (one << 64) - one; // int64_t max
        // [LB, LB+1, UB-1, UB]
        Scalars valid_inputs;
        valid_inputs.Add(lower_bound);
        valid_inputs.Add(lower_bound + one);
        valid_inputs.Add(upper_bound - one);
        valid_inputs.Add(upper_bound);

        // [-1, UB+1, UB+2, UB*2]
        Scalars invalid_inputs;
        invalid_inputs.Add(one.Negate());
        invalid_inputs.Add(upper_bound + one);
        invalid_inputs.Add(upper_bound + one + one);
        invalid_inputs.Add(upper_bound << 1);

        // test single valid value
        for (auto value : valid_inputs.m_vec) {
            Scalars values;
            values.Add(value);

            TestCase x;
            x.name = strprintf("valid input value %s min_value=%s", value.GetString(), lower_bound.GetString()).c_str();
            x.values = values;
            x.is_batched = false;
            x.should_complete_recovery = true;
            x.num_amounts = 1;
            x.msg = GenMsgPair();
            x.verify_result = x.values >= lower_bound && x.values <= (upper_bound + lower_bound);
            x.min_value = lower_bound;
            test_cases.push_back(x);
        }

        // test single invalid value
        for (auto value : invalid_inputs.m_vec) {
            Scalars values;
            values.Add(value);

            TestCase x;
            x.name = strprintf("invalid input value %s min_value=%s", value.GetString(), lower_bound.GetString()).c_str();
            x.values = values;
            x.is_batched = false;
            x.should_complete_recovery = true;
            x.num_amounts = 0;
            x.msg = GenMsgPair();
            x.verify_result = x.values >= lower_bound && x.values <= (upper_bound + lower_bound);
            x.min_value = lower_bound;
            test_cases.push_back(x);
        }

        // test batched valid values
        {
            TestCase x;
            x.name = "batched valid values";
            x.values = valid_inputs;
            x.is_batched = true;
            x.should_complete_recovery = true;
            x.num_amounts = 0;
            x.msg = GenMsgPair();
            x.verify_result = x.values >= lower_bound && x.values <= (upper_bound + lower_bound);
            x.min_value = lower_bound;
            test_cases.push_back(x);
        }

        // test batched invalid values
        {
            TestCase x;
            x.name = "batched invalid values";
            x.values = invalid_inputs;
            x.is_batched = true;
            x.should_complete_recovery = true;
            x.num_amounts = 0;
            x.msg = GenMsgPair();
            x.verify_result = x.values >= lower_bound && x.values <= (upper_bound + lower_bound);
            x.min_value = lower_bound;
            test_cases.push_back(x);
        }

        // test with messages of various length
        {
            Scalars values;
            values.Add(Scalar(1));

            std::vector<size_t> msg_sizes{1ul, 23ul, 24ul, range_proof::Setup::max_message_size};
            for (auto msg_size : msg_sizes) {
                TestCase x;
                x.name = strprintf("with message of length %d min_value=%s", msg_size, lower_bound.GetString()).c_str();
                x.values = values;
                x.is_batched = true;
                x.should_complete_recovery = true;
                x.num_amounts = 1;
                x.msg = GenMsgPair(std::string(msg_size, 'x'));
                x.verify_result = x.values >= lower_bound && x.values <= (upper_bound + lower_bound);
                x.min_value = lower_bound;
                test_cases.push_back(x);
            }
        }

        // test # of input values from 1 to max
        {
            for (size_t n = 1; n <= range_proof::Setup::max_input_values; ++n) {
                Scalars values;
                for (size_t i = 0; i < n; ++i) {
                    values.Add(Scalar(i + 1));
                }
                TestCase x;
                x.name = strprintf("%d valid input values min_value=%s", n, lower_bound.GetString()).c_str();
                x.values = values;
                x.is_batched = true;
                x.should_complete_recovery = true;
                x.num_amounts = n == 1 ? 1 : 0; // recovery should be performed only when n=1
                x.msg = GenMsgPair();
                x.verify_result = x.values >= lower_bound && x.values <= (upper_bound + lower_bound);
                x.min_value = lower_bound;
                test_cases.push_back(x);
            }
        }

        // test valid and invalid values mixed
        {
            Scalars values;
            for (auto& s : valid_inputs.m_vec)
                values.Add(s);
            for (auto& s : invalid_inputs.m_vec)
                values.Add(s);

            TestCase x;
            x.name = "mix of valid and invalid values";
            x.values = values;
            x.is_batched = true;
            x.should_complete_recovery = true;
            x.num_amounts = 0;
            x.msg = GenMsgPair();
            x.verify_result = x.values >= lower_bound && x.values <= (upper_bound + lower_bound);
            x.min_value = lower_bound;
            test_cases.push_back(x);
        }

        {
            // string of maximum message size 54
            const std::string s("Pneumonoultramicroscopicsilicovolcanoconiosis123456789");
            assert(s.size() == range_proof::Setup::max_message_size);
            Scalars values;
            values.Add(one);

            for (size_t i = 0; i <= s.size(); ++i) { // try message of size 0 to 54
                auto msg = s.substr(0, i);

                TestCase x;
                x.name = strprintf("message size %ld min_value=%s", i, lower_bound.GetString()).c_str();
                x.values = values;
                x.is_batched = false;
                x.should_complete_recovery = true;
                x.num_amounts = 1;
                x.msg = GenMsgPair(msg);
                x.verify_result = x.values >= lower_bound && x.values <= (upper_bound + lower_bound);

                x.min_value = lower_bound;
                test_cases.push_back(x);
            }
        }
    }

    return test_cases;
}

static void RunTestCase(
    bulletproofs_plus::RangeProofLogic<T>& rp,
    TestCase& test_case)
{
    auto token_id = GenTokenId();
    auto nonce = GenNonce();

    std::vector<bulletproofs_plus::RangeProofWithSeed<T>> proofs;

    // calculate proofs
    if (test_case.is_batched) {
        auto proof = rp.Prove(test_case.values, nonce, test_case.msg.second, token_id, test_case.min_value);
        bulletproofs_plus::RangeProofWithSeed<T> p{proof, token_id, test_case.min_value};
        proofs.emplace_back(p);
    } else {
        for (auto value : test_case.values.m_vec) {
            Scalars single_value_vec;
            single_value_vec.Add(value);

            auto proof = rp.Prove(single_value_vec, nonce, test_case.msg.second, token_id, test_case.min_value);
            bulletproofs_plus::RangeProofWithSeed<T> p{proof, token_id, test_case.min_value};
            proofs.emplace_back(p);
        }
    }

    // verify proofs
    auto verify_result = rp.Verify(proofs);
    BOOST_CHECK(verify_result == test_case.verify_result);

    // recover value, gamma and message
    std::vector<bulletproofs_plus::AmountRecoveryRequest<T>> reqs;

    reqs.reserve(proofs.size());
for (size_t i = 0; i < proofs.size(); ++i) {
        reqs.push_back(bulletproofs_plus::AmountRecoveryRequest<T>::of(proofs[i], nonce));
    }
    auto recovery_result = rp.RecoverAmounts(reqs);
    BOOST_CHECK(recovery_result.is_completed == test_case.should_complete_recovery);

    if (recovery_result.is_completed) {
        auto amounts = recovery_result.amounts;

        BOOST_CHECK(amounts.size() == test_case.num_amounts);

        for (size_t i = 0; i < amounts.size(); ++i) {
            auto x = amounts[i];
            auto gamma = nonce.GetHashWithSalt(100 + i);
            BOOST_CHECK(((uint64_t)x.amount) == test_case.values[i].GetUint64());
            BOOST_CHECK(x.gamma == gamma);

            std::vector<unsigned char> x_msg(x.message.begin(), x.message.end());
            BOOST_CHECK(x_msg == test_case.msg.second);
        }
    }
}

BOOST_AUTO_TEST_CASE(test_range_proof_prove_verify_recovery)
{
    auto test_cases = BuildTestCases();
    bulletproofs_plus::RangeProofLogic<T> rp;
    for (auto test_case: test_cases) {
        RunTestCase(rp, test_case);
    }
}

BOOST_AUTO_TEST_CASE(test_range_proof_message_size)
{
    Scalars values;
    values.Add(Scalar(1));
    MclG1Point nonce = MclG1Point::GetBasePoint();
    TokenId token_id;
    RangeProofLogic rpl;

    {
        // empty msg
        std::vector<unsigned char> msg;
        BOOST_CHECK_NO_THROW(rpl.Prove(values, nonce, msg, token_id));
    }
    {
        // msg of valid size
        std::string s(range_proof::Setup::max_message_size, 'x');
        std::vector<unsigned char> msg(s.begin(), s.end());
        BOOST_CHECK_NO_THROW(rpl.Prove(values, nonce, msg, token_id));
    }
    {
        // msg of exceeded size
        std::string s(range_proof::Setup::max_message_size + 1, 'x');
        std::vector<unsigned char> msg(s.begin(), s.end());
        BOOST_CHECK_THROW(rpl.Prove(values, nonce, msg, token_id), std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(test_range_proof_number_of_input_values)
{
    MclG1Point nonce = MclG1Point::GetBasePoint();
    std::vector<unsigned char> msg;
    TokenId token_id;
    RangeProofLogic rpl;

    {
        // should throw if there is no input value
        Scalars values;
        BOOST_CHECK_THROW(rpl.Prove(values, nonce, msg, token_id), std::runtime_error);
    }
    {
        // should not throw if number of input values is within the valid range
        Scalars values;
        values.Add(Scalar(1));
        BOOST_CHECK_NO_THROW(rpl.Prove(values, nonce, msg, token_id));
    }
    {
        // should throw if number of input values is outsize the valid range
        Scalars values;
        for (size_t i=0; i<range_proof::Setup::max_input_values + 1; ++i) {
            values.Add(Scalar(1));
        }
        BOOST_CHECK_THROW(rpl.Prove(values, nonce, msg, token_id), std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(test_range_proof_validate_proofs_by_sizes)
{
    auto gen_valid_proof_wo_value_commitments = [](size_t num_inputs) {
        bulletproofs_plus::RangeProofWithSeed<T> p;
        auto n = blsct::Common::GetFirstPowerOf2GreaterOrEqTo(num_inputs);
        for (size_t i=0; i<n; ++i) {
            p.Vs.Add(MclG1Point::GetBasePoint());
        }
        auto num_rounds = range_proof::Common<T>::GetNumRoundsExclLast(n);
        for (size_t i=0; i<num_rounds; ++i) {
            p.Ls.Add(MclG1Point::GetBasePoint());
            p.Rs.Add(MclG1Point::GetBasePoint());
        }
        return p;
    };

    {
        // no proof should validate fine
        std::vector<bulletproofs_plus::RangeProofWithSeed<T>> proofs;
        BOOST_CHECK_NO_THROW(range_proof::Common<T>::ValidateProofsBySizes(proofs));
    }
    {
        // no value commitment
        bulletproofs_plus::RangeProofWithSeed<T> p;
        std::vector<bulletproofs_plus::RangeProofWithSeed<T>> proofs{p};
        BOOST_CHECK_THROW(range_proof::Common<T>::ValidateProofsBySizes(proofs), std::runtime_error);
    }
    {
        // minimum number of value commitments
        auto p = gen_valid_proof_wo_value_commitments(1);
        std::vector<bulletproofs_plus::RangeProofWithSeed<T>> proofs{p};
        BOOST_CHECK_NO_THROW(range_proof::Common<T>::ValidateProofsBySizes(proofs));
    }
    {
        // maximum number of value commitments
        auto p = gen_valid_proof_wo_value_commitments(range_proof::Setup::max_input_values);
        std::vector<bulletproofs_plus::RangeProofWithSeed<T>> proofs{p};
        BOOST_CHECK_NO_THROW(range_proof::Common<T>::ValidateProofsBySizes(proofs));
    }
    {
        // number of value commitments exceeding maximum
        auto p = gen_valid_proof_wo_value_commitments(range_proof::Setup::max_input_values + 1);
        std::vector<bulletproofs_plus::RangeProofWithSeed<T>> proofs{p};
        BOOST_CHECK_THROW(range_proof::Common<T>::ValidateProofsBySizes(proofs), std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(test_range_proof_compute_d)
{
    size_t m = 3;
    size_t n = 4;
    Scalar two(2);
    Scalar z(3);

    Scalars two_pows = Scalars::FirstNPow(two, n);
    Scalar z_sq = z.Square();
    Scalars z_asc_by_2_pows = RangeProofLogic::ComputeZAscBy2Pows(z, m);

    Scalars d = RangeProofLogic::Compute_D(z_asc_by_2_pows, two_pows, z_sq, m);

    BOOST_CHECK_EQUAL(d.Size(), 12);
    BOOST_CHECK_EQUAL(d[0].GetUint64(), 1 * 3*3);
    BOOST_CHECK_EQUAL(d[1].GetUint64(), 2 * 3*3);
    BOOST_CHECK_EQUAL(d[2].GetUint64(), 4 * 3*3);
    BOOST_CHECK_EQUAL(d[3].GetUint64(), 8 * 3*3);
    BOOST_CHECK_EQUAL(d[4].GetUint64(), 1 * 3*3*3*3);
    BOOST_CHECK_EQUAL(d[5].GetUint64(), 2 * 3*3*3*3);
    BOOST_CHECK_EQUAL(d[6].GetUint64(), 4 * 3*3*3*3);
    BOOST_CHECK_EQUAL(d[7].GetUint64(), 8 * 3*3*3*3);
    BOOST_CHECK_EQUAL(d[8].GetUint64(), 1 * 3*3*3*3*3*3);
    BOOST_CHECK_EQUAL(d[9].GetUint64(), 2 * 3*3*3*3*3*3);
    BOOST_CHECK_EQUAL(d[10].GetUint64(), 4 * 3*3*3*3*3*3);
    BOOST_CHECK_EQUAL(d[11].GetUint64(), 8 * 3*3*3*3*3*3);
}

BOOST_AUTO_TEST_CASE(test_range_proof_get_num_leading_zeros)
{
    uint32_t n = std::numeric_limits<uint32_t>::max();

    for (size_t i=0; i<=32; ++i) {
        size_t num_zeros = RangeProofLogic::GetNumLeadingZeros(n);
        if (i == 32) {  // when n == 0
            BOOST_CHECK_EQUAL(num_zeros, 0);
        } else {  // when n > 0
            BOOST_CHECK_EQUAL(num_zeros, i);
            n >>= 1;
        }
    }
}

BOOST_AUTO_TEST_CASE(test_range_proof_transcript_v2_roundtrip)
{
    auto nonce = GenNonce();
    auto msg = GenMsgPair();
    auto token_id = GenTokenId();

    Scalars vs;
    vs.Add(Scalar(2));
    vs.Add(Scalar(5));

    RangeProofLogic rpl;

    // v1 (legacy) prove + verify still round-trips: the default path is
    // unchanged, so no existing proof is invalidated.
    auto p_v1 = rpl.Prove(vs, nonce, msg.second, token_id, Scalar(0), /*transcript_v2=*/false);
    {
        bulletproofs_plus::RangeProofWithSeed<T> s(p_v1, token_id);
        s.transcript_v2 = false;
        BOOST_CHECK(rpl.Verify(std::vector<bulletproofs_plus::RangeProofWithSeed<T>>{s}));
    }

    // v2 prove + v2 verify round-trips.
    auto p_v2 = rpl.Prove(vs, nonce, msg.second, token_id, Scalar(0), /*transcript_v2=*/true);
    {
        bulletproofs_plus::RangeProofWithSeed<T> s(p_v2, token_id);
        s.transcript_v2 = true;
        BOOST_CHECK(rpl.Verify(std::vector<bulletproofs_plus::RangeProofWithSeed<T>>{s}));
    }

    // The two transcripts are genuinely different: a v1 proof verified under
    // the v2 rule and a v2 proof verified under the v1 rule both fail. This is
    // what makes the height gate a real rule change rather than a no-op.
    {
        bulletproofs_plus::RangeProofWithSeed<T> s(p_v1, token_id);
        s.transcript_v2 = true;
        BOOST_CHECK(!rpl.Verify(std::vector<bulletproofs_plus::RangeProofWithSeed<T>>{s}));
    }
    {
        bulletproofs_plus::RangeProofWithSeed<T> s(p_v2, token_id);
        s.transcript_v2 = false;
        BOOST_CHECK(!rpl.Verify(std::vector<bulletproofs_plus::RangeProofWithSeed<T>>{s}));
    }
}

BOOST_AUTO_TEST_CASE(test_range_proof_transcript_v2_binds_A)
{
    // Regression test for the transcript ordering difference between v1 and v2.
    //
    // Under the legacy (v1) transcript, the y and z challenges are derived from
    // the value commitments alone and A is absorbed only afterwards, so (y, z)
    // do not depend on A. Under v2, A is absorbed into the transcript before y
    // and z are drawn, so (y, z) do depend on A.
    //
    // This test pins that property directly: modifying A leaves (y, z) unchanged
    // under v1 but changes them under v2.
    auto nonce = GenNonce();
    auto msg = GenMsgPair();
    auto token_id = GenTokenId();
    Scalars vs;
    vs.Add(Scalar(2));

    RangeProofLogic rpl;
    const Point tamper = Point::GetBasePoint();

    // --- v1: A is NOT bound into y/z ---
    auto p1 = rpl.Prove(vs, nonce, msg.second, token_id, Scalar(0), /*transcript_v2=*/false);
    bulletproofs_plus::RangeProofWithSeed<T> s1(p1, token_id);
    s1.transcript_v2 = false;
    auto t1 = bulletproofs_plus::RangeProofWithTranscript<T>::Build(s1);

    bulletproofs_plus::RangeProofWithSeed<T> s1_tampered(p1, token_id);
    s1_tampered.transcript_v2 = false;
    s1_tampered.A = s1_tampered.A + tamper; // modify A after y,z are derived
    auto t1_tampered = bulletproofs_plus::RangeProofWithTranscript<T>::Build(s1_tampered);

    // y and z are unchanged despite A changing -> A is not bound into them.
    BOOST_CHECK(t1.y == t1_tampered.y);
    BOOST_CHECK(t1.z == t1_tampered.z);

    // --- v2: A IS bound into y/z ---
    auto p2 = rpl.Prove(vs, nonce, msg.second, token_id, Scalar(0), /*transcript_v2=*/true);
    bulletproofs_plus::RangeProofWithSeed<T> s2(p2, token_id);
    s2.transcript_v2 = true;
    auto t2 = bulletproofs_plus::RangeProofWithTranscript<T>::Build(s2);

    bulletproofs_plus::RangeProofWithSeed<T> s2_tampered(p2, token_id);
    s2_tampered.transcript_v2 = true;
    s2_tampered.A = s2_tampered.A + tamper;
    auto t2_tampered = bulletproofs_plus::RangeProofWithTranscript<T>::Build(s2_tampered);

    // y (and hence z) change with A -> A is absorbed before the challenges are
    // drawn, so the challenges are bound to A.
    BOOST_CHECK(t2.y != t2_tampered.y);
}

BOOST_AUTO_TEST_SUITE_END()
