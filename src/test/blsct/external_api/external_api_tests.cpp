// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/eip_2333/bls12_381_keygen.h>
#include <blsct/external_api/blsct.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof_logic.h>
#include <blsct/tokens/predicate_parser.h>
#include <blsct/wallet/txfactory.h>
#include <blsct/wallet/unsigned_transaction.h>
#include <blsct/wallet/verification.h>
#include <core_io.h>
#include <hash.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <txdb.h>
#include <util/strencodings.h>
#include <wallet/receive.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(external_api_tests, BasicTestingSetup)

uint8_t hex_to_uint(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    } else {
        throw std::invalid_argument("Unexpected hex char found");
    }
}

static std::map<std::string, std::string> g_collected_map;
static void CollectMapEntry(const char* key, const char* value, void* /*user_data*/)
{
    g_collected_map[key] = value;
}

static std::map<std::string, std::string> ReadTokenInfoMetadata(const char* hex)
{
    g_collected_map.clear();
    get_token_info_metadata(hex, CollectMapEntry, nullptr);
    return g_collected_map;
}

static std::map<std::string, std::string> ReadMintNftMetadata(const uint8_t* pred, size_t len)
{
    g_collected_map.clear();
    get_mint_nft_predicate_metadata(pred, len, CollectMapEntry, nullptr);
    return g_collected_map;
}

// This test checks if there is any structural change in
// CMutableTransaction and its dependencies
BOOST_AUTO_TEST_CASE(test_cmutable_transaction_sizes)
{
    // in case there is a structural change in CMutableTransaction,
    // tx_hex needs to be regenerated to reflect the structure change
    std::string tx_hex = "200000000100000000000000000000000000000000000000000000000000000000000000000503615d0200ffffffff02ffffffffffffff7f0100000000000000015101855f4e35c5fbe93bf5b8a7a2dc55420144388fd0736ce7d9c8289e793da409d89f2bf2f4f4ac9364d81922d9255c33880683ed1c387aa2555b28af1c6d2b4a2725af9551263c00962daeec3736de0724167d18579973ff9cfcaeedc9ed59036aaaa2ad79cef575dc618d14729169a88c87edb5d3303efab1109572ca4a98800d61c45d8ca9074a7beb9c5c4123e7af8054b4bce1a360c663b86e8af1f06dea120fce8d7529b90ff383fd69c7dd9a50215881df91544949b95eaeac780c133699bdb030b321c32c0efbafa29fe840fe93b01bffc47e096a4577f5ba7d6745506f5e658cbd21c0c7f4c5fc28fdb28dd1c27a8027da5ca650a48ced1c52725abc54a1bd54e9823341753de270ea7882fd54b5b7513d9184635b9dbf0812ccf769df4cb50985bfa52fa515fa7034a317b2da1453d2d919797a22e6889c8aada6fe25e2dfda8f57f57de8fc2a9fa957d264240d06b8548ad7eec8b644df2e89b9a5a1d83ecce4ca94005b7d61782743e74ed011f7cc96c634327b67cfbc954de4effa0d7884f88d27ac1c1686bad02f527975ed9f3e7b2570120dc68ad88ddd350119d00c6df24916d5fc361f20f4f4d4482711b5850b3f91c9315beb1af544d63ed7049b6a1af783e0171526ba9c31466de735527d2d1bfeaf292a73ecf0312e6e784ae18dc6949e4a452fadc0734bff7bdf56074434f7a311290ba2ec6cbe960e29829d2b8ad6fb7946e356580b5a40f9676274a8336c5eecc36a9ddb58bb81cd8d08dfda7714aa9634941a94076cbc3ed74561d9043146dc81f1ccafd4e06f98faae3da017fe07af9ac407d0b81e6e1e634e5b53f5f98728850298673e355093844d0443466fad33d233ed7c40c1788a43d4d48d63778e8cf80e9cd5d01e789637b0cae99a372dd0bc8b5dbf2bc2df9fea229d71eaebab6a9277bb3bb3ba07c14edef6a7fcdcf02e8c1e927872003b9683d3b3ff1e740d5ec8a8145361166b33da8dcda6edf5d7bf32f63d27a5b72e515e6641b672275eee06f3bd5abd6790eded07d49b9e55e5c29e136eb5ad4857f9f55b6e7be10d2002ed91244243ea0fe7b6dea43ea70eb0d3d438ae2a335ced8e1620392562a2c503d2c4b53bed0d39c3749cb032741cacd0ca73bc6d72d350184cc82a45ad8df2e3443599ba51dfd5dce328362f9032cb350f579234f36c282d4b0acdf27d6a8d66f62713adf6481c8c9f240f59a15c6e064a5c05b56e6c068801f639ee1e83003a6a8dd97d5c24b5236c30d43efa0d75709fcaba4ca72077232f537900b2697973d2a08ee405d4298d4a8afeb24f6066b9648b3265e10931756678606fc173b92525567648af5408ff6af65eece8bbe70c671f9f8b94f012dd97eb3f8efcbeae6b34fc2fa3932ffac63b68c7167eeea1b7798872c92e40c057663cd1bdd07ce887a175b0feb74c394f9232dbaf3c8bd84e5624c2b6ca3605cfe3a1acfd1c5871a54d5a5b497588916840d422eeabc75d528275e0f7db46d95654ec9453c20000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9000000008a8c3b2f2bafb7b71f9192b2b8e02df5caf27c04b535ef577c0703f820a110155984f294bc01fccaf6957b622156a97712e57526ce7ef914af67e7aea2fd3daf8a4176660300ea64be6ab6c87b1a597cb96f7d5ac0ab59fe115190bc33946ba3";

    DataStream st{ParseHex(tx_hex)};
    TransactionSerParams params{.allow_witness = true};
    ParamsStream ps{params, st};

    CMutableTransaction tx;

    try {
        tx.Unserialize(ps); // should not throw an exception
    } catch (...) {
        BOOST_CHECK(false);
    }
}

BOOST_AUTO_TEST_CASE(test_build_tx_in_gamma_is_blsct_scalar)
{
    init();

    // create a random scalar to use as gamma
    auto gamma_rv = gen_random_scalar();
    BOOST_REQUIRE_EQUAL(gamma_rv.result, BLSCT_SUCCESS);
    auto* gamma = &gamma_rv.value;

    // create a spending key
    auto sk_rv = gen_random_scalar();
    BOOST_REQUIRE_EQUAL(sk_rv.result, BLSCT_SUCCESS);
    auto* spending_key = &sk_rv.value;

    // create a token id
    auto tid_rv = gen_default_token_id();
    BOOST_REQUIRE_EQUAL(tid_rv.result, BLSCT_SUCCESS);
    auto* token_id = &tid_rv.value;

    // create an out point
    std::string txid_hex(64, '0');
    auto op_rv = gen_out_point(txid_hex.c_str());
    BOOST_REQUIRE_EQUAL(op_rv.result, BLSCT_SUCCESS);
    auto* out_point = &op_rv.value;

    auto tx_in_rv = build_tx_in(
        1000,
        gamma,
        spending_key,
        token_id,
        out_point,
        false,
        false);
    BOOST_REQUIRE_EQUAL(tx_in_rv.result, BLSCT_SUCCESS);
    auto* tx_in = &tx_in_rv.value;

    // verify the amount round-trips
    auto amt_rv = get_tx_in_amount(tx_in);
    BOOST_REQUIRE_EQUAL(amt_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(amt_rv.value, 1000ULL);

    // verify the gamma round-trips as a full 32-byte scalar
    BlsctScalarResult retrieved_gamma_rv = get_tx_in_gamma(tx_in);
    BOOST_REQUIRE_EQUAL(retrieved_gamma_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK(are_scalar_equal(gamma, &retrieved_gamma_rv.value) == 1);
}

BOOST_AUTO_TEST_CASE(test_amount_recovery_returns_gamma)
{
    init();

    uint64_t amount = 42;
    std::string msg = "hello";
    std::vector<uint8_t> msg_vec(msg.begin(), msg.end());

    auto tid_rv = gen_default_token_id();
    BOOST_REQUIRE_EQUAL(tid_rv.result, BLSCT_SUCCESS);
    auto* blsct_token_id = &tid_rv.value;

    TokenId token_id;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_token_id, TOKEN_ID_SIZE, token_id);

    // build a range proof using the C++ API so we know the expected gamma
    bulletproofs_plus::RangeProofLogic<Mcl> rpl;
    Scalars vs;
    vs.Add(Mcl::Scalar(static_cast<int64_t>(amount)));
    auto nonce = Mcl::Point::Rand();
    auto range_proof = rpl.Prove(vs, nonce, msg_vec, token_id);

    // recover via C++ API to get expected gamma
    auto cpp_req = bulletproofs_plus::AmountRecoveryRequest<Mcl>::of(range_proof, nonce);
    auto cpp_result = rpl.RecoverAmounts({cpp_req});
    BOOST_REQUIRE(cpp_result.is_completed);
    BOOST_REQUIRE_EQUAL(cpp_result.amounts.size(), 1u);
    Scalar expected_gamma = cpp_result.amounts[0].gamma;

    // serialize range proof for the C API
    DataStream rp_st{};
    range_proof.Serialize(rp_st);
    size_t rp_size = rp_st.size();
    auto* rp_buf = static_cast<BlsctRangeProof*>(malloc(rp_size));
    std::memcpy(rp_buf, rp_st.data(), rp_size);

    // serialize nonce for the C API
    BlsctPoint blsct_nonce;
    SERIALIZE_AND_COPY(nonce, blsct_nonce);

    BlsctAmountRecoveryReq req{};
    req.range_proof = rp_buf;
    req.range_proof_size = rp_size;
    std::memcpy(req.nonce, blsct_nonce, POINT_SIZE);
    std::memcpy(req.token_id, tid_rv.value, TOKEN_ID_SIZE);

    BlsctAmountRecoveryResult result{};
    BOOST_REQUIRE_EQUAL(recover_amount(&req, 1, &result), BLSCT_SUCCESS);
    BOOST_CHECK(result.is_succ);
    BOOST_CHECK_EQUAL(result.amount, amount);

    // verify the gamma matches the expected value from the C++ recovery
    BlsctScalar expected_gamma_bytes;
    SERIALIZE_AND_COPY(expected_gamma, expected_gamma_bytes);
    BOOST_CHECK(are_scalar_equal(&result.gamma, &expected_gamma_bytes) == 1);

    free(rp_buf);
}

BOOST_AUTO_TEST_CASE(test_recovered_gamma_round_trips_through_tx_in)
{
    init();

    uint64_t amount = 100;
    std::string msg = "rt";
    std::vector<uint8_t> msg_vec(msg.begin(), msg.end());

    auto tid_rv = gen_default_token_id();
    BOOST_REQUIRE_EQUAL(tid_rv.result, BLSCT_SUCCESS);
    auto* blsct_token_id = &tid_rv.value;

    TokenId token_id;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_token_id, TOKEN_ID_SIZE, token_id);

    // produce a range proof and recover to get a real gamma
    bulletproofs_plus::RangeProofLogic<Mcl> rpl;
    Scalars vs;
    vs.Add(Mcl::Scalar(static_cast<int64_t>(amount)));
    auto nonce = Mcl::Point::Rand();
    auto range_proof = rpl.Prove(vs, nonce, msg_vec, token_id);

    DataStream rp_st{};
    range_proof.Serialize(rp_st);
    auto* rp_buf = static_cast<BlsctRangeProof*>(malloc(rp_st.size()));
    std::memcpy(rp_buf, rp_st.data(), rp_st.size());

    BlsctPoint blsct_nonce;
    SERIALIZE_AND_COPY(nonce, blsct_nonce);

    BlsctAmountRecoveryReq req{};
    req.range_proof = rp_buf;
    req.range_proof_size = rp_st.size();
    std::memcpy(req.nonce, blsct_nonce, POINT_SIZE);
    std::memcpy(req.token_id, tid_rv.value, TOKEN_ID_SIZE);

    BlsctAmountRecoveryResult result{};
    BOOST_REQUIRE_EQUAL(recover_amount(&req, 1, &result), BLSCT_SUCCESS);
    BOOST_REQUIRE(result.is_succ);

    // feed the recovered gamma directly into build_tx_in
    auto sk_rv = gen_random_scalar();
    BOOST_REQUIRE_EQUAL(sk_rv.result, BLSCT_SUCCESS);
    auto* spending_key = &sk_rv.value;

    std::string txid_hex(64, '0');
    auto op_rv = gen_out_point(txid_hex.c_str());
    BOOST_REQUIRE_EQUAL(op_rv.result, BLSCT_SUCCESS);
    auto* out_point = &op_rv.value;

    auto tx_in_rv = build_tx_in(
        amount,
        &result.gamma,
        spending_key,
        blsct_token_id,
        out_point,
        false,
        false);
    BOOST_REQUIRE_EQUAL(tx_in_rv.result, BLSCT_SUCCESS);
    auto* tx_in = &tx_in_rv.value;

    // the gamma stored in the tx_in must equal the recovered gamma
    BlsctScalarResult tx_in_gamma_rv = get_tx_in_gamma(tx_in);
    BOOST_CHECK(are_scalar_equal(&result.gamma, &tx_in_gamma_rv.value) == 1);

    free(rp_buf);
}

BOOST_AUTO_TEST_CASE(test_token_info_predicates_and_unsigned_outputs)
{
    init();

    const char* meta_keys[] = {"name", "symbol"};
    const char* meta_vals[] = {"Collection", "COLL"};

    auto collection_hash_rv = calc_collection_token_hash(meta_keys, meta_vals, 2, 1000);
    BOOST_REQUIRE_EQUAL(collection_hash_rv.result, BLSCT_SUCCESS);
    auto* collection_hash = &collection_hash_rv.value;

    const std::map<std::string, std::string> expected_metadata{{"name", "Collection"}, {"symbol", "COLL"}};
    const uint256 expected_collection_hash = (HashWriter{} << expected_metadata << CAmount{1000}).GetHash();
    BOOST_CHECK(std::memcmp(collection_hash, expected_collection_hash.begin(), UINT256_SIZE) == 0);

    auto master_token_key_rv = gen_scalar(42);
    BOOST_REQUIRE_EQUAL(master_token_key_rv.result, BLSCT_SUCCESS);
    auto* master_token_key = &master_token_key_rv.value;

    auto token_key_rv = derive_collection_token_key(master_token_key, collection_hash);
    BOOST_REQUIRE_EQUAL(token_key_rv.result, BLSCT_SUCCESS);
    auto* token_key = &token_key_rv.value;

    MclScalar expected_token_key = BLS12_381_KeyGen::derive_child_SK_hash(MclScalar(uint64_t{42}), expected_collection_hash);
    MclScalar token_key_native;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(token_key, SCALAR_SIZE, token_key_native);
    BOOST_CHECK(token_key_native == expected_token_key);

    BlsctPubKeyResult token_public_key_rv = derive_collection_token_public_key(master_token_key, collection_hash);
    BOOST_REQUIRE_EQUAL(token_public_key_rv.result, BLSCT_SUCCESS);
    auto* token_public_key = &token_public_key_rv.value;

    size_t token_info_len = 0;
    BOOST_REQUIRE_EQUAL(build_token_info(BlsctToken, token_public_key, meta_keys, meta_vals, 2, 1000, nullptr, 0, &token_info_len), BLSCT_SUCCESS);
    std::vector<char> token_info_hex(token_info_len + 1);
    BOOST_REQUIRE_EQUAL(build_token_info(BlsctToken, token_public_key, meta_keys, meta_vals, 2, 1000, token_info_hex.data(), token_info_hex.size(), &token_info_len), BLSCT_SUCCESS);
    auto type_rv = get_token_info_type(token_info_hex.data());
    BOOST_REQUIRE_EQUAL(type_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(type_rv.value, BlsctToken);
    BOOST_CHECK_EQUAL(get_token_info_total_supply(token_info_hex.data()).value, 1000U);

    BOOST_CHECK(ReadTokenInfoMetadata(token_info_hex.data()) == expected_metadata);

    size_t create_pred_len = 0;
    BOOST_REQUIRE_EQUAL(build_create_token_predicate(token_info_hex.data(), nullptr, 0, &create_pred_len), BLSCT_SUCCESS);
    std::vector<uint8_t> create_pred_buf(create_pred_len);
    BOOST_REQUIRE_EQUAL(build_create_token_predicate(token_info_hex.data(), create_pred_buf.data(), create_pred_buf.size(), &create_pred_len), BLSCT_SUCCESS);
    auto* create_pred = create_pred_buf.data();
    auto create_pred_type_rv = get_vector_predicate_type(create_pred, create_pred_len);
    BOOST_REQUIRE_EQUAL(create_pred_type_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(create_pred_type_rv.value, BlsctCreateTokenPredicateType);

    size_t parsed_token_info_len = 0;
    BOOST_REQUIRE_EQUAL(get_create_token_predicate_token_info(create_pred, create_pred_len, nullptr, 0, &parsed_token_info_len), BLSCT_SUCCESS);
    std::vector<char> parsed_token_info_hex(parsed_token_info_len + 1);
    BOOST_REQUIRE_EQUAL(get_create_token_predicate_token_info(create_pred, create_pred_len, parsed_token_info_hex.data(), parsed_token_info_hex.size(), &parsed_token_info_len), BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(std::string(parsed_token_info_hex.data()), std::string(token_info_hex.data()));

    size_t mint_pred_len = 0;
    BOOST_REQUIRE_EQUAL(build_mint_token_predicate(token_public_key, 25, nullptr, 0, &mint_pred_len), BLSCT_SUCCESS);
    std::vector<uint8_t> mint_pred_buf(mint_pred_len);
    BOOST_REQUIRE_EQUAL(build_mint_token_predicate(token_public_key, 25, mint_pred_buf.data(), mint_pred_buf.size(), &mint_pred_len), BLSCT_SUCCESS);
    auto* mint_pred = mint_pred_buf.data();
    auto mint_pred_type_rv = get_vector_predicate_type(mint_pred, mint_pred_len);
    BOOST_REQUIRE_EQUAL(mint_pred_type_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(mint_pred_type_rv.value, BlsctMintTokenPredicateType);
    BOOST_CHECK_EQUAL(get_mint_token_predicate_amount(mint_pred, mint_pred_len).value, 25U);

    BlsctPubKeyResult mint_pred_pub_key_rv = get_mint_token_predicate_public_key(mint_pred, mint_pred_len);
    BOOST_REQUIRE_EQUAL(mint_pred_pub_key_rv.result, BLSCT_SUCCESS);
    BlsctPointHexResult token_pub_hex_rv = serialize_public_key(reinterpret_cast<const BlsctPoint*>(token_public_key));
    BlsctPointHexResult mint_pub_hex_rv = serialize_public_key(reinterpret_cast<const BlsctPoint*>(&mint_pred_pub_key_rv.value));
    BOOST_REQUIRE_EQUAL(token_pub_hex_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(mint_pub_hex_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(std::string(token_pub_hex_rv.value), std::string(mint_pub_hex_rv.value));

    const char* nft_keys[] = {"rarity"};
    const char* nft_vals[] = {"legendary"};

    size_t mint_nft_pred_len = 0;
    BOOST_REQUIRE_EQUAL(build_mint_nft_predicate(token_public_key, 7, nft_keys, nft_vals, 1, nullptr, 0, &mint_nft_pred_len), BLSCT_SUCCESS);
    std::vector<uint8_t> mint_nft_pred_buf(mint_nft_pred_len);
    BOOST_REQUIRE_EQUAL(build_mint_nft_predicate(token_public_key, 7, nft_keys, nft_vals, 1, mint_nft_pred_buf.data(), mint_nft_pred_buf.size(), &mint_nft_pred_len), BLSCT_SUCCESS);
    auto* mint_nft_pred = mint_nft_pred_buf.data();
    auto mint_nft_pred_type_rv = get_vector_predicate_type(mint_nft_pred, mint_nft_pred_len);
    BOOST_REQUIRE_EQUAL(mint_nft_pred_type_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(mint_nft_pred_type_rv.value, BlsctMintNftPredicateType);
    BOOST_CHECK_EQUAL(get_mint_nft_predicate_nft_id(mint_nft_pred, mint_nft_pred_len).value, 7U);

    const std::map<std::string, std::string> expected_nft_metadata{{"rarity", "legendary"}};
    BOOST_CHECK(ReadMintNftMetadata(mint_nft_pred, mint_nft_pred_len) == expected_nft_metadata);

    auto view_key_rv = gen_scalar(11);
    auto spend_key_rv = gen_scalar(12);
    BOOST_REQUIRE_EQUAL(view_key_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(spend_key_rv.result, BLSCT_SUCCESS);
    BlsctPubKeyResult spend_pub_key_rv = scalar_to_pub_key(&spend_key_rv.value);
    BOOST_REQUIRE_EQUAL(spend_pub_key_rv.result, BLSCT_SUCCESS);
    auto* spend_pub_key = &spend_pub_key_rv.value;
    BlsctSubAddrIdResult sub_addr_id_rv = gen_sub_addr_id(0, 1);
    BOOST_REQUIRE_EQUAL(sub_addr_id_rv.result, BLSCT_SUCCESS);
    auto* sub_addr_id = &sub_addr_id_rv.value;
    BlsctSubAddrResult dest_rv = derive_sub_address(&view_key_rv.value, spend_pub_key, sub_addr_id);
    BOOST_REQUIRE_EQUAL(dest_rv.result, BLSCT_SUCCESS);
    auto* dest = &dest_rv.value;
    auto blinding_key_rv = gen_scalar(99);
    BOOST_REQUIRE_EQUAL(blinding_key_rv.result, BLSCT_SUCCESS);

    size_t create_output_len = 0;
    BOOST_REQUIRE_EQUAL(build_unsigned_create_token_output(token_key, token_info_hex.data(), nullptr, 0, &create_output_len), BLSCT_SUCCESS);
    std::vector<char> create_output_hex(create_output_len + 1);
    BOOST_REQUIRE_EQUAL(build_unsigned_create_token_output(token_key, token_info_hex.data(), create_output_hex.data(), create_output_hex.size(), &create_output_len), BLSCT_SUCCESS);
    {
        DataStream st{ParseHex(create_output_hex.data())};
        blsct::UnsignedOutput output;
        st >> output;
        auto parsed = blsct::ParsePredicate(output.out.predicate);
        BOOST_CHECK(parsed.IsCreateTokenPredicate());
        BOOST_CHECK_EQUAL(parsed.GetTokenInfo().nTotalSupply, 1000);
    }

    size_t mint_output_len = 0;
    BOOST_REQUIRE_EQUAL(build_unsigned_mint_token_output(dest, 25, &blinding_key_rv.value, token_key, token_public_key, nullptr, 0, &mint_output_len), BLSCT_SUCCESS);
    std::vector<char> mint_output_hex(mint_output_len + 1);
    BOOST_REQUIRE_EQUAL(build_unsigned_mint_token_output(dest, 25, &blinding_key_rv.value, token_key, token_public_key, mint_output_hex.data(), mint_output_hex.size(), &mint_output_len), BLSCT_SUCCESS);
    {
        DataStream st{ParseHex(mint_output_hex.data())};
        blsct::UnsignedOutput output;
        st >> output;
        auto parsed = blsct::ParsePredicate(output.out.predicate);
        BOOST_CHECK(parsed.IsMintTokenPredicate());
        BOOST_CHECK_EQUAL(parsed.GetAmount(), 25);
    }

    size_t mint_nft_output_len = 0;
    BOOST_REQUIRE_EQUAL(build_unsigned_mint_nft_output(dest, &blinding_key_rv.value, token_key, token_public_key, 7, nft_keys, nft_vals, 1, nullptr, 0, &mint_nft_output_len), BLSCT_SUCCESS);
    std::vector<char> mint_nft_output_hex(mint_nft_output_len + 1);
    BOOST_REQUIRE_EQUAL(build_unsigned_mint_nft_output(dest, &blinding_key_rv.value, token_key, token_public_key, 7, nft_keys, nft_vals, 1, mint_nft_output_hex.data(), mint_nft_output_hex.size(), &mint_nft_output_len), BLSCT_SUCCESS);
    {
        DataStream st{ParseHex(mint_nft_output_hex.data())};
        blsct::UnsignedOutput output;
        st >> output;
        auto parsed = blsct::ParsePredicate(output.out.predicate);
        BOOST_CHECK(parsed.IsMintNftPredicate());
        BOOST_CHECK_EQUAL(parsed.GetNftId(), 7U);
        BOOST_CHECK(parsed.GetNftMetaData() == expected_nft_metadata);
    }
}

BOOST_AUTO_TEST_CASE(test_unsigned_transaction_sign)
{
    init();

    auto view_key_rv = gen_scalar(21);
    auto spend_key_rv = gen_scalar(22);
    auto input_spending_key_rv = gen_scalar(23);
    auto gamma_rv = gen_scalar(24);
    auto blinding_key_rv = gen_scalar(25);
    auto default_token_id_rv = gen_default_token_id();
    BOOST_REQUIRE_EQUAL(view_key_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(spend_key_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(input_spending_key_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(gamma_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(blinding_key_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(default_token_id_rv.result, BLSCT_SUCCESS);

    BlsctPubKeyResult spend_pub_key_rv = scalar_to_pub_key(&spend_key_rv.value);
    BOOST_REQUIRE_EQUAL(spend_pub_key_rv.result, BLSCT_SUCCESS);
    auto* spend_pub_key = &spend_pub_key_rv.value;
    BlsctSubAddrIdResult sub_addr_id_rv = gen_sub_addr_id(0, 2);
    BOOST_REQUIRE_EQUAL(sub_addr_id_rv.result, BLSCT_SUCCESS);
    auto* sub_addr_id = &sub_addr_id_rv.value;
    BlsctSubAddrResult dest_rv = derive_sub_address(&view_key_rv.value, spend_pub_key, sub_addr_id);
    BOOST_REQUIRE_EQUAL(dest_rv.result, BLSCT_SUCCESS);
    auto* dest = &dest_rv.value;

    auto out_point_rv = gen_out_point("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    BOOST_REQUIRE_EQUAL(out_point_rv.result, BLSCT_SUCCESS);

    auto tx_in_rv = build_tx_in(
        1000,
        &gamma_rv.value,
        &input_spending_key_rv.value,
        &default_token_id_rv.value,
        &out_point_rv.value,
        false,
        false);
    BOOST_REQUIRE_EQUAL(tx_in_rv.result, BLSCT_SUCCESS);

    size_t unsigned_input_len = 0;
    BOOST_REQUIRE_EQUAL(build_unsigned_input(&tx_in_rv.value, nullptr, 0, &unsigned_input_len), BLSCT_SUCCESS);
    std::vector<char> unsigned_input_hex(unsigned_input_len + 1);
    BOOST_REQUIRE_EQUAL(build_unsigned_input(&tx_in_rv.value, unsigned_input_hex.data(), unsigned_input_hex.size(), &unsigned_input_len), BLSCT_SUCCESS);

    auto tx_out_rv = build_tx_out(
        dest,
        500,
        "memo",
        &default_token_id_rv.value,
        TxOutputType::Normal,
        0,
        false,
        &blinding_key_rv.value);
    BOOST_REQUIRE_EQUAL(tx_out_rv.result, BLSCT_SUCCESS);

    size_t unsigned_output_len = 0;
    BOOST_REQUIRE_EQUAL(build_unsigned_output(&tx_out_rv.value, nullptr, 0, &unsigned_output_len), BLSCT_SUCCESS);
    std::vector<char> unsigned_output_hex(unsigned_output_len + 1);
    BOOST_REQUIRE_EQUAL(build_unsigned_output(&tx_out_rv.value, unsigned_output_hex.data(), unsigned_output_hex.size(), &unsigned_output_len), BLSCT_SUCCESS);

    const char* input_hexes[] = {unsigned_input_hex.data()};
    const char* output_hexes[] = {unsigned_output_hex.data()};

    size_t signed_tx_len;
    BLSCT_RESULT signed_tx_r = sign_unsigned_transaction(input_hexes, 1, output_hexes, 1, 125, nullptr, 0, &signed_tx_len);
    BOOST_REQUIRE_EQUAL(signed_tx_r, BLSCT_SUCCESS);
    std::vector<char> signed_tx_hex_buf(signed_tx_len + 1);
    sign_unsigned_transaction(input_hexes, 1, output_hexes, 1, 125, signed_tx_hex_buf.data(), signed_tx_hex_buf.size(), nullptr);
    const char* signed_tx_hex = signed_tx_hex_buf.data();

    CMutableTransaction decoded;
    BOOST_REQUIRE(DecodeHexTx(decoded, signed_tx_hex));
    CTransaction signed_tx(decoded);
    BOOST_CHECK(signed_tx.IsBLSCT());
    BOOST_CHECK_EQUAL(signed_tx.vin.size(), 1U);
    BOOST_CHECK_EQUAL(signed_tx.vout.size(), 2U);
    BOOST_CHECK_EQUAL(signed_tx.vout.back().nValue, 125);
    auto fee_predicate = blsct::ParsePredicate(signed_tx.vout.back().predicate);
    BOOST_CHECK(fee_predicate.IsPayFeePredicate());
}

BOOST_AUTO_TEST_CASE(test_are_ctx_in_equal)
{
    init();

    // create two CTxIns with different out_points
    uint256 hash_a, hash_b;
    hash_a.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    hash_b.SetHex("2222222222222222222222222222222222222222222222222222222222222222");

    CTxIn tx_in_a{COutPoint{hash_a}};
    CTxIn tx_in_b{COutPoint{hash_b}};

    // same object should be equal
    BOOST_CHECK(are_ctx_in_equal(&tx_in_a, &tx_in_a));

    // different out_points should not be equal
    BOOST_CHECK(!are_ctx_in_equal(&tx_in_a, &tx_in_b));
}

BOOST_AUTO_TEST_CASE(test_aggregate_transactions)
{
    init();

    const auto build_signed_tx = [](const uint64_t seed_base, const char* out_point_hex, const uint64_t output_amount, const uint64_t fee) {
        auto view_key_rv = gen_scalar(seed_base + 1);
        auto spend_key_rv = gen_scalar(seed_base + 2);
        auto input_spending_key_rv = gen_scalar(seed_base + 3);
        auto gamma_rv = gen_scalar(seed_base + 4);
        auto blinding_key_rv = gen_scalar(seed_base + 5);
        auto default_token_id_rv = gen_default_token_id();

        BOOST_REQUIRE_EQUAL(view_key_rv.result, BLSCT_SUCCESS);
        BOOST_REQUIRE_EQUAL(spend_key_rv.result, BLSCT_SUCCESS);
        BOOST_REQUIRE_EQUAL(input_spending_key_rv.result, BLSCT_SUCCESS);
        BOOST_REQUIRE_EQUAL(gamma_rv.result, BLSCT_SUCCESS);
        BOOST_REQUIRE_EQUAL(blinding_key_rv.result, BLSCT_SUCCESS);
        BOOST_REQUIRE_EQUAL(default_token_id_rv.result, BLSCT_SUCCESS);

        BlsctPubKeyResult spend_pub_key_rv = scalar_to_pub_key(&spend_key_rv.value);
        BOOST_REQUIRE_EQUAL(spend_pub_key_rv.result, BLSCT_SUCCESS);
        auto* spend_pub_key = &spend_pub_key_rv.value;

        BlsctSubAddrIdResult sub_addr_id_rv = gen_sub_addr_id(0, seed_base);
        BOOST_REQUIRE_EQUAL(sub_addr_id_rv.result, BLSCT_SUCCESS);
        auto* sub_addr_id = &sub_addr_id_rv.value;
        BlsctSubAddrResult dest_rv = derive_sub_address(&view_key_rv.value, spend_pub_key, sub_addr_id);
        BOOST_REQUIRE_EQUAL(dest_rv.result, BLSCT_SUCCESS);
        auto* dest = &dest_rv.value;

        auto out_point_rv = gen_out_point(out_point_hex);
        BOOST_REQUIRE_EQUAL(out_point_rv.result, BLSCT_SUCCESS);

        auto tx_in_rv = build_tx_in(
            1000,
            &gamma_rv.value,
            &input_spending_key_rv.value,
            &default_token_id_rv.value,
            &out_point_rv.value,
            false,
            false);
        BOOST_REQUIRE_EQUAL(tx_in_rv.result, BLSCT_SUCCESS);

        size_t unsigned_input_len = 0;
        BOOST_REQUIRE_EQUAL(build_unsigned_input(&tx_in_rv.value, nullptr, 0, &unsigned_input_len), BLSCT_SUCCESS);
        std::vector<char> unsigned_input_hex(unsigned_input_len + 1);
        BOOST_REQUIRE_EQUAL(build_unsigned_input(&tx_in_rv.value, unsigned_input_hex.data(), unsigned_input_hex.size(), &unsigned_input_len), BLSCT_SUCCESS);

        auto tx_out_rv = build_tx_out(
            dest,
            output_amount,
            "aggregate",
            &default_token_id_rv.value,
            TxOutputType::Normal,
            0,
            false,
            &blinding_key_rv.value);
        BOOST_REQUIRE_EQUAL(tx_out_rv.result, BLSCT_SUCCESS);

        size_t unsigned_output_len = 0;
        BOOST_REQUIRE_EQUAL(build_unsigned_output(&tx_out_rv.value, nullptr, 0, &unsigned_output_len), BLSCT_SUCCESS);
        std::vector<char> unsigned_output_hex(unsigned_output_len + 1);
        BOOST_REQUIRE_EQUAL(build_unsigned_output(&tx_out_rv.value, unsigned_output_hex.data(), unsigned_output_hex.size(), &unsigned_output_len), BLSCT_SUCCESS);

        const char* in_hexes[] = {unsigned_input_hex.data()};
        const char* out_hexes[] = {unsigned_output_hex.data()};

        size_t signed_tx_len;
        BLSCT_RESULT signed_tx_r = sign_unsigned_transaction(in_hexes, 1, out_hexes, 1, fee, nullptr, 0, &signed_tx_len);
        BOOST_REQUIRE_EQUAL(signed_tx_r, BLSCT_SUCCESS);
        std::vector<char> signed_tx_buf(signed_tx_len + 1);
        sign_unsigned_transaction(in_hexes, 1, out_hexes, 1, fee, signed_tx_buf.data(), signed_tx_buf.size(), nullptr);
        const std::string signed_tx_hex(signed_tx_buf.data());

        return signed_tx_hex;
    };

    const std::string tx1 = build_signed_tx(31, "1111111111111111111111111111111111111111111111111111111111111111", 400, 125);
    const std::string tx2 = build_signed_tx(41, "2222222222222222222222222222222222222222222222222222222222222222", 300, 200);

    const char* tx_hexes[] = {tx1.c_str(), tx2.c_str()};

    size_t agg_len;
    BLSCT_RESULT agg_r = aggregate_transactions(tx_hexes, 2, nullptr, 0, &agg_len);
    BOOST_REQUIRE_EQUAL(agg_r, BLSCT_SUCCESS);
    std::vector<char> agg_buf(agg_len + 1);
    aggregate_transactions(tx_hexes, 2, agg_buf.data(), agg_buf.size(), nullptr);
    const char* aggregate_hex = agg_buf.data();

    CMutableTransaction decoded;
    BOOST_REQUIRE(DecodeHexTx(decoded, aggregate_hex));
    CTransaction aggregated_tx(decoded);
    BOOST_CHECK(aggregated_tx.IsBLSCT());
    BOOST_CHECK_EQUAL(aggregated_tx.vin.size(), 2U);
    BOOST_CHECK_EQUAL(aggregated_tx.vout.size(), 3U);
    BOOST_CHECK_EQUAL(aggregated_tx.vout.back().nValue, 325);
    auto fee_predicate = blsct::ParsePredicate(aggregated_tx.vout.back().predicate);
    BOOST_CHECK(fee_predicate.IsPayFeePredicate());
}

// ---------------------------------------------------------------------------
// Smoke tests for previously untested CTx accessor functions
// ---------------------------------------------------------------------------

// Helper: build a signed tx hex via the unsigned-tx C API
static std::string BuildSignedTxHex(uint64_t seed_base, uint64_t input_amount, uint64_t output_amount, uint64_t fee)
{
    auto view_key_rv = gen_scalar(seed_base + 1);
    auto spend_key_rv = gen_scalar(seed_base + 2);
    auto input_sk_rv = gen_scalar(seed_base + 3);
    auto gamma_rv = gen_scalar(seed_base + 4);
    auto blind_rv = gen_scalar(seed_base + 5);
    auto tid_rv = gen_default_token_id();
    BOOST_REQUIRE_EQUAL(view_key_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(spend_key_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(input_sk_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(gamma_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(blind_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(tid_rv.result, BLSCT_SUCCESS);

    BlsctPubKeyResult spend_pub_rv = scalar_to_pub_key(&spend_key_rv.value);
    BlsctSubAddrIdResult sub_id_rv = gen_sub_addr_id(0, seed_base);
    BOOST_REQUIRE_EQUAL(spend_pub_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(sub_id_rv.result, BLSCT_SUCCESS);
    auto* spend_pub = &spend_pub_rv.value;
    auto* sub_id = &sub_id_rv.value;
    BlsctSubAddrResult dest_rv2 = derive_sub_address(&view_key_rv.value, spend_pub, sub_id);
    BOOST_REQUIRE_EQUAL(dest_rv2.result, BLSCT_SUCCESS);
    auto* dest = &dest_rv2.value;

    auto op_rv = gen_out_point("aabbccdd0011223344556677889900aabbccddeeff00112233445566778899aa");
    BOOST_REQUIRE_EQUAL(op_rv.result, BLSCT_SUCCESS);

    auto in_rv = build_tx_in(input_amount,
                             &gamma_rv.value,
                             &input_sk_rv.value,
                             &tid_rv.value,
                             &op_rv.value, false, false);
    BOOST_REQUIRE_EQUAL(in_rv.result, BLSCT_SUCCESS);

    size_t uin_len = 0;
    BOOST_REQUIRE_EQUAL(build_unsigned_input(&in_rv.value, nullptr, 0, &uin_len), BLSCT_SUCCESS);
    std::vector<char> uin_hex(uin_len + 1);
    BOOST_REQUIRE_EQUAL(build_unsigned_input(&in_rv.value, uin_hex.data(), uin_hex.size(), &uin_len), BLSCT_SUCCESS);

    auto out_rv = build_tx_out(dest, output_amount, "smoke",
                               &tid_rv.value,
                               TxOutputType::Normal, 0, false,
                               &blind_rv.value);
    BOOST_REQUIRE_EQUAL(out_rv.result, BLSCT_SUCCESS);

    size_t uout_len = 0;
    BOOST_REQUIRE_EQUAL(build_unsigned_output(&out_rv.value, nullptr, 0, &uout_len), BLSCT_SUCCESS);
    std::vector<char> uout_hex(uout_len + 1);
    BOOST_REQUIRE_EQUAL(build_unsigned_output(&out_rv.value, uout_hex.data(), uout_hex.size(), &uout_len), BLSCT_SUCCESS);

    const char* in_hexes[] = {uin_hex.data()};
    const char* out_hexes[] = {uout_hex.data()};

    size_t signed_len;
    BLSCT_RESULT signed_r = sign_unsigned_transaction(in_hexes, 1, out_hexes, 1, fee, nullptr, 0, &signed_len);
    BOOST_REQUIRE_EQUAL(signed_r, BLSCT_SUCCESS);
    std::vector<char> signed_buf(signed_len + 1);
    sign_unsigned_transaction(in_hexes, 1, out_hexes, 1, fee, signed_buf.data(), signed_buf.size(), nullptr);
    std::string hex(signed_buf.data());

    return hex;
}

// Build a signed CMutableTransaction from hex
static CMutableTransaction DecodeTx(const std::string& hex)
{
    CMutableTransaction tx;
    BOOST_REQUIRE(DecodeHexTx(tx, hex));
    return tx;
}

// Build a signed tx hex via the unsigned-tx C API (ctx-level accessor input)
static std::string BuildCtxViaApi(uint64_t input_amount, uint64_t output_amount, uint64_t fee = 125)
{
    auto view_key_rv = gen_scalar(201);
    auto spend_key_rv = gen_scalar(202);
    auto input_sk_rv = gen_scalar(203);
    auto gamma_rv = gen_scalar(204);
    auto blind_rv = gen_scalar(205);
    auto tid_rv = gen_default_token_id();
    BOOST_REQUIRE_EQUAL(view_key_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(spend_key_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(input_sk_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(gamma_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(blind_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(tid_rv.result, BLSCT_SUCCESS);

    BlsctPubKeyResult spend_pub_rv2 = scalar_to_pub_key(&spend_key_rv.value);
    BlsctSubAddrIdResult sub_id_rv2 = gen_sub_addr_id(0, 7);
    BOOST_REQUIRE_EQUAL(spend_pub_rv2.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(sub_id_rv2.result, BLSCT_SUCCESS);
    auto* spend_pub = &spend_pub_rv2.value;
    auto* sub_id = &sub_id_rv2.value;
    BlsctSubAddrResult dest_rv3 = derive_sub_address(&view_key_rv.value, spend_pub, sub_id);
    BOOST_REQUIRE_EQUAL(dest_rv3.result, BLSCT_SUCCESS);
    auto* dest = &dest_rv3.value;

    auto op_rv = gen_out_point("deadbeef0000000000000000000000000000000000000000000000000000cafe");
    BOOST_REQUIRE_EQUAL(op_rv.result, BLSCT_SUCCESS);

    auto in_rv = build_tx_in(input_amount,
                             &gamma_rv.value,
                             &input_sk_rv.value,
                             &tid_rv.value,
                             &op_rv.value, false, false);
    BOOST_REQUIRE_EQUAL(in_rv.result, BLSCT_SUCCESS);

    size_t uin_len = 0;
    BOOST_REQUIRE_EQUAL(build_unsigned_input(&in_rv.value, nullptr, 0, &uin_len), BLSCT_SUCCESS);
    std::vector<char> uin_hex(uin_len + 1);
    BOOST_REQUIRE_EQUAL(build_unsigned_input(&in_rv.value, uin_hex.data(), uin_hex.size(), &uin_len), BLSCT_SUCCESS);

    auto out_rv = build_tx_out(dest, output_amount, "ctxtest",
                               &tid_rv.value,
                               TxOutputType::Normal, 0, false,
                               &blind_rv.value);
    BOOST_REQUIRE_EQUAL(out_rv.result, BLSCT_SUCCESS);

    size_t uout_len = 0;
    BOOST_REQUIRE_EQUAL(build_unsigned_output(&out_rv.value, nullptr, 0, &uout_len), BLSCT_SUCCESS);
    std::vector<char> uout_hex(uout_len + 1);
    BOOST_REQUIRE_EQUAL(build_unsigned_output(&out_rv.value, uout_hex.data(), uout_hex.size(), &uout_len), BLSCT_SUCCESS);

    const char* in_hexes[] = {uin_hex.data()};
    const char* out_hexes[] = {uout_hex.data()};

    size_t signed_len;
    BLSCT_RESULT signed_r = sign_unsigned_transaction(in_hexes, 1, out_hexes, 1, fee, nullptr, 0, &signed_len);
    BOOST_REQUIRE_EQUAL(signed_r, BLSCT_SUCCESS);
    std::vector<char> signed_buf(signed_len + 1);
    sign_unsigned_transaction(in_hexes, 1, out_hexes, 1, fee, signed_buf.data(), signed_buf.size(), nullptr);

    return std::string(signed_buf.data());
}

BOOST_AUTO_TEST_CASE(test_build_ctx_and_serialization)
{
    init();

    std::string ctx_hex = BuildCtxViaApi(1000, 500);
    BOOST_REQUIRE(!ctx_hex.empty());

    // get_ctx_id returns a non-empty hex string
    BlsctCTxIdHexResult ctx_id_rv = get_ctx_id(ctx_hex.c_str());
    BOOST_REQUIRE_EQUAL(ctx_id_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(std::strlen(ctx_id_rv.value), 64u); // 32 bytes = 64 hex chars

    // same hex produces same id (round-trip is implicit — the hex IS the serialized form)
    BlsctCTxIdHexResult ctx_id2_rv = get_ctx_id(ctx_hex.c_str());
    BOOST_REQUIRE_EQUAL(ctx_id2_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(std::string(ctx_id_rv.value), std::string(ctx_id2_rv.value));
}

BOOST_AUTO_TEST_CASE(test_ctx_in_vector_accessors)
{
    init();

    std::string tx_hex = BuildSignedTxHex(51, 1000, 400, 100);
    CMutableTransaction mtx = DecodeTx(tx_hex);
    BOOST_CHECK(!mtx.vin.empty());

    std::string ctx_hex = BuildCtxViaApi(1000, 400);
    BOOST_REQUIRE(!ctx_hex.empty());

    auto ins_sz_rv = get_ctx_ins_size(ctx_hex.c_str());
    BOOST_REQUIRE_EQUAL(ins_sz_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(ins_sz_rv.value, 1u);
}

BOOST_AUTO_TEST_CASE(test_ctx_in_field_accessors)
{
    init();

    std::string ctx_hex = BuildCtxViaApi(1000, 500);
    BOOST_REQUIRE(!ctx_hex.empty());

    // prev_out_hash is a 32-byte CTxId
    BlsctCTxIdResult prev_hash_rv = get_ctx_in_prev_out_hash_at(ctx_hex.c_str(), 0);
    BOOST_REQUIRE_EQUAL(prev_hash_rv.result, BLSCT_SUCCESS);
    // BuildCtxViaApi uses a hard-coded non-zero outpoint hash ("deadbeef..."), so must be non-zero
    bool all_zero = true;
    for (size_t i = 0; i < CTX_ID_SIZE; ++i) {
        if (prev_hash_rv.value[i] != 0) {
            all_zero = false;
            break;
        }
    }
    BOOST_CHECK(!all_zero);

    // scriptSig (blsct inputs have empty scriptSig)
    BlsctScriptResult script_sig_rv = get_ctx_in_script_sig_at(ctx_hex.c_str(), 0);
    BOOST_REQUIRE_EQUAL(script_sig_rv.result, BLSCT_SUCCESS);

    // sequence — non-rbf input => 0xffffffff
    auto seq_rv = get_ctx_in_sequence_at(ctx_hex.c_str(), 0);
    BOOST_REQUIRE_EQUAL(seq_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(seq_rv.value, 0xffffffffU);

    // scriptWitness
    BlsctScriptResult witness_rv = get_ctx_in_script_witness_at(ctx_hex.c_str(), 0);
    BOOST_REQUIRE_EQUAL(witness_rv.result, BLSCT_SUCCESS);
}

BOOST_AUTO_TEST_CASE(test_ctx_out_vector_and_field_accessors)
{
    init();

    const uint64_t test_fee = 125;
    std::string ctx_hex = BuildCtxViaApi(2000, 800, test_fee);
    BOOST_REQUIRE(!ctx_hex.empty());

    // 1 data output + 1 fee output = 2
    auto outs_sz_rv = get_ctx_outs_size(ctx_hex.c_str());
    BOOST_REQUIRE_EQUAL(outs_sz_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(outs_sz_rv.value, 2u);

    // out0 = data output, out1 = fee output
    // data output nValue is 0 (actual amount is in the range proof)
    BOOST_CHECK_EQUAL(get_ctx_out_value_at(ctx_hex.c_str(), 0).value, 0u);

    // fee output nValue is the fee amount
    BOOST_CHECK_EQUAL(get_ctx_out_value_at(ctx_hex.c_str(), 1).value, test_fee);

    // data output: scriptPubKey
    BlsctScriptResult spk_rv = get_ctx_out_script_pub_key_at(ctx_hex.c_str(), 0);
    BOOST_REQUIRE_EQUAL(spk_rv.result, BLSCT_SUCCESS);

    // data output: token_id
    BlsctTokenIdResult tok_rv = get_ctx_out_token_id_at(ctx_hex.c_str(), 0);
    BOOST_REQUIRE_EQUAL(tok_rv.result, BLSCT_SUCCESS);

    // data output: spending_key, ephemeral_key, blinding_key
    BlsctPointResult sk_rv = get_ctx_out_spending_key_at(ctx_hex.c_str(), 0);
    BOOST_REQUIRE_EQUAL(sk_rv.result, BLSCT_SUCCESS);

    BlsctPointResult ek_rv = get_ctx_out_ephemeral_key_at(ctx_hex.c_str(), 0);
    BOOST_REQUIRE_EQUAL(ek_rv.result, BLSCT_SUCCESS);

    BlsctPointResult bk_rv = get_ctx_out_blinding_key_at(ctx_hex.c_str(), 0);
    BOOST_REQUIRE_EQUAL(bk_rv.result, BLSCT_SUCCESS);

    // data output: view_tag
    BlsctUint16Result vt_rv = get_ctx_out_view_tag_at(ctx_hex.c_str(), 0);
    BOOST_REQUIRE_EQUAL(vt_rv.result, BLSCT_SUCCESS);

    // data output: range_proof (non-empty)
    size_t rp_len = 0;
    BOOST_REQUIRE_EQUAL(get_ctx_out_range_proof_at(ctx_hex.c_str(), 0, nullptr, 0, &rp_len), BLSCT_SUCCESS);
    BOOST_CHECK(rp_len > 0);
    std::vector<uint8_t> rp_buf(rp_len);
    BOOST_REQUIRE_EQUAL(get_ctx_out_range_proof_at(ctx_hex.c_str(), 0, rp_buf.data(), rp_buf.size(), &rp_len), BLSCT_SUCCESS);

    // fee output: vector_predicate (PayFeePredicate)
    size_t pred_len = 0;
    BOOST_REQUIRE_EQUAL(get_ctx_out_vector_predicate_at(ctx_hex.c_str(), 1, nullptr, 0, &pred_len), BLSCT_SUCCESS);
    BOOST_CHECK(pred_len > 0);

    // are_ctx_outs_equal — same hex compared to itself
    BOOST_CHECK(are_ctx_outs_equal(ctx_hex.c_str(), ctx_hex.c_str()));
}

BOOST_AUTO_TEST_CASE(test_ctx_vector_equal_handles_null_inputs)
{
    init();

    BOOST_CHECK(!are_ctx_ins_equal(nullptr, nullptr));
    BOOST_CHECK(!are_ctx_outs_equal(nullptr, nullptr));
}

BOOST_AUTO_TEST_CASE(test_ctx_in_equal_handles_null_inputs)
{
    init();

    uint256 hash;
    hash.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    CTxIn tx_in{COutPoint{hash}};
    const void* p = reinterpret_cast<const void*>(&tx_in);

    BOOST_CHECK(!are_ctx_in_equal(nullptr, nullptr));
    BOOST_CHECK(!are_ctx_in_equal(nullptr, p));
    BOOST_CHECK(!are_ctx_in_equal(p, nullptr));
}

BOOST_AUTO_TEST_CASE(test_ctx_out_equal_handles_null_inputs)
{
    init();

    CTxOut tx_out{};
    const void* p = reinterpret_cast<const void*>(&tx_out);

    BOOST_CHECK(!are_ctx_out_equal(nullptr, nullptr));
    BOOST_CHECK(!are_ctx_out_equal(nullptr, p));
    BOOST_CHECK(!are_ctx_out_equal(p, nullptr));
}


BOOST_AUTO_TEST_CASE(test_get_ctx_out_vector_predicate_handles_null)
{
    init();

    size_t pred_len = 0;
    BLSCT_RESULT rv = get_ctx_out_vector_predicate(nullptr, nullptr, 0, &pred_len);
    BOOST_CHECK(rv != BLSCT_SUCCESS);
}

BOOST_AUTO_TEST_CASE(test_ctx_ins_equality_across_instances)
{
    init();

    // Build two ctxs via BuildCtxViaApi and compare their ins/outs
    std::string hex_a = BuildCtxViaApi(1500, 600);
    std::string hex_b = BuildCtxViaApi(1500, 600);
    BOOST_REQUIRE(!hex_a.empty() && !hex_b.empty());

    // Both have 1 input
    auto ins_a_rv = get_ctx_ins_size(hex_a.c_str());
    BOOST_REQUIRE_EQUAL(ins_a_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(ins_a_rv.value, 1u);
    auto ins_b_rv = get_ctx_ins_size(hex_b.c_str());
    BOOST_REQUIRE_EQUAL(ins_b_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(ins_b_rv.value, 1u);

    auto outs_a_rv = get_ctx_outs_size(hex_a.c_str());
    BOOST_REQUIRE_EQUAL(outs_a_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(outs_a_rv.value, 2u);
    auto outs_b_rv = get_ctx_outs_size(hex_b.c_str());
    BOOST_REQUIRE_EQUAL(outs_b_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(outs_b_rv.value, 2u);
}

// ---------------------------------------------------------------------------
// Smoke tests for range proof functions
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_range_proof_build_and_verify)
{
    init();

    auto tid_rv = gen_default_token_id();
    BOOST_REQUIRE_EQUAL(tid_rv.result, BLSCT_SUCCESS);

    // Create a nonce
    auto nonce_rv = gen_base_point();
    BOOST_REQUIRE_EQUAL(nonce_rv.result, BLSCT_SUCCESS);

    // Build range proof
    uint64_t amounts[] = {42};
    size_t rp_len = 0;
    BOOST_REQUIRE_EQUAL(build_range_proof(amounts, 1, &nonce_rv.value, "smoke_test", &tid_rv.value, nullptr, 0, &rp_len), BLSCT_SUCCESS);
    BOOST_CHECK(rp_len > 0);
    std::vector<uint8_t> rp_buf(rp_len);
    BOOST_REQUIRE_EQUAL(build_range_proof(amounts, 1, &nonce_rv.value, "smoke_test", &tid_rv.value, rp_buf.data(), rp_buf.size(), &rp_len), BLSCT_SUCCESS);

    // Accessor getters — each returns a typed result struct
    BlsctPointResult rp_A_rv = get_range_proof_A(rp_buf.data(), rp_len);
    BlsctPointResult rp_A_wip_rv = get_range_proof_A_wip(rp_buf.data(), rp_len);
    BlsctPointResult rp_B_rv = get_range_proof_B(rp_buf.data(), rp_len);
    BOOST_REQUIRE_EQUAL(rp_A_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(rp_A_wip_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(rp_B_rv.result, BLSCT_SUCCESS);

    BlsctScalarResult rp_r_prime_rv = get_range_proof_r_prime(rp_buf.data(), rp_len);
    BlsctScalarResult rp_s_prime_rv = get_range_proof_s_prime(rp_buf.data(), rp_len);
    BlsctScalarResult rp_delta_prime_rv = get_range_proof_delta_prime(rp_buf.data(), rp_len);
    BlsctScalarResult rp_alpha_hat_rv = get_range_proof_alpha_hat(rp_buf.data(), rp_len);
    BlsctScalarResult rp_tau_x_rv = get_range_proof_tau_x(rp_buf.data(), rp_len);
    BOOST_REQUIRE_EQUAL(rp_r_prime_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(rp_s_prime_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(rp_delta_prime_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(rp_alpha_hat_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(rp_tau_x_rv.result, BLSCT_SUCCESS);

    // Verify
    const BlsctRangeProof* proofs[] = {rp_buf.data()};
    size_t proof_sizes[] = {rp_len};
    auto verify_rv = verify_range_proofs(proofs, proof_sizes, 1);
    BOOST_REQUIRE_EQUAL(verify_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK(verify_rv.value);

    // Serialize / deserialize round-trip
    auto rp_sz_rv = serialize_range_proof(rp_buf.data(), rp_len, nullptr, 0);
    BOOST_REQUIRE_EQUAL(rp_sz_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE(rp_sz_rv.value > 0);
    std::vector<char> rp_hex(rp_sz_rv.value + 1);
    auto rp_w_rv = serialize_range_proof(rp_buf.data(), rp_len, rp_hex.data(), rp_hex.size());
    BOOST_REQUIRE_EQUAL(rp_w_rv.result, BLSCT_SUCCESS);

    size_t deser_len = 0;
    BOOST_REQUIRE_EQUAL(deserialize_range_proof(rp_hex.data(), rp_len, nullptr, 0, &deser_len), BLSCT_SUCCESS);
    std::vector<uint8_t> deser_buf(deser_len);
    BOOST_REQUIRE_EQUAL(deserialize_range_proof(rp_hex.data(), rp_len, deser_buf.data(), deser_buf.size(), &deser_len), BLSCT_SUCCESS);
}

// ---------------------------------------------------------------------------
// Smoke test for are_vector_predicate_equal
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_vector_predicate_equality)
{
    init();

    auto pk_rv = gen_random_public_key();
    BOOST_REQUIRE_EQUAL(pk_rv.result, BLSCT_SUCCESS);

    size_t pred_a_len = 0;
    BOOST_REQUIRE_EQUAL(build_mint_token_predicate(&pk_rv.value, 100, nullptr, 0, &pred_a_len), BLSCT_SUCCESS);
    std::vector<uint8_t> pred_a_buf(pred_a_len);
    BOOST_REQUIRE_EQUAL(build_mint_token_predicate(&pk_rv.value, 100, pred_a_buf.data(), pred_a_buf.size(), &pred_a_len), BLSCT_SUCCESS);

    size_t pred_b_len = 0;
    BOOST_REQUIRE_EQUAL(build_mint_token_predicate(&pk_rv.value, 100, nullptr, 0, &pred_b_len), BLSCT_SUCCESS);
    std::vector<uint8_t> pred_b_buf(pred_b_len);
    BOOST_REQUIRE_EQUAL(build_mint_token_predicate(&pk_rv.value, 100, pred_b_buf.data(), pred_b_buf.size(), &pred_b_len), BLSCT_SUCCESS);

    // Same predicate bytes => equal
    BOOST_CHECK_EQUAL(are_vector_predicate_equal(pred_a_buf.data(), pred_a_len, pred_b_buf.data(), pred_b_len), 1);

    // Different size => not equal
    BOOST_CHECK_EQUAL(are_vector_predicate_equal(pred_a_buf.data(), pred_a_len, pred_b_buf.data(), pred_b_len - 1), 0);
}

// ---------------------------------------------------------------------------
// Scalar operations
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_scalar_serialize_deserialize_roundtrip)
{
    init();

    auto rv = gen_scalar(42);
    BOOST_REQUIRE_EQUAL(rv.result, BLSCT_SUCCESS);

    BlsctScalarHexResult hex_rv = serialize_scalar(&rv.value);
    BOOST_REQUIRE_EQUAL(hex_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE(strlen(hex_rv.value) > 0);

    auto deser_rv = deserialize_scalar(hex_rv.value);
    BOOST_REQUIRE_EQUAL(deser_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(are_scalar_equal(&rv.value, &deser_rv.value), 1);
}

BOOST_AUTO_TEST_CASE(test_scalar_to_uint64)
{
    init();

    auto rv = gen_scalar(12345);
    BOOST_REQUIRE_EQUAL(rv.result, BLSCT_SUCCESS);

    BOOST_CHECK_EQUAL(scalar_to_uint64(&rv.value).value, 12345u);
}

BOOST_AUTO_TEST_CASE(test_scalar_to_str)
{
    init();

    auto rv = gen_scalar(1);
    BOOST_REQUIRE_EQUAL(rv.result, BLSCT_SUCCESS);

    auto sz_rv = scalar_to_str(&rv.value, nullptr, 0);
    BOOST_REQUIRE_EQUAL(sz_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE(sz_rv.value > 0);
    std::vector<char> str(sz_rv.value + 1);
    auto w_rv = scalar_to_str(&rv.value, str.data(), str.size());
    BOOST_REQUIRE_EQUAL(w_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK(strlen(str.data()) > 0);
}

// ---------------------------------------------------------------------------
// Point operations
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_point_serialize_deserialize_roundtrip)
{
    init();

    auto rv = gen_base_point();
    BOOST_REQUIRE_EQUAL(rv.result, BLSCT_SUCCESS);

    BlsctPointHexResult hex_rv = serialize_point(&rv.value);
    BOOST_REQUIRE_EQUAL(hex_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(strlen(hex_rv.value), POINT_SIZE * 2u);

    auto deser_rv = deserialize_point(hex_rv.value);
    BOOST_REQUIRE_EQUAL(deser_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(are_point_equal(&rv.value, &deser_rv.value), 1);
}

BOOST_AUTO_TEST_CASE(test_gen_random_point)
{
    init();

    auto rv = gen_random_point();
    BOOST_REQUIRE_EQUAL(rv.result, BLSCT_SUCCESS);
}

BOOST_AUTO_TEST_CASE(test_are_point_equal)
{
    init();

    auto rv_a = gen_base_point();
    auto rv_b = gen_base_point();
    auto rv_c = gen_random_point();
    BOOST_REQUIRE_EQUAL(rv_a.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(rv_b.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(rv_c.result, BLSCT_SUCCESS);

    BOOST_CHECK_EQUAL(are_point_equal(&rv_a.value, &rv_b.value), 1);
    BOOST_CHECK_EQUAL(are_point_equal(&rv_a.value, &rv_c.value), 0);
}

BOOST_AUTO_TEST_CASE(test_is_valid_point)
{
    init();

    auto rv = gen_base_point();
    BOOST_REQUIRE_EQUAL(rv.result, BLSCT_SUCCESS);

    BOOST_CHECK(is_valid_point(&rv.value));
}

BOOST_AUTO_TEST_CASE(test_point_to_str)
{
    init();

    auto rv = gen_base_point();
    BOOST_REQUIRE_EQUAL(rv.result, BLSCT_SUCCESS);

    auto sz_rv = point_to_str(&rv.value, nullptr, 0);
    BOOST_REQUIRE_EQUAL(sz_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE(sz_rv.value > 0);
    std::vector<char> str(sz_rv.value + 1);
    auto w_rv = point_to_str(&rv.value, str.data(), str.size());
    BOOST_REQUIRE_EQUAL(w_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK(strlen(str.data()) > 0);
}

BOOST_AUTO_TEST_CASE(test_scalar_multiply_point)
{
    init();

    auto p_rv = gen_base_point();
    auto s_rv = gen_scalar(2);
    BOOST_REQUIRE_EQUAL(p_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(s_rv.result, BLSCT_SUCCESS);

    BlsctPointResult result_rv = scalar_muliply_point(&p_rv.value, &s_rv.value);
    BOOST_REQUIRE_EQUAL(result_rv.result, BLSCT_SUCCESS);
    // 2*G != G
    BOOST_CHECK_EQUAL(are_point_equal(&result_rv.value, &p_rv.value), 0);
}

BOOST_AUTO_TEST_CASE(test_point_from_scalar)
{
    init();

    auto s_rv = gen_scalar(1);
    BOOST_REQUIRE_EQUAL(s_rv.result, BLSCT_SUCCESS);

    BlsctPointResult p_rv2 = point_from_scalar(&s_rv.value);
    BOOST_REQUIRE_EQUAL(p_rv2.result, BLSCT_SUCCESS);

    auto base_rv = gen_base_point();
    BOOST_REQUIRE_EQUAL(base_rv.result, BLSCT_SUCCESS);

    // 1*G == G
    BOOST_CHECK_EQUAL(are_point_equal(&p_rv2.value, &base_rv.value), 1);
}

// ---------------------------------------------------------------------------
// Public key operations
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_public_key_serialize_deserialize_roundtrip)
{
    init();

    auto rv = gen_random_public_key();
    BOOST_REQUIRE_EQUAL(rv.result, BLSCT_SUCCESS);

    BlsctPointHexResult hex_rv = serialize_public_key(reinterpret_cast<const BlsctPoint*>(&rv.value));
    BOOST_REQUIRE_EQUAL(hex_rv.result, BLSCT_SUCCESS);

    auto deser_rv = deserialize_public_key(hex_rv.value);
    BOOST_REQUIRE_EQUAL(deser_rv.result, BLSCT_SUCCESS);
}

BOOST_AUTO_TEST_CASE(test_get_public_key_point_and_back)
{
    init();

    auto rv = gen_random_public_key();
    BOOST_REQUIRE_EQUAL(rv.result, BLSCT_SUCCESS);

    BlsctPointResult pt_rv = get_public_key_point(&rv.value);
    BOOST_REQUIRE_EQUAL(pt_rv.result, BLSCT_SUCCESS);

    BlsctPubKeyResult pk2_rv = point_to_public_key(&pt_rv.value);
    BOOST_REQUIRE_EQUAL(pk2_rv.result, BLSCT_SUCCESS);

    // round-trip: pk == pk2
    BlsctPointHexResult hex1_rv = serialize_public_key(reinterpret_cast<const BlsctPoint*>(&rv.value));
    BlsctPointHexResult hex2_rv = serialize_public_key(reinterpret_cast<const BlsctPoint*>(&pk2_rv.value));
    BOOST_REQUIRE_EQUAL(hex1_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(hex2_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(std::string(hex1_rv.value), std::string(hex2_rv.value));
}

// ---------------------------------------------------------------------------
// Double public key (DPK) operations
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_gen_double_pub_key_and_serialize_roundtrip)
{
    init();

    auto pk1_rv = gen_random_public_key();
    auto pk2_rv = gen_random_public_key();
    BOOST_REQUIRE_EQUAL(pk1_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(pk2_rv.result, BLSCT_SUCCESS);

    auto dpk_rv = gen_double_pub_key(&pk1_rv.value, &pk2_rv.value);
    BOOST_REQUIRE_EQUAL(dpk_rv.result, BLSCT_SUCCESS);

    BlsctDoublePubKeyHexResult hex_rv = serialize_dpk(&dpk_rv.value);
    BOOST_REQUIRE_EQUAL(hex_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(strlen(hex_rv.value), DOUBLE_PUBLIC_KEY_SIZE * 2u);

    auto deser_rv = deserialize_dpk(hex_rv.value);
    BOOST_REQUIRE_EQUAL(deser_rv.result, BLSCT_SUCCESS);
}

BOOST_AUTO_TEST_CASE(test_dpk_to_sub_addr_and_back)
{
    init();

    auto pk1_rv = gen_random_public_key();
    auto pk2_rv = gen_random_public_key();
    BOOST_REQUIRE_EQUAL(pk1_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(pk2_rv.result, BLSCT_SUCCESS);

    auto dpk_rv = gen_double_pub_key(&pk1_rv.value, &pk2_rv.value);
    BOOST_REQUIRE_EQUAL(dpk_rv.result, BLSCT_SUCCESS);

    auto sub_rv = dpk_to_sub_addr(&dpk_rv.value);
    BOOST_REQUIRE_EQUAL(sub_rv.result, BLSCT_SUCCESS);

    BlsctDoublePubKeyResult dpk2_rv = sub_addr_to_dpk(&sub_rv.value);
    BOOST_REQUIRE_EQUAL(dpk2_rv.result, BLSCT_SUCCESS);

    BlsctDoublePubKeyHexResult h1_rv = serialize_dpk(&dpk_rv.value);
    BlsctDoublePubKeyHexResult h2_rv = serialize_dpk(&dpk2_rv.value);
    BOOST_REQUIRE_EQUAL(h1_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(h2_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(std::string(h1_rv.value), std::string(h2_rv.value));
}

// ---------------------------------------------------------------------------
// Address encode/decode
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_encode_decode_address_roundtrip)
{
    init();

    auto pk1_rv = gen_random_public_key();
    auto pk2_rv = gen_random_public_key();
    BOOST_REQUIRE_EQUAL(pk1_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(pk2_rv.result, BLSCT_SUCCESS);

    auto dpk_rv = gen_double_pub_key(&pk1_rv.value, &pk2_rv.value);
    BOOST_REQUIRE_EQUAL(dpk_rv.result, BLSCT_SUCCESS);

    size_t addr_len;
    BLSCT_RESULT enc_r = encode_address(&dpk_rv.value, Bech32, nullptr, 0, &addr_len);
    BOOST_REQUIRE_EQUAL(enc_r, BLSCT_SUCCESS);
    std::vector<char> addr_buf(addr_len + 1);
    encode_address(&dpk_rv.value, Bech32, addr_buf.data(), addr_buf.size(), nullptr);
    const char* addr = addr_buf.data();

    auto dec_rv = decode_address(addr);
    BOOST_REQUIRE_EQUAL(dec_rv.result, BLSCT_SUCCESS);

    BlsctDoublePubKeyHexResult h1_rv = serialize_dpk(&dpk_rv.value);
    BlsctDoublePubKeyHexResult h2_rv = serialize_dpk(&dec_rv.value);
    BOOST_REQUIRE_EQUAL(h1_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(h2_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(std::string(h1_rv.value), std::string(h2_rv.value));
}

// ---------------------------------------------------------------------------
// Key ID operations
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_calc_key_id_and_serialize_roundtrip)
{
    init();

    auto s_rv = gen_random_scalar();
    BOOST_REQUIRE_EQUAL(s_rv.result, BLSCT_SUCCESS);

    BlsctPubKeyResult blind_pk_rv = scalar_to_pub_key(&s_rv.value);
    BlsctPubKeyResult spend_pk_rv = scalar_to_pub_key(&s_rv.value);
    BOOST_REQUIRE_EQUAL(blind_pk_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(spend_pk_rv.result, BLSCT_SUCCESS);

    BlsctKeyIdResult key_id_rv = calc_key_id(&blind_pk_rv.value, &spend_pk_rv.value, &s_rv.value);
    BOOST_REQUIRE_EQUAL(key_id_rv.result, BLSCT_SUCCESS);

    BlsctKeyIdHexResult hex_rv = serialize_key_id(&key_id_rv.value);
    BOOST_REQUIRE_EQUAL(hex_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(strlen(hex_rv.value), KEY_ID_SIZE * 2u);

    auto deser_rv = deserialize_key_id(hex_rv.value);
    BOOST_REQUIRE_EQUAL(deser_rv.result, BLSCT_SUCCESS);
}

// ---------------------------------------------------------------------------
// Sub-address operations
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_serialize_deserialize_sub_addr_roundtrip)
{
    init();

    auto s_rv = gen_random_scalar();
    BOOST_REQUIRE_EQUAL(s_rv.result, BLSCT_SUCCESS);

    BlsctPubKeyResult spend_pk_rv2 = scalar_to_pub_key(&s_rv.value);
    BOOST_REQUIRE_EQUAL(spend_pk_rv2.result, BLSCT_SUCCESS);
    auto* spend_pk = &spend_pk_rv2.value;

    BlsctSubAddrIdResult sub_id_rv3 = gen_sub_addr_id(0, 0);
    BOOST_REQUIRE_EQUAL(sub_id_rv3.result, BLSCT_SUCCESS);
    auto* sub_id = &sub_id_rv3.value;

    BlsctSubAddrResult sub_rv2 = derive_sub_address(&s_rv.value, spend_pk, sub_id);
    BOOST_REQUIRE_EQUAL(sub_rv2.result, BLSCT_SUCCESS);
    auto* sub = &sub_rv2.value;

    BlsctSubAddrHexResult hex_rv = serialize_sub_addr(sub);
    BOOST_REQUIRE_EQUAL(hex_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(strlen(hex_rv.value), SUB_ADDR_SIZE * 2u);

    auto deser_rv = deserialize_sub_addr(hex_rv.value);
    BOOST_REQUIRE_EQUAL(deser_rv.result, BLSCT_SUCCESS);
}

// ---------------------------------------------------------------------------
// Sub-address ID operations
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_sub_addr_id_fields_and_roundtrip)
{
    init();

    BlsctSubAddrIdResult sub_id_rv4 = gen_sub_addr_id(7, 42);
    BOOST_REQUIRE_EQUAL(sub_id_rv4.result, BLSCT_SUCCESS);
    auto* sub_id = &sub_id_rv4.value;

    auto acct_rv = get_sub_addr_id_account(sub_id);
    BOOST_REQUIRE_EQUAL(acct_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(acct_rv.value, 7);
    auto addr_rv = get_sub_addr_id_address(sub_id);
    BOOST_REQUIRE_EQUAL(addr_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(addr_rv.value, 42u);

    BlsctSubAddrIdHexResult hex_rv = serialize_sub_addr_id(sub_id);
    BOOST_REQUIRE_EQUAL(hex_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(strlen(hex_rv.value), SUB_ADDR_ID_SIZE * 2u);

    auto deser_rv = deserialize_sub_addr_id(hex_rv.value);
    BOOST_REQUIRE_EQUAL(deser_rv.result, BLSCT_SUCCESS);
    auto acct_rv2 = get_sub_addr_id_account(&deser_rv.value);
    BOOST_REQUIRE_EQUAL(acct_rv2.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(acct_rv2.value, 7);
    auto addr_rv2 = get_sub_addr_id_address(&deser_rv.value);
    BOOST_REQUIRE_EQUAL(addr_rv2.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(addr_rv2.value, 42u);
}

// ---------------------------------------------------------------------------
// Out point operations
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_out_point_serialize_deserialize_roundtrip)
{
    init();

    std::string txid_hex(64, '1');
    auto rv = gen_out_point(txid_hex.c_str());
    BOOST_REQUIRE_EQUAL(rv.result, BLSCT_SUCCESS);

    BlsctOutPointHexResult hex_rv = serialize_out_point(&rv.value);
    BOOST_REQUIRE_EQUAL(hex_rv.result, BLSCT_SUCCESS);

    auto deser_rv = deserialize_out_point(hex_rv.value);
    BOOST_REQUIRE_EQUAL(deser_rv.result, BLSCT_SUCCESS);

    uninit();
}

BOOST_AUTO_TEST_CASE(test_gen_out_point_bad_inputs)
{
    init();

    BOOST_CHECK_EQUAL(gen_out_point(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(gen_out_point("").result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(gen_out_point("deadbeef").result, BLSCT_FAILURE);
    // one char short
    BOOST_CHECK_EQUAL(gen_out_point(std::string(63, '0').c_str()).result, BLSCT_FAILURE);
    // one char long
    BOOST_CHECK_EQUAL(gen_out_point(std::string(65, '0').c_str()).result, BLSCT_FAILURE);

    uninit();
}

// ---------------------------------------------------------------------------
// Token ID operations
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_token_id_fields_and_roundtrip)
{
    init();

    auto rv = gen_token_id_with_token_and_subid(99, 7);
    BOOST_REQUIRE_EQUAL(rv.result, BLSCT_SUCCESS);

    BOOST_CHECK_EQUAL(get_token_id_token(&rv.value).value, 99u);
    BOOST_CHECK_EQUAL(get_token_id_subid(&rv.value).value, 7u);

    BlsctTokenIdHexResult hex_rv = serialize_token_id(&rv.value);
    BOOST_REQUIRE_EQUAL(hex_rv.result, BLSCT_SUCCESS);

    auto deser_rv = deserialize_token_id(hex_rv.value);
    BOOST_REQUIRE_EQUAL(deser_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(get_token_id_token(&deser_rv.value).value, 99u);
    BOOST_CHECK_EQUAL(get_token_id_subid(&deser_rv.value).value, 7u);
}

BOOST_AUTO_TEST_CASE(test_gen_token_id)
{
    init();

    auto rv = gen_token_id(55);
    BOOST_REQUIRE_EQUAL(rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(get_token_id_token(&rv.value).value, 55u);
}

// ---------------------------------------------------------------------------
// CTx ID operations
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_ctx_id_serialize_deserialize_roundtrip)
{
    init();

    std::string hex64(64, 'a');
    auto rv = deserialize_ctx_id(hex64.c_str());
    BOOST_REQUIRE_EQUAL(rv.result, BLSCT_SUCCESS);

    BlsctCTxIdHexResult hex_rv = serialize_ctx_id(&rv.value);
    BOOST_REQUIRE_EQUAL(hex_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(std::string(hex_rv.value), hex64);
}

// ---------------------------------------------------------------------------
// Script operations
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_script_serialize_deserialize_roundtrip)
{
    init();

    std::string hex56(SCRIPT_SIZE * 2, 'b');
    auto rv = deserialize_script(hex56.c_str());
    BOOST_REQUIRE_EQUAL(rv.result, BLSCT_SUCCESS);

    BlsctScriptHexResult hex_rv = serialize_script(&rv.value);
    BOOST_REQUIRE_EQUAL(hex_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(std::string(hex_rv.value), hex56);
}

// ---------------------------------------------------------------------------
// Signature: sign + verify + serialize/deserialize
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_sign_and_verify_message)
{
    init();

    auto sk_rv = gen_random_scalar();
    BOOST_REQUIRE_EQUAL(sk_rv.result, BLSCT_SUCCESS);
    BlsctPubKeyResult pk_rv = scalar_to_pub_key(&sk_rv.value);
    BOOST_REQUIRE_EQUAL(pk_rv.result, BLSCT_SUCCESS);
    auto* pk = &pk_rv.value;

    const char* msg = "hello blsct";
    BlsctSignatureResult sig_rv = sign_message(&sk_rv.value, msg);
    BOOST_REQUIRE_EQUAL(sig_rv.result, BLSCT_SUCCESS);
    auto* sig = &sig_rv.value;

    BOOST_CHECK(verify_msg_sig(pk, msg, sig));
    BOOST_CHECK(!verify_msg_sig(pk, "wrong message", sig));

    BlsctSignatureHexResult hex_rv = serialize_signature(sig);
    BOOST_REQUIRE_EQUAL(hex_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(strlen(hex_rv.value), SIGNATURE_SIZE * 2u);

    auto deser_rv = deserialize_signature(hex_rv.value);
    BOOST_REQUIRE_EQUAL(deser_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK(verify_msg_sig(pk, msg, &deser_rv.value));
}

// ---------------------------------------------------------------------------
// Key derivation chain
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_key_derivation_chain)
{
    init();

    auto seed_rv = gen_random_scalar();
    BOOST_REQUIRE_EQUAL(seed_rv.result, BLSCT_SUCCESS);

    BlsctScalarResult child_rv = from_seed_to_child_key(&seed_rv.value);
    BOOST_REQUIRE_EQUAL(child_rv.result, BLSCT_SUCCESS);

    BlsctScalarResult blind_rv = from_child_key_to_blinding_key(&child_rv.value);
    BlsctScalarResult token_rv = from_child_key_to_token_key(&child_rv.value);
    BlsctScalarResult txkey_rv = from_child_key_to_tx_key(&child_rv.value);
    BOOST_REQUIRE_EQUAL(blind_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(token_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(txkey_rv.result, BLSCT_SUCCESS);

    BlsctScalarResult view_rv = from_tx_key_to_view_key(&txkey_rv.value);
    BlsctScalarResult spend_rv = from_tx_key_to_spending_key(&txkey_rv.value);
    BOOST_REQUIRE_EQUAL(view_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(spend_rv.result, BLSCT_SUCCESS);

    // All derived keys succeed — smoke test only
}

BOOST_AUTO_TEST_CASE(test_key_derivation_chain_null_inputs)
{
    init();

    BOOST_CHECK_EQUAL(from_seed_to_child_key(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(from_child_key_to_blinding_key(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(from_child_key_to_token_key(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(from_child_key_to_tx_key(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(from_tx_key_to_view_key(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(from_tx_key_to_spending_key(nullptr).result, BLSCT_FAILURE);

    uninit();
}

// ---------------------------------------------------------------------------
// calc_nonce, calc_view_tag, calc_priv_spending_key, gen_dpk_with_keys_acct_addr
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_calc_nonce_and_view_tag)
{
    init();

    auto s_rv = gen_random_scalar();
    BOOST_REQUIRE_EQUAL(s_rv.result, BLSCT_SUCCESS);
    BlsctPubKeyResult blind_pk_rv2 = scalar_to_pub_key(&s_rv.value);
    BOOST_REQUIRE_EQUAL(blind_pk_rv2.result, BLSCT_SUCCESS);
    auto* blind_pk = &blind_pk_rv2.value;

    BlsctPointResult nonce_rv2 = calc_nonce(blind_pk, &s_rv.value);
    BOOST_REQUIRE_EQUAL(nonce_rv2.result, BLSCT_SUCCESS);

    auto tag_rv = calc_view_tag(blind_pk, &s_rv.value);
    BOOST_REQUIRE_EQUAL(tag_rv.result, BLSCT_SUCCESS);
    // tag is deterministic — calling again must give same value
    auto tag_rv2 = calc_view_tag(blind_pk, &s_rv.value);
    BOOST_REQUIRE_EQUAL(tag_rv2.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(tag_rv2.value, tag_rv.value);

    uninit();
}

BOOST_AUTO_TEST_CASE(test_calc_nonce_null_inputs)
{
    init();

    auto s_rv = gen_random_scalar();
    BOOST_REQUIRE_EQUAL(s_rv.result, BLSCT_SUCCESS);
    BlsctPubKeyResult blind_pk_rv = scalar_to_pub_key(&s_rv.value);
    BOOST_REQUIRE_EQUAL(blind_pk_rv.result, BLSCT_SUCCESS);

    BOOST_CHECK_EQUAL(calc_nonce(nullptr, &s_rv.value).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(calc_nonce(&blind_pk_rv.value, nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(calc_nonce(nullptr, nullptr).result, BLSCT_FAILURE);

    uninit();
}

BOOST_AUTO_TEST_CASE(test_calc_priv_spending_key)
{
    init();

    auto s_rv = gen_random_scalar();
    BOOST_REQUIRE_EQUAL(s_rv.result, BLSCT_SUCCESS);
    BlsctPubKeyResult blind_pk_rv3 = scalar_to_pub_key(&s_rv.value);
    BOOST_REQUIRE_EQUAL(blind_pk_rv3.result, BLSCT_SUCCESS);
    auto* blind_pk = &blind_pk_rv3.value;

    BlsctScalarResult priv_spend_rv = calc_priv_spending_key(blind_pk, &s_rv.value, &s_rv.value, 0, 0);
    BOOST_REQUIRE_EQUAL(priv_spend_rv.result, BLSCT_SUCCESS);

    uninit();
}

BOOST_AUTO_TEST_CASE(test_calc_priv_spending_key_null_inputs)
{
    init();

    auto s_rv = gen_random_scalar();
    BOOST_REQUIRE_EQUAL(s_rv.result, BLSCT_SUCCESS);
    BlsctPubKeyResult blind_pk_rv = scalar_to_pub_key(&s_rv.value);
    BOOST_REQUIRE_EQUAL(blind_pk_rv.result, BLSCT_SUCCESS);
    auto* blind_pk = &blind_pk_rv.value;
    auto* scalar = &s_rv.value;

    BOOST_CHECK_EQUAL(calc_priv_spending_key(nullptr, scalar, scalar, 0, 0).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(calc_priv_spending_key(blind_pk, nullptr, scalar, 0, 0).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(calc_priv_spending_key(blind_pk, scalar, nullptr, 0, 0).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(calc_priv_spending_key(nullptr, nullptr, nullptr, 0, 0).result, BLSCT_FAILURE);

    uninit();
}

BOOST_AUTO_TEST_CASE(test_gen_dpk_with_keys_acct_addr)
{
    init();

    auto s_rv = gen_random_scalar();
    BOOST_REQUIRE_EQUAL(s_rv.result, BLSCT_SUCCESS);
    BlsctPubKeyResult spend_pk_rv4 = scalar_to_pub_key(&s_rv.value);
    BOOST_REQUIRE_EQUAL(spend_pk_rv4.result, BLSCT_SUCCESS);
    auto* spend_pk = &spend_pk_rv4.value;

    BlsctDoublePubKeyResult dpk_rv2 = gen_dpk_with_keys_acct_addr(&s_rv.value, spend_pk, 0, 0);
    BOOST_REQUIRE_EQUAL(dpk_rv2.result, BLSCT_SUCCESS);

    BlsctDoublePubKeyHexResult hex_rv = serialize_dpk(&dpk_rv2.value);
    BOOST_REQUIRE_EQUAL(hex_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(strlen(hex_rv.value), DOUBLE_PUBLIC_KEY_SIZE * 2u);
}

// ---------------------------------------------------------------------------
// TxIn / TxOut accessor round-trips
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_tx_in_accessors)
{
    init();

    auto gamma_rv = gen_scalar(10);
    auto sk_rv = gen_scalar(20);
    auto tid_rv = gen_default_token_id();
    auto op_rv = gen_out_point(std::string(64, '0').c_str());
    BOOST_REQUIRE_EQUAL(gamma_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(sk_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(tid_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(op_rv.result, BLSCT_SUCCESS);

    auto tx_in_rv = build_tx_in(1000, &gamma_rv.value, &sk_rv.value, &tid_rv.value, &op_rv.value, true, true);
    BOOST_REQUIRE_EQUAL(tx_in_rv.result, BLSCT_SUCCESS);
    auto* tx_in = &tx_in_rv.value;

    auto amt_rv2 = get_tx_in_amount(tx_in);
    BOOST_REQUIRE_EQUAL(amt_rv2.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(amt_rv2.value, 1000u);
    auto staked_rv = get_tx_in_staked_commitment(tx_in);
    BOOST_REQUIRE_EQUAL(staked_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK(staked_rv.value);
    auto rbf_rv = get_tx_in_rbf(tx_in);
    BOOST_REQUIRE_EQUAL(rbf_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK(rbf_rv.value);

    BlsctScalarResult sk2_rv = get_tx_in_spending_key(tx_in);
    BOOST_REQUIRE_EQUAL(sk2_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(are_scalar_equal(&sk_rv.value, &sk2_rv.value), 1);

    BlsctTokenIdResult tid2_rv = get_tx_in_token_id(tx_in);
    BOOST_REQUIRE_EQUAL(tid2_rv.result, BLSCT_SUCCESS);

    BlsctOutPointResult op2_rv = get_tx_in_out_point(tx_in);
    BOOST_REQUIRE_EQUAL(op2_rv.result, BLSCT_SUCCESS);
}

BOOST_AUTO_TEST_CASE(test_tx_out_accessors)
{
    init();

    auto s_rv = gen_random_scalar();
    auto tid_rv = gen_default_token_id();
    BOOST_REQUIRE_EQUAL(s_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(tid_rv.result, BLSCT_SUCCESS);

    BlsctPubKeyResult spend_pk_rv5 = scalar_to_pub_key(&s_rv.value);
    BlsctSubAddrIdResult sub_id_rv5 = gen_sub_addr_id(0, 0);
    BOOST_REQUIRE_EQUAL(spend_pk_rv5.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(sub_id_rv5.result, BLSCT_SUCCESS);
    auto* spend_pk = &spend_pk_rv5.value;
    auto* sub_id = &sub_id_rv5.value;
    BlsctSubAddrResult dest_rv4 = derive_sub_address(&s_rv.value, spend_pk, sub_id);
    BOOST_REQUIRE_EQUAL(dest_rv4.result, BLSCT_SUCCESS);
    auto* dest = &dest_rv4.value;

    auto blind_rv = gen_random_scalar();
    BOOST_REQUIRE_EQUAL(blind_rv.result, BLSCT_SUCCESS);

    auto tx_out_rv = build_tx_out(dest, 500, "memo_test", &tid_rv.value, Normal, 10, false, &blind_rv.value);
    BOOST_REQUIRE_EQUAL(tx_out_rv.result, BLSCT_SUCCESS);
    auto* tx_out = &tx_out_rv.value;

    auto out_amt_rv = get_tx_out_amount(tx_out);
    BOOST_REQUIRE_EQUAL(out_amt_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(out_amt_rv.value, 500u);
    auto otype_rv = get_tx_out_output_type(tx_out);
    BOOST_REQUIRE_EQUAL(otype_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(otype_rv.value, Normal);
    auto min_stake_rv = get_tx_out_min_stake(tx_out);
    BOOST_REQUIRE_EQUAL(min_stake_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(min_stake_rv.value, 10u);
    auto sfa_rv = get_tx_out_subtract_fee_from_amount(tx_out);
    BOOST_REQUIRE_EQUAL(sfa_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK(!sfa_rv.value);

    auto memo_rv = get_tx_out_memo(tx_out);
    BOOST_REQUIRE_EQUAL(memo_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE(memo_rv.value != nullptr);
    BOOST_CHECK_EQUAL(std::string(memo_rv.value), "memo_test");

    BlsctSubAddrResult dest2_rv = get_tx_out_destination(tx_out);
    BOOST_REQUIRE_EQUAL(dest2_rv.result, BLSCT_SUCCESS);

    BlsctTokenIdResult tid2_rv = get_tx_out_token_id(tx_out);
    BOOST_REQUIRE_EQUAL(tid2_rv.result, BLSCT_SUCCESS);

    BlsctScalarResult blind2_rv = get_tx_out_blinding_key(tx_out);
    BOOST_REQUIRE_EQUAL(blind2_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(are_scalar_equal(&blind_rv.value, &blind2_rv.value), 1);
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// set/get blsct chain
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_set_get_blsct_chain)
{
    init();

    enum BlsctChain original = get_blsct_chain();

    set_blsct_chain(Testnet);
    BOOST_CHECK_EQUAL(get_blsct_chain(), Testnet);

    set_blsct_chain(Regtest);
    BOOST_CHECK_EQUAL(get_blsct_chain(), Regtest);

    set_blsct_chain(original);
    BOOST_CHECK_EQUAL(get_blsct_chain(), original);
}

// ---------------------------------------------------------------------------
// Hex utilities
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_serialize_raw_obj_roundtrip)
{
    init();

    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    auto sz_rv = serialize_raw_obj(data, sizeof(data), nullptr, 0);
    BOOST_REQUIRE_EQUAL(sz_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE(sz_rv.value > 0);
    std::vector<char> hex(sz_rv.value + 1);
    auto w_rv = serialize_raw_obj(data, sizeof(data), hex.data(), hex.size());
    BOOST_REQUIRE_EQUAL(w_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(std::string(hex.data()), "01020304");

    size_t obj_len = 0;
    BOOST_REQUIRE_EQUAL(deserialize_raw_obj(hex.data(), nullptr, 0, &obj_len), BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(obj_len, sizeof(data));
    std::vector<uint8_t> obj_buf(obj_len);
    BOOST_REQUIRE_EQUAL(deserialize_raw_obj(hex.data(), obj_buf.data(), obj_buf.size(), &obj_len), BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(memcmp(obj_buf.data(), data, sizeof(data)), 0);
}

// ---------------------------------------------------------------------------
// Unsigned input/output serialize/deserialize roundtrip
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_unsigned_input_serialize_deserialize_roundtrip)
{
    init();

    auto s_rv = gen_random_scalar();
    auto tid_rv = gen_default_token_id();
    auto op_rv = gen_out_point(std::string(64, '0').c_str());
    BOOST_REQUIRE_EQUAL(s_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(tid_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(op_rv.result, BLSCT_SUCCESS);

    auto tx_in_rv = build_tx_in(1000, &s_rv.value, &s_rv.value, &tid_rv.value, &op_rv.value, false, false);
    BOOST_REQUIRE_EQUAL(tx_in_rv.result, BLSCT_SUCCESS);

    size_t uin_len = 0;
    BOOST_REQUIRE_EQUAL(build_unsigned_input(&tx_in_rv.value, nullptr, 0, &uin_len), BLSCT_SUCCESS);
    BOOST_REQUIRE(uin_len > 0);
    std::vector<char> uin_hex(uin_len + 1);
    BOOST_REQUIRE_EQUAL(build_unsigned_input(&tx_in_rv.value, uin_hex.data(), uin_hex.size(), &uin_len), BLSCT_SUCCESS);

    // verify that a deserialized UnsignedInput can be passed to sign_unsigned_transaction
    const char* in_hexes[] = {uin_hex.data()};
    size_t dummy_len = 0;
    // sign without any outputs just to verify deserialization doesn't crash
    // (signing may fail due to missing outputs, that's acceptable here)
    sign_unsigned_transaction(in_hexes, 1, nullptr, 0, 0, nullptr, 0, &dummy_len);
}

// ---------------------------------------------------------------------------
// Vector predicate serialize/deserialize roundtrip
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_vector_predicate_serialize_deserialize_roundtrip)
{
    init();

    auto pk_rv = gen_random_public_key();
    BOOST_REQUIRE_EQUAL(pk_rv.result, BLSCT_SUCCESS);

    size_t pred_len = 0;
    BOOST_REQUIRE_EQUAL(build_mint_token_predicate(&pk_rv.value, 100, nullptr, 0, &pred_len), BLSCT_SUCCESS);
    std::vector<uint8_t> pred_buf(pred_len);
    BOOST_REQUIRE_EQUAL(build_mint_token_predicate(&pk_rv.value, 100, pred_buf.data(), pred_buf.size(), &pred_len), BLSCT_SUCCESS);

    auto vp_sz_rv = serialize_vector_predicate(pred_buf.data(), pred_len, nullptr, 0);
    BOOST_REQUIRE_EQUAL(vp_sz_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE(vp_sz_rv.value > 0);
    std::vector<char> hex(vp_sz_rv.value + 1);
    auto vp_w_rv = serialize_vector_predicate(pred_buf.data(), pred_len, hex.data(), hex.size());
    BOOST_REQUIRE_EQUAL(vp_w_rv.result, BLSCT_SUCCESS);

    size_t deser_len = 0;
    BOOST_REQUIRE_EQUAL(deserialize_vector_predicate(hex.data(), nullptr, 0, &deser_len), BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(deser_len, pred_len);
    std::vector<uint8_t> deser_buf(deser_len);
    BOOST_REQUIRE_EQUAL(deserialize_vector_predicate(hex.data(), deser_buf.data(), deser_buf.size(), &deser_len), BLSCT_SUCCESS);
}

// ---------------------------------------------------------------------------
// Token info public key accessor
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_get_token_info_public_key)
{
    init();

    auto pk_rv = gen_random_public_key();
    BOOST_REQUIRE_EQUAL(pk_rv.result, BLSCT_SUCCESS);

    size_t info_len = 0;
    BOOST_REQUIRE_EQUAL(build_token_info(BlsctToken, &pk_rv.value, nullptr, nullptr, 0, 1000, nullptr, 0, &info_len), BLSCT_SUCCESS);
    std::vector<char> info_hex(info_len + 1);
    BOOST_REQUIRE_EQUAL(build_token_info(BlsctToken, &pk_rv.value, nullptr, nullptr, 0, 1000, info_hex.data(), info_hex.size(), &info_len), BLSCT_SUCCESS);

    BlsctPubKeyResult pk2_rv = get_token_info_public_key(info_hex.data());
    BOOST_REQUIRE_EQUAL(pk2_rv.result, BLSCT_SUCCESS);

    BlsctPointHexResult h1_rv = serialize_public_key(reinterpret_cast<const BlsctPoint*>(&pk_rv.value));
    BlsctPointHexResult h2_rv = serialize_public_key(reinterpret_cast<const BlsctPoint*>(&pk2_rv.value));
    BOOST_REQUIRE_EQUAL(h1_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(h2_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(std::string(h1_rv.value), std::string(h2_rv.value));
}

// ---------------------------------------------------------------------------
// Amount recovery: result size and msg accessors
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_amount_recovery_result_size_and_msg)
{
    init();

    uint64_t amount = 77;
    std::string msg = "recovery_msg";

    auto tid_rv = gen_default_token_id();
    BOOST_REQUIRE_EQUAL(tid_rv.result, BLSCT_SUCCESS);

    TokenId token_id;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(tid_rv.value, TOKEN_ID_SIZE, token_id);

    Mcl::Point nonce_pt = Mcl::Point::Rand();
    BlsctPoint blsct_nonce;
    SERIALIZE_AND_COPY(nonce_pt, blsct_nonce);

    uint64_t amounts[] = {amount};
    size_t rp_len = 0;
    BOOST_REQUIRE_EQUAL(build_range_proof(amounts, 1, &blsct_nonce, msg.c_str(), &tid_rv.value, nullptr, 0, &rp_len), BLSCT_SUCCESS);
    std::vector<uint8_t> rp_buf(rp_len);
    BOOST_REQUIRE_EQUAL(build_range_proof(amounts, 1, &blsct_nonce, msg.c_str(), &tid_rv.value, rp_buf.data(), rp_buf.size(), &rp_len), BLSCT_SUCCESS);

    BlsctAmountRecoveryReq req{};
    req.range_proof = rp_buf.data();
    req.range_proof_size = rp_len;
    std::memcpy(req.nonce, blsct_nonce, POINT_SIZE);
    std::memcpy(req.token_id, tid_rv.value, TOKEN_ID_SIZE);

    BlsctAmountRecoveryResult result{};
    BOOST_REQUIRE_EQUAL(recover_amount(&req, 1, &result), BLSCT_SUCCESS);

    BOOST_CHECK(result.is_succ);
    BOOST_CHECK_EQUAL(result.amount, amount);
    BOOST_CHECK_EQUAL(std::string(result.msg), msg);
}

// Regression tests for CScript memcpy bugs in script accessor functions.
//
// CScript = prevector<28, unsigned char>. Its first 28 bytes ARE the inline
// (direct) storage array, so memcpy(&script, 28) is accidentally correct for
// scripts up to 28 bytes. For scripts > 28 bytes prevector switches to
// indirect (heap) mode: the first 12 bytes become {char* ptr, uint32_t cap}
// and the copy returns pointer bytes instead of script content.
//
// All real BLSCT scripts are <= 28 bytes, so the bug is latent. These tests
// force indirect mode with a 34-byte script to verify the accessor returns
// the actual script bytes rather than the prevector header.

BOOST_AUTO_TEST_CASE(test_get_ctx_in_script_sig_oversized_returns_bad_size)
{
    CScript large_sig;
    large_sig.push_back(0x00);
    large_sig.push_back(0x20);
    for (int i = 0; i < 32; ++i)
        large_sig.push_back(static_cast<uint8_t>(i + 1));
    BOOST_REQUIRE_GT(large_sig.size(), (size_t)SCRIPT_SIZE);

    CTxIn txin;
    txin.scriptSig = large_sig;

    BlsctScriptResult rv = get_ctx_in_script_sig(static_cast<const void*>(&txin));
    BOOST_CHECK_EQUAL(rv.result, BLSCT_BAD_SIZE);
}

BOOST_AUTO_TEST_CASE(test_get_ctx_in_script_sig_fits_returns_success)
{
    CScript small_sig;
    for (int i = 0; i < SCRIPT_SIZE; ++i)
        small_sig.push_back(static_cast<uint8_t>(i + 1));
    BOOST_REQUIRE_EQUAL(small_sig.size(), (size_t)SCRIPT_SIZE);

    CTxIn txin;
    txin.scriptSig = small_sig;

    BlsctScriptResult rv = get_ctx_in_script_sig(static_cast<const void*>(&txin));
    BOOST_REQUIRE_EQUAL(rv.result, BLSCT_SUCCESS);
    for (size_t i = 0; i < SCRIPT_SIZE; ++i)
        BOOST_CHECK_EQUAL(rv.value[i], small_sig[i]);
}

BOOST_AUTO_TEST_CASE(test_get_ctx_in_script_witness_oversized_returns_bad_size)
{
    std::vector<uint8_t> large_item(SCRIPT_SIZE + 1, 0xab);

    CTxIn txin;
    txin.scriptWitness.stack.push_back(large_item);

    BlsctScriptResult rv = get_ctx_in_script_witness(static_cast<const void*>(&txin));
    BOOST_CHECK_EQUAL(rv.result, BLSCT_BAD_SIZE);
}

BOOST_AUTO_TEST_CASE(test_get_ctx_in_script_witness_fits_returns_success)
{
    std::vector<uint8_t> item(SCRIPT_SIZE);
    for (int i = 0; i < SCRIPT_SIZE; ++i)
        item[i] = static_cast<uint8_t>(i + 1);

    CTxIn txin;
    txin.scriptWitness.stack.push_back(item);

    BlsctScriptResult rv = get_ctx_in_script_witness(static_cast<const void*>(&txin));
    BOOST_REQUIRE_EQUAL(rv.result, BLSCT_SUCCESS);
    for (size_t i = 0; i < SCRIPT_SIZE; ++i)
        BOOST_CHECK_EQUAL(rv.value[i], item[i]);
}

BOOST_AUTO_TEST_CASE(test_get_ctx_out_script_pub_key_oversized_returns_bad_size)
{
    CScript large_spk;
    large_spk.push_back(0x00);
    large_spk.push_back(0x20);
    for (int i = 0; i < 32; ++i)
        large_spk.push_back(static_cast<uint8_t>(i + 1));
    BOOST_REQUIRE_GT(large_spk.size(), (size_t)SCRIPT_SIZE);

    CTxOut txout(0, large_spk);

    BlsctScriptResult rv = get_ctx_out_script_pub_key(static_cast<const void*>(&txout));
    BOOST_CHECK_EQUAL(rv.result, BLSCT_BAD_SIZE);
}

BOOST_AUTO_TEST_CASE(test_get_ctx_out_script_pub_key_fits_returns_success)
{
    CScript small_spk;
    for (int i = 0; i < SCRIPT_SIZE; ++i)
        small_spk.push_back(static_cast<uint8_t>(i + 1));
    BOOST_REQUIRE_EQUAL(small_spk.size(), (size_t)SCRIPT_SIZE);

    CTxOut txout(0, small_spk);

    BlsctScriptResult rv = get_ctx_out_script_pub_key(static_cast<const void*>(&txout));
    BOOST_REQUIRE_EQUAL(rv.result, BLSCT_SUCCESS);
    for (size_t i = 0; i < SCRIPT_SIZE; ++i)
        BOOST_CHECK_EQUAL(rv.value[i], small_spk[i]);
}

BOOST_AUTO_TEST_CASE(test_recover_amount_without_init_returns_error)
{
    uninit();
    BOOST_CHECK_EQUAL(recover_amount(nullptr, 0, nullptr), BLSCT_INIT_NOT_CALLED);
}

BOOST_AUTO_TEST_CASE(test_recover_amount_null_range_proof_returns_failure)
{
    init();

    BlsctAmountRecoveryReq req{};
    req.range_proof = nullptr;
    BlsctAmountRecoveryResult result{};
    BOOST_CHECK_EQUAL(recover_amount(&req, 1, &result), BLSCT_FAILURE);

    uninit();
}

BOOST_AUTO_TEST_CASE(test_build_range_proof_without_init_returns_error)
{
    uninit();
    uint64_t amounts[] = {42};
    size_t rp_len = 0;
    BLSCT_RESULT rv = build_range_proof(amounts, 1, nullptr, "memo", nullptr, nullptr, 0, &rp_len);
    BOOST_CHECK_EQUAL(rv, BLSCT_INIT_NOT_CALLED);
    init();
}

BOOST_AUTO_TEST_CASE(test_verify_range_proofs_without_init_returns_error)
{
    uninit();
    BlsctBoolResult rv = verify_range_proofs(nullptr, nullptr, 0);
    BOOST_CHECK_EQUAL(rv.result, BLSCT_INIT_NOT_CALLED);
    init();
}

// ---------------------------------------------------------------------------
// BlsctUint64Result failure cases
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_get_ctx_out_value_null_returns_failure)
{
    BlsctUint64Result rv = get_ctx_out_value(nullptr);
    BOOST_CHECK_EQUAL(rv.result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_get_ctx_out_value_at_bad_hex_returns_failure)
{
    BlsctUint64Result rv = get_ctx_out_value_at("notahex", 0);
    BOOST_CHECK_EQUAL(rv.result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_get_ctx_out_value_at_out_of_bounds_returns_failure)
{
    init();
    // valid tx hex from test_cmutable_transaction_sizes
    std::string tx_hex = "200000000100000000000000000000000000000000000000000000000000000000000000000503615d0200ffffffff02ffffffffffffff7f0100000000000000015101855f4e35c5fbe93bf5b8a7a2dc55420144388fd0736ce7d9c8289e793da409d89f2bf2f4f4ac9364d81922d9255c33880683ed1c387aa2555b28af1c6d2b4a2725af9551263c00962daeec3736de0724167d18579973ff9cfcaeedc9ed59036aaaa2ad79cef575dc618d14729169a88c87edb5d3303efab1109572ca4a98800d61c45d8ca9074a7beb9c5c4123e7af8054b4bce1a360c663b86e8af1f06dea120fce8d7529b90ff383fd69c7dd9a50215881df91544949b95eaeac780c133699bdb030b321c32c0efbafa29fe840fe93b01bffc47e096a4577f5ba7d6745506f5e658cbd21c0c7f4c5fc28fdb28dd1c27a8027da5ca650a48ced1c52725abc54a1bd54e9823341753de270ea7882fd54b5b7513d9184635b9dbf0812ccf769df4cb50985bfa52fa515fa7034a317b2da1453d2d919797a22e6889c8aada6fe25e2dfda8f57f57de8fc2a9fa957d264240d06b8548ad7eec8b644df2e89b9a5a1d83ecce4ca94005b7d61782743e74ed011f7cc96c634327b67cfbc954de4effa0d7884f88d27ac1c1686bad02f527975ed9f3e7b2570120dc68ad88ddd350119d00c6df24916d5fc361f20f4f4d4482711b5850b3f91c9315beb1af544d63ed7049b6a1af783e0171526ba9c31466de735527d2d1bfeaf292a73ecf0312e6e784ae18dc6949e4a452fadc0734bff7bdf56074434f7a311290ba2ec6cbe960e29829d2b8ad6fb7946e356580b5a40f9676274a8336c5eecc36a9ddb58bb81cd8d08dfda7714aa9634941a94076cbc3ed74561d9043146dc81f1ccafd4e06f98faae3da017fe07af9ac407d0b81e6e1e634e5b53f5f98728850298673e355093844d0443466fad33d233ed7c40c1788a43d4d48d63778e8cf80e9cd5d01e789637b0cae99a372dd0bc8b5dbf2bc2df9fea229d71eaebab6a9277bb3bb3ba07c14edef6a7fcdcf02e8c1e927872003b9683d3b3ff1e740d5ec8a8145361166b33da8dcda6edf5d7bf32f63d27a5b72e515e6641b672275eee06f3bd5abd6790eded07d49b9e55e5c29e136eb5ad4857f9f55b6e7be10d2002ed91244243ea0fe7b6dea43ea70eb0d3d438ae2a335ced8e1620392562a2c503d2c4b53bed0d39c3749cb032741cacd0ca73bc6d72d350184cc82a45ad8df2e3443599ba51dfd5dce328362f9032cb350f579234f36c282d4b0acdf27d6a8d66f62713adf6481c8c9f240f59a15c6e064a5c05b56e6c068801f639ee1e83003a6a8dd97d5c24b5236c30d43efa0d75709fcaba4ca72077232f537900b2697973d2a08ee405d4298d4a8afeb24f6066b9648b3265e10931756678606fc173b92525567648af5408ff6af65eece8bbe70c671f9f8b94f012dd97eb3f8efcbeae6b34fc2fa3932ffac63b68c7167eeea1b7798872c92e40c057663cd1bdd07ce887a175b0feb74c394f9232dbaf3c8bd84e5624c2b6ca3605cfe3a1acfd1c5871a54d5a5b497588916840d422eeabc75d528275e0f7db46d95654ec9453c20000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9000000008a8c3b2f2bafb7b71f9192b2b8e02df5caf27c04b535ef577c0703f820a110155984f294bc01fccaf6957b622156a97712e57526ce7ef914af67e7aea2fd3daf8a4176660300ea64be6ab6c87b1a597cb96f7d5ac0ab59fe115190bc33946ba3";
    BlsctUint64Result rv = get_ctx_out_value_at(tx_hex.c_str(), 9999);
    BOOST_CHECK_EQUAL(rv.result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_scalar_to_uint64_null_returns_failure)
{
    BlsctUint64Result rv = scalar_to_uint64(nullptr);
    BOOST_CHECK_EQUAL(rv.result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_get_token_id_token_null_returns_failure)
{
    BlsctUint64Result rv = get_token_id_token(nullptr);
    BOOST_CHECK_EQUAL(rv.result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_get_token_id_subid_null_returns_failure)
{
    BlsctUint64Result rv = get_token_id_subid(nullptr);
    BOOST_CHECK_EQUAL(rv.result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_get_token_info_total_supply_bad_hex_returns_failure)
{
    BlsctUint64Result rv = get_token_info_total_supply("notahex");
    BOOST_CHECK_EQUAL(rv.result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_get_mint_token_predicate_amount_wrong_type_returns_failure)
{
    // use a create-token predicate — wrong type for mint-token query
    init();
    auto pk_rv = gen_random_public_key();
    BOOST_REQUIRE_EQUAL(pk_rv.result, BLSCT_SUCCESS);
    size_t token_info_len = 0;
    build_token_info(BlsctToken, &pk_rv.value, nullptr, nullptr, 0, 1000, nullptr, 0, &token_info_len);
    std::vector<char> token_info_hex(token_info_len + 1);
    build_token_info(BlsctToken, &pk_rv.value, nullptr, nullptr, 0, 1000, token_info_hex.data(), token_info_hex.size(), &token_info_len);

    size_t pred_len = 0;
    build_create_token_predicate(token_info_hex.data(), nullptr, 0, &pred_len);
    std::vector<uint8_t> pred_buf(pred_len);
    build_create_token_predicate(token_info_hex.data(), pred_buf.data(), pred_buf.size(), &pred_len);

    BlsctUint64Result rv = get_mint_token_predicate_amount(pred_buf.data(), pred_len);
    BOOST_CHECK_EQUAL(rv.result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_get_mint_nft_predicate_nft_id_wrong_type_returns_failure)
{
    // use a mint-token predicate — wrong type for mint-nft query
    init();
    auto pk_rv = gen_random_public_key();
    BOOST_REQUIRE_EQUAL(pk_rv.result, BLSCT_SUCCESS);

    size_t pred_len = 0;
    build_mint_token_predicate(&pk_rv.value, 42, nullptr, 0, &pred_len);
    std::vector<uint8_t> pred_buf(pred_len);
    build_mint_token_predicate(&pk_rv.value, 42, pred_buf.data(), pred_buf.size(), &pred_len);

    BlsctUint64Result rv = get_mint_nft_predicate_nft_id(pred_buf.data(), pred_len);
    BOOST_CHECK_EQUAL(rv.result, BLSCT_FAILURE);
}

// ---------------------------------------------------------------------------
// Null/bad-input failure cases fixed in earlier refactor
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_deserialize_raw_obj_null_returns_failure)
{
    uint8_t buf[4];
    size_t out_len = 0;
    BOOST_CHECK_EQUAL(deserialize_raw_obj(nullptr, buf, sizeof(buf), &out_len), BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_build_ctx_empty_ins_or_outs_returns_failure)
{
    char buf[1];
    size_t out_len = 0;
    BlsctTxOutData dummy_out{};
    BlsctTxInData dummy_in{};
    BOOST_CHECK_EQUAL(build_ctx(nullptr, 0, &dummy_out, 1, buf, sizeof(buf), &out_len).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(build_ctx(&dummy_in, 1, nullptr, 0, buf, sizeof(buf), &out_len).result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_deserialize_token_id_wrong_size_returns_bad_size)
{
    // 4 bytes instead of TOKEN_ID_SIZE (40)
    BlsctTokenIdResult rv = deserialize_token_id("deadbeef");
    BOOST_CHECK_EQUAL(rv.result, BLSCT_BAD_SIZE);
}

BOOST_AUTO_TEST_CASE(test_build_tx_out_null_dest_returns_failure)
{
    init();
    auto tid_rv = gen_default_token_id();
    auto sk_rv = gen_random_scalar();
    BlsctTxOutResult rv = build_tx_out(
        nullptr, 100, "memo", &tid_rv.value,
        TxOutputType::Normal, 0, false, &sk_rv.value);
    BOOST_CHECK_EQUAL(rv.result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_build_tx_out_null_memo_returns_failure)
{
    init();
    auto sa_rv = gen_sub_addr_id(0, 0);
    auto tid_rv = gen_default_token_id();
    auto sk_rv = gen_random_scalar();
    // derive a valid sub address to use as dest
    auto view_rv = gen_random_scalar();
    auto spend_rv = gen_random_public_key();
    auto sub_rv = derive_sub_address(&view_rv.value, &spend_rv.value, &sa_rv.value);
    BOOST_REQUIRE_EQUAL(sub_rv.result, BLSCT_SUCCESS);
    BlsctTxOutResult rv = build_tx_out(
        &sub_rv.value, 100, nullptr, &tid_rv.value,
        TxOutputType::Normal, 0, false, &sk_rv.value);
    BOOST_CHECK_EQUAL(rv.result, BLSCT_FAILURE);

    uninit();
}

BOOST_AUTO_TEST_CASE(test_build_tx_out_memo_boundary)
{
    init();
    auto sa_rv = gen_sub_addr_id(0, 0);
    auto tid_rv = gen_default_token_id();
    auto sk_rv = gen_random_scalar();
    auto view_rv = gen_random_scalar();
    auto spend_rv = gen_random_public_key();
    auto sub_rv = derive_sub_address(&view_rv.value, &spend_rv.value, &sa_rv.value);
    BOOST_REQUIRE_EQUAL(sub_rv.result, BLSCT_SUCCESS);

    // exactly MAX_MEMO_LEN chars — must succeed
    std::string max_memo(MAX_MEMO_LEN, 'x');
    auto ok_rv = build_tx_out(&sub_rv.value, 100, max_memo.c_str(), &tid_rv.value, TxOutputType::Normal, 0, false, &sk_rv.value);
    BOOST_CHECK_EQUAL(ok_rv.result, BLSCT_SUCCESS);
    BOOST_CHECK_EQUAL(std::string(ok_rv.value.memo_c_str), max_memo);

    // MAX_MEMO_LEN + 1 chars — must fail
    std::string over_memo(MAX_MEMO_LEN + 1, 'x');
    auto fail_rv = build_tx_out(&sub_rv.value, 100, over_memo.c_str(), &tid_rv.value, TxOutputType::Normal, 0, false, &sk_rv.value);
    BOOST_CHECK_EQUAL(fail_rv.result, BLSCT_MEMO_TOO_LONG);

    uninit();
}

// ---------------------------------------------------------------------------
// Null pointer safety for ctx_in / ctx_out void* accessors
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_ctx_in_accessors_null_returns_failure)
{
    BOOST_CHECK_EQUAL(get_ctx_in_prev_out_hash(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_ctx_in_script_sig(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_ctx_in_sequence(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_ctx_in_script_witness(nullptr).result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_ctx_out_accessors_null_returns_failure)
{
    BOOST_CHECK_EQUAL(get_ctx_out_script_pub_key(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_ctx_out_spending_key(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_ctx_out_ephemeral_key(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_ctx_out_blinding_key(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_ctx_out_range_proof(nullptr, nullptr, 0, nullptr), BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_ctx_out_view_tag(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_ctx_out_token_id(nullptr).result, BLSCT_FAILURE);
}

// ---------------------------------------------------------------------------
// BlsctTxInData / BlsctTxOutData null accessor failure cases
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_tx_in_null_accessors_return_failure)
{
    BOOST_CHECK_EQUAL(get_tx_in_amount(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_tx_in_gamma(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_tx_in_spending_key(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_tx_in_token_id(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_tx_in_out_point(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_tx_in_staked_commitment(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_tx_in_rbf(nullptr).result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_tx_out_null_accessors_return_failure)
{
    BOOST_CHECK_EQUAL(get_tx_out_destination(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_tx_out_amount(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_tx_out_memo(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_tx_out_token_id(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_tx_out_output_type(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_tx_out_min_stake(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_tx_out_subtract_fee_from_amount(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_tx_out_blinding_key(nullptr).result, BLSCT_FAILURE);
}

// ---------------------------------------------------------------------------
// BlsctInt64Result / BlsctUint64Result null pointer safety for sub_addr_id
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_get_sub_addr_id_null_returns_failure)
{
    BOOST_CHECK_EQUAL(get_sub_addr_id_account(nullptr).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_sub_addr_id_address(nullptr).result, BLSCT_FAILURE);
}

// ---------------------------------------------------------------------------
// BlsctSizeTResult null pointer safety
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_sizeresult_null_returns_failure)
{
    BOOST_CHECK_EQUAL(point_to_str(nullptr, nullptr, 0).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(scalar_to_str(nullptr, nullptr, 0).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(serialize_range_proof(nullptr, 0, nullptr, 0).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(serialize_vector_predicate(nullptr, 0, nullptr, 0).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(serialize_raw_obj(nullptr, 0, nullptr, 0).result, BLSCT_FAILURE);
}

// ---------------------------------------------------------------------------
// BlsctUint64Result null pointer safety for calc_view_tag
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_calc_view_tag_null_returns_failure)
{
    init();
    auto view_rv = gen_scalar(1);
    BOOST_REQUIRE_EQUAL(view_rv.result, BLSCT_SUCCESS);
    auto pk_rv = gen_random_public_key();
    BOOST_REQUIRE_EQUAL(pk_rv.result, BLSCT_SUCCESS);

    BOOST_CHECK_EQUAL(calc_view_tag(nullptr, &view_rv.value).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(calc_view_tag(&pk_rv.value, nullptr).result, BLSCT_FAILURE);
}

// ---------------------------------------------------------------------------
// BlsctSizeTResult bad-hex failure cases (get_ctx_ins_size / get_ctx_outs_size)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_get_ctx_ins_size_bad_hex_returns_failure)
{
    BOOST_CHECK_EQUAL(get_ctx_ins_size("notahex").result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_get_ctx_outs_size_bad_hex_returns_failure)
{
    BOOST_CHECK_EQUAL(get_ctx_outs_size("notahex").result, BLSCT_FAILURE);
}

// ---------------------------------------------------------------------------
// BlsctCTxIdHexResult bad-hex failure case (get_ctx_id)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_get_ctx_id_bad_hex_returns_failure)
{
    BOOST_CHECK_EQUAL(get_ctx_id("notahex").result, BLSCT_FAILURE);
}

// ---------------------------------------------------------------------------
// _at indexed accessors: bad hex → BLSCT_FAILURE
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_ctx_in_at_accessors_bad_hex_return_failure)
{
    BOOST_CHECK_EQUAL(get_ctx_in_prev_out_hash_at("notahex", 0).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_ctx_in_script_sig_at("notahex", 0).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_ctx_in_sequence_at("notahex", 0).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_ctx_in_script_witness_at("notahex", 0).result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_ctx_out_at_accessors_bad_hex_return_failure)
{
    BOOST_CHECK_EQUAL(get_ctx_out_script_pub_key_at("notahex", 0).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_ctx_out_token_id_at("notahex", 0).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_ctx_out_spending_key_at("notahex", 0).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_ctx_out_ephemeral_key_at("notahex", 0).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_ctx_out_blinding_key_at("notahex", 0).result, BLSCT_FAILURE);
    BOOST_CHECK_EQUAL(get_ctx_out_view_tag_at("notahex", 0).result, BLSCT_FAILURE);
}

// ---------------------------------------------------------------------------
// Deserializer bad-hex / wrong-size failure cases
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_deserialize_dpk_bad_hex_returns_bad_size)
{
    BOOST_CHECK_EQUAL(deserialize_dpk("deadbeef").result, BLSCT_BAD_SIZE);
}

BOOST_AUTO_TEST_CASE(test_deserialize_key_id_bad_hex_returns_bad_size)
{
    BOOST_CHECK_EQUAL(deserialize_key_id("deadbeef").result, BLSCT_BAD_SIZE);
}

BOOST_AUTO_TEST_CASE(test_deserialize_out_point_bad_hex_returns_bad_size)
{
    BOOST_CHECK_EQUAL(deserialize_out_point("deadbeef").result, BLSCT_BAD_SIZE);
}

BOOST_AUTO_TEST_CASE(test_deserialize_point_bad_hex_returns_failure)
{
    BOOST_CHECK_EQUAL(deserialize_point("notahex").result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_deserialize_public_key_bad_hex_returns_failure)
{
    BOOST_CHECK_EQUAL(deserialize_public_key("notahex").result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_deserialize_scalar_bad_hex_returns_failure)
{
    BOOST_CHECK_EQUAL(deserialize_scalar("notahex").result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_deserialize_script_bad_hex_returns_bad_size)
{
    BOOST_CHECK_EQUAL(deserialize_script("deadbeef").result, BLSCT_BAD_SIZE);
}

BOOST_AUTO_TEST_CASE(test_deserialize_signature_bad_hex_returns_bad_size)
{
    BOOST_CHECK_EQUAL(deserialize_signature("deadbeef").result, BLSCT_BAD_SIZE);
}

BOOST_AUTO_TEST_CASE(test_deserialize_sub_addr_bad_hex_returns_bad_size)
{
    BOOST_CHECK_EQUAL(deserialize_sub_addr("deadbeef").result, BLSCT_BAD_SIZE);
}

BOOST_AUTO_TEST_CASE(test_deserialize_sub_addr_id_bad_hex_returns_bad_size)
{
    BOOST_CHECK_EQUAL(deserialize_sub_addr_id("deadbeef").result, BLSCT_BAD_SIZE);
}

// ---------------------------------------------------------------------------
// Token info bad-input failure cases
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_get_token_info_type_null_returns_failure)
{
    BOOST_CHECK_EQUAL(get_token_info_type(nullptr).result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_get_token_info_type_bad_hex_returns_failure)
{
    BOOST_CHECK_EQUAL(get_token_info_type("notahex").result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_get_token_info_public_key_bad_hex_returns_failure)
{
    BOOST_CHECK_EQUAL(get_token_info_public_key("notahex").result, BLSCT_FAILURE);
}

// ---------------------------------------------------------------------------
// BlsctPredicateTypeResult null pointer safety
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_get_vector_predicate_type_null_returns_failure)
{
    BOOST_CHECK_EQUAL(get_vector_predicate_type(nullptr, 0).result, BLSCT_FAILURE);
}

// ---------------------------------------------------------------------------
// BlsctPubKeyResult wrong-predicate-type failure cases
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_get_mint_token_predicate_public_key_wrong_type_returns_failure)
{
    init();
    auto pk_rv = gen_random_public_key();
    BOOST_REQUIRE_EQUAL(pk_rv.result, BLSCT_SUCCESS);
    size_t token_info_len = 0;
    build_token_info(BlsctToken, &pk_rv.value, nullptr, nullptr, 0, 1000, nullptr, 0, &token_info_len);
    std::vector<char> token_info_hex(token_info_len + 1);
    build_token_info(BlsctToken, &pk_rv.value, nullptr, nullptr, 0, 1000, token_info_hex.data(), token_info_hex.size(), &token_info_len);
    size_t pred_len = 0;
    build_create_token_predicate(token_info_hex.data(), nullptr, 0, &pred_len);
    std::vector<uint8_t> pred_buf(pred_len);
    build_create_token_predicate(token_info_hex.data(), pred_buf.data(), pred_buf.size(), &pred_len);

    BOOST_CHECK_EQUAL(get_mint_token_predicate_public_key(pred_buf.data(), pred_len).result, BLSCT_FAILURE);
}

BOOST_AUTO_TEST_CASE(test_get_mint_nft_predicate_public_key_wrong_type_returns_failure)
{
    init();
    auto pk_rv = gen_random_public_key();
    BOOST_REQUIRE_EQUAL(pk_rv.result, BLSCT_SUCCESS);
    size_t pred_len = 0;
    build_mint_token_predicate(&pk_rv.value, 42, nullptr, 0, &pred_len);
    std::vector<uint8_t> pred_buf(pred_len);
    build_mint_token_predicate(&pk_rv.value, 42, pred_buf.data(), pred_buf.size(), &pred_len);

    BOOST_CHECK_EQUAL(get_mint_nft_predicate_public_key(pred_buf.data(), pred_len).result, BLSCT_FAILURE);
}

// ---------------------------------------------------------------------------
// BlsctDoublePubKeyResult bad-address failure case (decode_address)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_decode_address_bad_input_returns_exception)
{
    BOOST_CHECK_EQUAL(decode_address("notanaddress").result, BLSCT_EXCEPTION);
}

// ---------------------------------------------------------------------------
// BlsctTxOutResult memo-too-long failure case
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(test_build_tx_out_memo_too_long_returns_memo_too_long)
{
    init();
    auto sa_rv = gen_sub_addr_id(0, 0);
    auto tid_rv = gen_default_token_id();
    auto sk_rv = gen_random_scalar();
    auto view_rv = gen_random_scalar();
    auto spend_rv = gen_random_public_key();
    BOOST_REQUIRE_EQUAL(sa_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(tid_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(sk_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(view_rv.result, BLSCT_SUCCESS);
    BOOST_REQUIRE_EQUAL(spend_rv.result, BLSCT_SUCCESS);
    auto sub_rv = derive_sub_address(&view_rv.value, &spend_rv.value, &sa_rv.value);
    BOOST_REQUIRE_EQUAL(sub_rv.result, BLSCT_SUCCESS);

    std::string long_memo(MAX_MEMO_LEN + 1, 'x');
    BlsctTxOutResult rv = build_tx_out(
        &sub_rv.value, 100, long_memo.c_str(), &tid_rv.value,
        TxOutputType::Normal, 0, false, &sk_rv.value);
    BOOST_CHECK_EQUAL(rv.result, BLSCT_MEMO_TOO_LONG);
}

BOOST_AUTO_TEST_SUITE_END()
