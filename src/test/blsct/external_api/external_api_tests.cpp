// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/external_api/blsct.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof_logic.h>
#include <util/strencodings.h>
#include <blsct/eip_2333/bls12_381_keygen.h>
#include <blsct/tokens/predicate_parser.h>
#include <blsct/wallet/unsigned_transaction.h>
#include <core_io.h>
#include <hash.h>
#include <blsct/wallet/txfactory.h>
#include <blsct/wallet/verification.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <txdb.h>
#include <wallet/receive.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>
#include <iostream>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(external_api_tests, BasicTestingSetup)

uint8_t hex_to_uint(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    } else {
        throw std::invalid_argument("Unexpected hex char found");
    }
}

template <typename T>
T& RequireSuccess(BlsctRetVal* rv)
{
    BOOST_REQUIRE(rv != nullptr);
    BOOST_REQUIRE_EQUAL(rv->result, BLSCT_SUCCESS);
    BOOST_REQUIRE(rv->value != nullptr);
    return *static_cast<T*>(rv->value);
}

static std::map<std::string, std::string> ReadStringMap(const void* vp_string_map)
{
    std::map<std::string, std::string> out;
    const size_t size = get_string_map_size(vp_string_map);
    for (size_t i = 0; i < size; ++i) {
        const char* key = get_string_map_key_at(vp_string_map, i);
        const char* value = get_string_map_value_at(vp_string_map, i);
        BOOST_REQUIRE(key != nullptr);
        BOOST_REQUIRE(value != nullptr);
        out[key] = value;
        free_obj((void*)key);
        free_obj((void*)value);
    }
    return out;
}

// This test checks if there is any structural change in
// CMutableTransaction and its dependencies
BOOST_AUTO_TEST_CASE(test_cmutable_transaction_sizes)
{
    // in case there is a structural change in CMutableTransaction,
    // tx_hex needs to be regenerated to reflect the structure change
    std::string tx_hex = "200000000100000000000000000000000000000000000000000000000000000000000000000503615d0200ffffffff02ffffffffffffff7f0100000000000000015101855f4e35c5fbe93bf5b8a7a2dc55420144388fd0736ce7d9c8289e793da409d89f2bf2f4f4ac9364d81922d9255c33880683ed1c387aa2555b28af1c6d2b4a2725af9551263c00962daeec3736de0724167d18579973ff9cfcaeedc9ed59036aaaa2ad79cef575dc618d14729169a88c87edb5d3303efab1109572ca4a98800d61c45d8ca9074a7beb9c5c4123e7af8054b4bce1a360c663b86e8af1f06dea120fce8d7529b90ff383fd69c7dd9a50215881df91544949b95eaeac780c133699bdb030b321c32c0efbafa29fe840fe93b01bffc47e096a4577f5ba7d6745506f5e658cbd21c0c7f4c5fc28fdb28dd1c27a8027da5ca650a48ced1c52725abc54a1bd54e9823341753de270ea7882fd54b5b7513d9184635b9dbf0812ccf769df4cb50985bfa52fa515fa7034a317b2da1453d2d919797a22e6889c8aada6fe25e2dfda8f57f57de8fc2a9fa957d264240d06b8548ad7eec8b644df2e89b9a5a1d83ecce4ca94005b7d61782743e74ed011f7cc96c634327b67cfbc954de4effa0d7884f88d27ac1c1686bad02f527975ed9f3e7b2570120dc68ad88ddd350119d00c6df24916d5fc361f20f4f4d4482711b5850b3f91c9315beb1af544d63ed7049b6a1af783e0171526ba9c31466de735527d2d1bfeaf292a73ecf0312e6e784ae18dc6949e4a452fadc0734bff7bdf56074434f7a311290ba2ec6cbe960e29829d2b8ad6fb7946e356580b5a40f9676274a8336c5eecc36a9ddb58bb81cd8d08dfda7714aa9634941a94076cbc3ed74561d9043146dc81f1ccafd4e06f98faae3da017fe07af9ac407d0b81e6e1e634e5b53f5f98728850298673e355093844d0443466fad33d233ed7c40c1788a43d4d48d63778e8cf80e9cd5d01e789637b0cae99a372dd0bc8b5dbf2bc2df9fea229d71eaebab6a9277bb3bb3ba07c14edef6a7fcdcf02e8c1e927872003b9683d3b3ff1e740d5ec8a8145361166b33da8dcda6edf5d7bf32f63d27a5b72e515e6641b672275eee06f3bd5abd6790eded07d49b9e55e5c29e136eb5ad4857f9f55b6e7be10d2002ed91244243ea0fe7b6dea43ea70eb0d3d438ae2a335ced8e1620392562a2c503d2c4b53bed0d39c3749cb032741cacd0ca73bc6d72d350184cc82a45ad8df2e3443599ba51dfd5dce328362f9032cb350f579234f36c282d4b0acdf27d6a8d66f62713adf6481c8c9f240f59a15c6e064a5c05b56e6c068801f639ee1e83003a6a8dd97d5c24b5236c30d43efa0d75709fcaba4ca72077232f537900b2697973d2a08ee405d4298d4a8afeb24f6066b9648b3265e10931756678606fc173b92525567648af5408ff6af65eece8bbe70c671f9f8b94f012dd97eb3f8efcbeae6b34fc2fa3932ffac63b68c7167eeea1b7798872c92e40c057663cd1bdd07ce887a175b0feb74c394f9232dbaf3c8bd84e5624c2b6ca3605cfe3a1acfd1c5871a54d5a5b497588916840d422eeabc75d528275e0f7db46d95654ec9453c20000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9000000008a8c3b2f2bafb7b71f9192b2b8e02df5caf27c04b535ef577c0703f820a110155984f294bc01fccaf6957b622156a97712e57526ce7ef914af67e7aea2fd3daf8a4176660300ea64be6ab6c87b1a597cb96f7d5ac0ab59fe115190bc33946ba3";

    DataStream st{ParseHex(tx_hex)};
    TransactionSerParams params { .allow_witness = true };
    ParamsStream ps {params, st};

    CMutableTransaction tx;

    try {
        tx.Unserialize(ps); // should not throw an exception
    } catch(...) {
        BOOST_CHECK(false);
    }
}

BOOST_AUTO_TEST_CASE(test_build_tx_in_gamma_is_blsct_scalar)
{
    init();

    // create a random scalar to use as gamma
    auto gamma_rv = gen_random_scalar();
    BOOST_REQUIRE(gamma_rv->result == BLSCT_SUCCESS);
    auto* gamma = static_cast<BlsctScalar*>(gamma_rv->value);

    // create a spending key
    auto sk_rv = gen_random_scalar();
    BOOST_REQUIRE(sk_rv->result == BLSCT_SUCCESS);
    auto* spending_key = static_cast<BlsctScalar*>(sk_rv->value);

    // create a token id
    auto tid_rv = gen_default_token_id();
    BOOST_REQUIRE(tid_rv->result == BLSCT_SUCCESS);
    auto* token_id = static_cast<BlsctTokenId*>(tid_rv->value);

    // create an out point
    std::string txid_hex(64, '0');
    auto op_rv = gen_out_point(txid_hex.c_str());
    BOOST_REQUIRE(op_rv->result == BLSCT_SUCCESS);
    auto* out_point = static_cast<BlsctOutPoint*>(op_rv->value);

    auto* tx_in_rv = build_tx_in(
        1000,
        gamma,
        spending_key,
        token_id,
        out_point,
        false,
        false);
    BOOST_REQUIRE(tx_in_rv->result == BLSCT_SUCCESS);
    auto* tx_in = static_cast<BlsctTxIn*>(tx_in_rv->value);

    // verify the amount round-trips
    BOOST_CHECK_EQUAL(get_tx_in_amount(tx_in), 1000ULL);

    // verify the gamma round-trips as a full 32-byte scalar
    const BlsctScalar* retrieved_gamma = get_tx_in_gamma(tx_in);
    BOOST_REQUIRE(retrieved_gamma != nullptr);
    BOOST_CHECK(are_scalar_equal(gamma, retrieved_gamma) == 1);

    free_obj(gamma_rv);
    free_obj(sk_rv);
    free_obj(tid_rv);
    free_obj(op_rv);
    free_obj(tx_in_rv);
}

BOOST_AUTO_TEST_CASE(test_amount_recovery_returns_gamma)
{
    init();

    uint64_t amount = 42;
    std::string msg = "hello";
    std::vector<uint8_t> msg_vec(msg.begin(), msg.end());

    auto tid_rv = gen_default_token_id();
    BOOST_REQUIRE(tid_rv->result == BLSCT_SUCCESS);
    auto* blsct_token_id = static_cast<BlsctTokenId*>(tid_rv->value);

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

    auto* req = gen_amount_recovery_req(rp_buf, rp_size, &blsct_nonce, nullptr);
    BOOST_REQUIRE(req != nullptr);

    void* req_vec = create_amount_recovery_req_vec();
    add_to_amount_recovery_req_vec(req_vec, req);

    auto* amounts_rv = recover_amount(req_vec);
    BOOST_REQUIRE(amounts_rv->result == BLSCT_SUCCESS);

    BOOST_CHECK(get_amount_recovery_result_is_succ(amounts_rv->value, 0));
    BOOST_CHECK_EQUAL(get_amount_recovery_result_amount(amounts_rv->value, 0), amount);

    // verify the gamma matches the expected value from the C++ recovery
    const BlsctScalar* recovered_gamma = get_amount_recovery_result_gamma(amounts_rv->value, 0);
    BOOST_REQUIRE(recovered_gamma != nullptr);

    BlsctScalar expected_gamma_bytes;
    SERIALIZE_AND_COPY(expected_gamma, expected_gamma_bytes);
    BOOST_CHECK(are_scalar_equal(recovered_gamma, &expected_gamma_bytes) == 1);

    free(rp_buf);
    delete req;
    delete_amount_recovery_req_vec(req_vec);
    free_amounts_ret_val(amounts_rv);
    free_obj(tid_rv);
}

BOOST_AUTO_TEST_CASE(test_recovered_gamma_round_trips_through_tx_in)
{
    init();

    uint64_t amount = 100;
    std::string msg = "rt";
    std::vector<uint8_t> msg_vec(msg.begin(), msg.end());

    auto tid_rv = gen_default_token_id();
    BOOST_REQUIRE(tid_rv->result == BLSCT_SUCCESS);
    auto* blsct_token_id = static_cast<BlsctTokenId*>(tid_rv->value);

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

    auto* req = gen_amount_recovery_req(rp_buf, rp_st.size(), &blsct_nonce, nullptr);
    void* req_vec = create_amount_recovery_req_vec();
    add_to_amount_recovery_req_vec(req_vec, req);

    auto* amounts_rv = recover_amount(req_vec);
    BOOST_REQUIRE(amounts_rv->result == BLSCT_SUCCESS);
    BOOST_REQUIRE(get_amount_recovery_result_is_succ(amounts_rv->value, 0));

    const BlsctScalar* recovered_gamma = get_amount_recovery_result_gamma(amounts_rv->value, 0);

    // feed the recovered gamma directly into build_tx_in
    auto sk_rv = gen_random_scalar();
    BOOST_REQUIRE(sk_rv->result == BLSCT_SUCCESS);
    auto* spending_key = static_cast<BlsctScalar*>(sk_rv->value);

    std::string txid_hex(64, '0');
    auto op_rv = gen_out_point(txid_hex.c_str());
    BOOST_REQUIRE(op_rv->result == BLSCT_SUCCESS);
    auto* out_point = static_cast<BlsctOutPoint*>(op_rv->value);

    auto* tx_in_rv = build_tx_in(
        amount,
        recovered_gamma,
        spending_key,
        blsct_token_id,
        out_point,
        false,
        false);
    BOOST_REQUIRE(tx_in_rv->result == BLSCT_SUCCESS);
    auto* tx_in = static_cast<BlsctTxIn*>(tx_in_rv->value);

    // the gamma stored in the tx_in must equal the recovered gamma
    const BlsctScalar* tx_in_gamma = get_tx_in_gamma(tx_in);
    BOOST_CHECK(are_scalar_equal(recovered_gamma, tx_in_gamma) == 1);

    free(rp_buf);
    delete req;
    delete_amount_recovery_req_vec(req_vec);
    free_amounts_ret_val(amounts_rv);
    free_obj(sk_rv);
    free_obj(op_rv);
    free_obj(tx_in_rv);
    free_obj(tid_rv);
}

BOOST_AUTO_TEST_CASE(test_token_info_predicates_and_unsigned_outputs)
{
    init();

    auto* metadata = create_string_map();
    BOOST_REQUIRE(metadata != nullptr);
    add_to_string_map(metadata, "name", "Collection");
    add_to_string_map(metadata, "symbol", "COLL");

    auto* collection_hash_rv = calc_collection_token_hash(metadata, 1000);
    BOOST_REQUIRE(collection_hash_rv != nullptr);
    BOOST_REQUIRE_EQUAL(collection_hash_rv->result, BLSCT_SUCCESS);
    auto* collection_hash = static_cast<BlsctUint256*>(collection_hash_rv->value);

    const std::map<std::string, std::string> expected_metadata{{"name", "Collection"}, {"symbol", "COLL"}};
    const uint256 expected_collection_hash = (HashWriter{} << expected_metadata << CAmount{1000}).GetHash();
    BOOST_CHECK(std::memcmp(collection_hash, expected_collection_hash.begin(), UINT256_SIZE) == 0);

    auto* master_token_key_rv = gen_scalar(42);
    BOOST_REQUIRE(master_token_key_rv != nullptr);
    BOOST_REQUIRE_EQUAL(master_token_key_rv->result, BLSCT_SUCCESS);
    auto* master_token_key = static_cast<BlsctScalar*>(master_token_key_rv->value);

    auto* token_key_rv = derive_collection_token_key(master_token_key, collection_hash);
    BOOST_REQUIRE(token_key_rv != nullptr);
    BOOST_REQUIRE_EQUAL(token_key_rv->result, BLSCT_SUCCESS);
    auto* token_key = static_cast<BlsctScalar*>(token_key_rv->value);

    MclScalar expected_token_key = BLS12_381_KeyGen::derive_child_SK_hash(MclScalar(uint64_t{42}), expected_collection_hash);
    MclScalar token_key_native;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(token_key, SCALAR_SIZE, token_key_native);
    BOOST_CHECK(token_key_native == expected_token_key);

    const BlsctPubKey* token_public_key = derive_collection_token_public_key(master_token_key, collection_hash);
    BOOST_REQUIRE(token_public_key != nullptr);

    auto* token_info_rv = build_token_info(BlsctToken, token_public_key, metadata, 1000);
    auto& token_info = RequireSuccess<blsct::TokenInfo>(token_info_rv);
    BOOST_CHECK_EQUAL(get_token_info_type(&token_info), BlsctToken);
    BOOST_CHECK_EQUAL(get_token_info_total_supply(&token_info), 1000U);

    void* token_info_metadata = get_token_info_metadata(&token_info);
    BOOST_REQUIRE(token_info_metadata != nullptr);
    BOOST_CHECK(ReadStringMap(token_info_metadata) == expected_metadata);
    delete_string_map(token_info_metadata);

    const char* token_info_hex = serialize_token_info(&token_info);
    BOOST_REQUIRE(token_info_hex != nullptr);
    auto* token_info_roundtrip_rv = deserialize_token_info(token_info_hex);
    auto& token_info_roundtrip = RequireSuccess<blsct::TokenInfo>(token_info_roundtrip_rv);
    BOOST_CHECK_EQUAL(token_info_roundtrip.nTotalSupply, token_info.nTotalSupply);
    BOOST_CHECK(token_info_roundtrip.publicKey == token_info.publicKey);
    BOOST_CHECK(token_info_roundtrip.mapMetadata == token_info.mapMetadata);

    auto* create_pred_rv = build_create_token_predicate(&token_info);
    BOOST_REQUIRE(create_pred_rv != nullptr);
    BOOST_REQUIRE_EQUAL(create_pred_rv->result, BLSCT_SUCCESS);
    auto* create_pred = static_cast<BlsctVectorPredicate*>(create_pred_rv->value);
    BOOST_CHECK_EQUAL(get_vector_predicate_type(create_pred, create_pred_rv->value_size), BlsctCreateTokenPredicateType);

    auto* parsed_token_info_rv = get_create_token_predicate_token_info(create_pred, create_pred_rv->value_size);
    auto& parsed_token_info = RequireSuccess<blsct::TokenInfo>(parsed_token_info_rv);
    BOOST_CHECK(parsed_token_info.publicKey == token_info.publicKey);
    BOOST_CHECK_EQUAL(parsed_token_info.nTotalSupply, token_info.nTotalSupply);
    BOOST_CHECK(parsed_token_info.mapMetadata == token_info.mapMetadata);

    auto* mint_pred_rv = build_mint_token_predicate(token_public_key, 25);
    BOOST_REQUIRE(mint_pred_rv != nullptr);
    BOOST_REQUIRE_EQUAL(mint_pred_rv->result, BLSCT_SUCCESS);
    auto* mint_pred = static_cast<BlsctVectorPredicate*>(mint_pred_rv->value);
    BOOST_CHECK_EQUAL(get_vector_predicate_type(mint_pred, mint_pred_rv->value_size), BlsctMintTokenPredicateType);
    BOOST_CHECK_EQUAL(get_mint_token_predicate_amount(mint_pred, mint_pred_rv->value_size), 25U);

    const BlsctPubKey* mint_pred_pub_key = get_mint_token_predicate_public_key(mint_pred, mint_pred_rv->value_size);
    BOOST_REQUIRE(mint_pred_pub_key != nullptr);
    const char* token_pub_hex = serialize_public_key(reinterpret_cast<const BlsctPoint*>(token_public_key));
    const char* mint_pub_hex = serialize_public_key(reinterpret_cast<const BlsctPoint*>(mint_pred_pub_key));
    BOOST_REQUIRE(token_pub_hex != nullptr);
    BOOST_REQUIRE(mint_pub_hex != nullptr);
    BOOST_CHECK_EQUAL(std::string(token_pub_hex), std::string(mint_pub_hex));

    auto* nft_metadata = create_string_map();
    BOOST_REQUIRE(nft_metadata != nullptr);
    add_to_string_map(nft_metadata, "rarity", "legendary");

    auto* mint_nft_pred_rv = build_mint_nft_predicate(token_public_key, 7, nft_metadata);
    BOOST_REQUIRE(mint_nft_pred_rv != nullptr);
    BOOST_REQUIRE_EQUAL(mint_nft_pred_rv->result, BLSCT_SUCCESS);
    auto* mint_nft_pred = static_cast<BlsctVectorPredicate*>(mint_nft_pred_rv->value);
    BOOST_CHECK_EQUAL(get_vector_predicate_type(mint_nft_pred, mint_nft_pred_rv->value_size), BlsctMintNftPredicateType);
    BOOST_CHECK_EQUAL(get_mint_nft_predicate_nft_id(mint_nft_pred, mint_nft_pred_rv->value_size), 7U);

    void* parsed_nft_metadata = get_mint_nft_predicate_metadata(mint_nft_pred, mint_nft_pred_rv->value_size);
    BOOST_REQUIRE(parsed_nft_metadata != nullptr);
    const std::map<std::string, std::string> expected_nft_metadata{{"rarity", "legendary"}};
    BOOST_CHECK(ReadStringMap(parsed_nft_metadata) == expected_nft_metadata);
    delete_string_map(parsed_nft_metadata);

    auto* view_key_rv = gen_scalar(11);
    auto* spend_key_rv = gen_scalar(12);
    BOOST_REQUIRE(view_key_rv != nullptr);
    BOOST_REQUIRE(spend_key_rv != nullptr);
    const BlsctPubKey* spend_pub_key = scalar_to_pub_key(static_cast<const BlsctScalar*>(spend_key_rv->value));
    BOOST_REQUIRE(spend_pub_key != nullptr);
    auto* sub_addr_id = gen_sub_addr_id(0, 1);
    BOOST_REQUIRE(sub_addr_id != nullptr);
    auto* dest = derive_sub_address(static_cast<const BlsctScalar*>(view_key_rv->value), spend_pub_key, sub_addr_id);
    BOOST_REQUIRE(dest != nullptr);
    auto* blinding_key_rv = gen_scalar(99);
    BOOST_REQUIRE(blinding_key_rv != nullptr);

    auto* create_output_rv = build_unsigned_create_token_output(token_key, &token_info);
    BOOST_REQUIRE(create_output_rv != nullptr);
    BOOST_REQUIRE_EQUAL(create_output_rv->result, BLSCT_SUCCESS);
    const char* create_output_hex = serialize_unsigned_output(create_output_rv->value);
    BOOST_REQUIRE(create_output_hex != nullptr);
    {
        DataStream st{ParseHex(create_output_hex)};
        blsct::UnsignedOutput output;
        st >> output;
        auto parsed = blsct::ParsePredicate(output.out.predicate);
        BOOST_CHECK(parsed.IsCreateTokenPredicate());
        BOOST_CHECK_EQUAL(parsed.GetTokenInfo().nTotalSupply, 1000);
    }

    auto* mint_output_rv = build_unsigned_mint_token_output(dest, 25, static_cast<const BlsctScalar*>(blinding_key_rv->value), token_key, token_public_key);
    BOOST_REQUIRE(mint_output_rv != nullptr);
    BOOST_REQUIRE_EQUAL(mint_output_rv->result, BLSCT_SUCCESS);
    const char* mint_output_hex = serialize_unsigned_output(mint_output_rv->value);
    BOOST_REQUIRE(mint_output_hex != nullptr);
    {
        DataStream st{ParseHex(mint_output_hex)};
        blsct::UnsignedOutput output;
        st >> output;
        auto parsed = blsct::ParsePredicate(output.out.predicate);
        BOOST_CHECK(parsed.IsMintTokenPredicate());
        BOOST_CHECK_EQUAL(parsed.GetAmount(), 25);
    }

    auto* mint_nft_output_rv = build_unsigned_mint_nft_output(dest, static_cast<const BlsctScalar*>(blinding_key_rv->value), token_key, token_public_key, 7, nft_metadata);
    BOOST_REQUIRE(mint_nft_output_rv != nullptr);
    BOOST_REQUIRE_EQUAL(mint_nft_output_rv->result, BLSCT_SUCCESS);
    const char* mint_nft_output_hex = serialize_unsigned_output(mint_nft_output_rv->value);
    BOOST_REQUIRE(mint_nft_output_hex != nullptr);
    {
        DataStream st{ParseHex(mint_nft_output_hex)};
        blsct::UnsignedOutput output;
        st >> output;
        auto parsed = blsct::ParsePredicate(output.out.predicate);
        BOOST_CHECK(parsed.IsMintNftPredicate());
        BOOST_CHECK_EQUAL(parsed.GetNftId(), 7U);
        BOOST_CHECK(parsed.GetNftMetaData() == expected_nft_metadata);
    }

    delete_string_map(metadata);
    delete_string_map(nft_metadata);
    delete_token_info(token_info_roundtrip_rv->value);
    free(token_info_roundtrip_rv);
    delete_token_info(parsed_token_info_rv->value);
    free(parsed_token_info_rv);
    delete_token_info(token_info_rv->value);
    free(token_info_rv);
    free_obj((void*)token_public_key);
    free_obj((void*)mint_pred_pub_key);
    free_obj((void*)token_pub_hex);
    free_obj((void*)mint_pub_hex);
    free_obj((void*)spend_pub_key);
    free_obj((void*)sub_addr_id);
    free_obj((void*)dest);
    free_obj((void*)create_output_hex);
    free_obj((void*)mint_output_hex);
    free_obj((void*)mint_nft_output_hex);
    delete_unsigned_output(create_output_rv->value);
    free(create_output_rv);
    delete_unsigned_output(mint_output_rv->value);
    free(mint_output_rv);
    delete_unsigned_output(mint_nft_output_rv->value);
    free(mint_nft_output_rv);
    free_obj(master_token_key_rv->value);
    free(master_token_key_rv);
    free_obj(token_key_rv->value);
    free(token_key_rv);
    free_obj(collection_hash_rv->value);
    free(collection_hash_rv);
    free_obj((void*)token_info_hex);
    free_obj(create_pred_rv->value);
    free(create_pred_rv);
    free_obj(mint_pred_rv->value);
    free(mint_pred_rv);
    free_obj(mint_nft_pred_rv->value);
    free(mint_nft_pred_rv);
    free_obj(view_key_rv->value);
    free(view_key_rv);
    free_obj(spend_key_rv->value);
    free(spend_key_rv);
    free_obj(blinding_key_rv->value);
    free(blinding_key_rv);
}

BOOST_AUTO_TEST_CASE(test_unsigned_transaction_sign)
{
    init();

    auto* view_key_rv = gen_scalar(21);
    auto* spend_key_rv = gen_scalar(22);
    auto* input_spending_key_rv = gen_scalar(23);
    auto* gamma_rv = gen_scalar(24);
    auto* blinding_key_rv = gen_scalar(25);
    auto* default_token_id_rv = gen_default_token_id();
    BOOST_REQUIRE(view_key_rv != nullptr);
    BOOST_REQUIRE(spend_key_rv != nullptr);
    BOOST_REQUIRE(input_spending_key_rv != nullptr);
    BOOST_REQUIRE(gamma_rv != nullptr);
    BOOST_REQUIRE(blinding_key_rv != nullptr);
    BOOST_REQUIRE(default_token_id_rv != nullptr);
    BOOST_REQUIRE_EQUAL(default_token_id_rv->result, BLSCT_SUCCESS);

    const BlsctPubKey* spend_pub_key = scalar_to_pub_key(static_cast<const BlsctScalar*>(spend_key_rv->value));
    BOOST_REQUIRE(spend_pub_key != nullptr);
    auto* sub_addr_id = gen_sub_addr_id(0, 2);
    BOOST_REQUIRE(sub_addr_id != nullptr);
    auto* dest = derive_sub_address(static_cast<const BlsctScalar*>(view_key_rv->value), spend_pub_key, sub_addr_id);
    BOOST_REQUIRE(dest != nullptr);

    auto* out_point_rv = gen_out_point("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    BOOST_REQUIRE(out_point_rv != nullptr);
    BOOST_REQUIRE_EQUAL(out_point_rv->result, BLSCT_SUCCESS);

    auto* tx_in_rv = build_tx_in(
        1000,
        static_cast<const BlsctScalar*>(gamma_rv->value),
        static_cast<const BlsctScalar*>(input_spending_key_rv->value),
        static_cast<const BlsctTokenId*>(default_token_id_rv->value),
        static_cast<const BlsctOutPoint*>(out_point_rv->value),
        false,
        false);
    BOOST_REQUIRE(tx_in_rv != nullptr);
    BOOST_REQUIRE_EQUAL(tx_in_rv->result, BLSCT_SUCCESS);

    auto* unsigned_input_rv = build_unsigned_input(static_cast<const BlsctTxIn*>(tx_in_rv->value));
    BOOST_REQUIRE(unsigned_input_rv != nullptr);
    BOOST_REQUIRE_EQUAL(unsigned_input_rv->result, BLSCT_SUCCESS);

    auto* tx_out_rv = build_tx_out(
        dest,
        500,
        "memo",
        static_cast<const BlsctTokenId*>(default_token_id_rv->value),
        TxOutputType::Normal,
        0,
        false,
        static_cast<const BlsctScalar*>(blinding_key_rv->value));
    BOOST_REQUIRE(tx_out_rv != nullptr);
    BOOST_REQUIRE_EQUAL(tx_out_rv->result, BLSCT_SUCCESS);

    auto* unsigned_output_rv = build_unsigned_output(static_cast<const BlsctTxOut*>(tx_out_rv->value));
    BOOST_REQUIRE(unsigned_output_rv != nullptr);
    BOOST_REQUIRE_EQUAL(unsigned_output_rv->result, BLSCT_SUCCESS);

    void* unsigned_tx = create_unsigned_transaction();
    BOOST_REQUIRE(unsigned_tx != nullptr);
    add_unsigned_transaction_input(unsigned_tx, unsigned_input_rv->value);
    add_unsigned_transaction_output(unsigned_tx, unsigned_output_rv->value);
    set_unsigned_transaction_fee(unsigned_tx, 125);

    BOOST_CHECK_EQUAL(get_unsigned_transaction_inputs_size(unsigned_tx), 1U);
    BOOST_CHECK_EQUAL(get_unsigned_transaction_outputs_size(unsigned_tx), 1U);
    BOOST_CHECK_EQUAL(get_unsigned_transaction_fee(unsigned_tx), 125U);

    const char* unsigned_tx_hex = serialize_unsigned_transaction(unsigned_tx);
    BOOST_REQUIRE(unsigned_tx_hex != nullptr);
    auto* unsigned_tx_roundtrip_rv = deserialize_unsigned_transaction(unsigned_tx_hex);
    BOOST_REQUIRE(unsigned_tx_roundtrip_rv != nullptr);
    BOOST_REQUIRE_EQUAL(unsigned_tx_roundtrip_rv->result, BLSCT_SUCCESS);

    BOOST_CHECK_EQUAL(get_unsigned_transaction_inputs_size(unsigned_tx_roundtrip_rv->value), 1U);
    BOOST_CHECK_EQUAL(get_unsigned_transaction_outputs_size(unsigned_tx_roundtrip_rv->value), 1U);
    BOOST_CHECK_EQUAL(get_unsigned_transaction_fee(unsigned_tx_roundtrip_rv->value), 125U);

    auto* signed_tx_rv = sign_unsigned_transaction(unsigned_tx_roundtrip_rv->value);
    BOOST_REQUIRE(signed_tx_rv != nullptr);
    BOOST_REQUIRE_EQUAL(signed_tx_rv->result, BLSCT_SUCCESS);
    const char* signed_tx_hex = static_cast<const char*>(signed_tx_rv->value);
    BOOST_REQUIRE(signed_tx_hex != nullptr);

    CMutableTransaction decoded;
    BOOST_REQUIRE(DecodeHexTx(decoded, signed_tx_hex));
    CTransaction signed_tx(decoded);
    BOOST_CHECK(signed_tx.IsBLSCT());
    BOOST_CHECK_EQUAL(signed_tx.vin.size(), 1U);
    BOOST_CHECK_EQUAL(signed_tx.vout.size(), 2U);
    BOOST_CHECK_EQUAL(signed_tx.vout.back().nValue, 125);
    auto fee_predicate = blsct::ParsePredicate(signed_tx.vout.back().predicate);
    BOOST_CHECK(fee_predicate.IsPayFeePredicate());

    free_obj(view_key_rv->value);
    free(view_key_rv);
    free_obj(spend_key_rv->value);
    free(spend_key_rv);
    free_obj(input_spending_key_rv->value);
    free(input_spending_key_rv);
    free_obj(gamma_rv->value);
    free(gamma_rv);
    free_obj(blinding_key_rv->value);
    free(blinding_key_rv);
    free_obj(default_token_id_rv->value);
    free(default_token_id_rv);
    free_obj((void*)spend_pub_key);
    free_obj((void*)sub_addr_id);
    free_obj((void*)dest);
    free_obj(out_point_rv->value);
    free(out_point_rv);
    free_obj(tx_in_rv->value);
    free(tx_in_rv);
    delete_unsigned_input(unsigned_input_rv->value);
    free(unsigned_input_rv);
    free_obj(tx_out_rv->value);
    free(tx_out_rv);
    delete_unsigned_output(unsigned_output_rv->value);
    free(unsigned_output_rv);
    free_obj((void*)unsigned_tx_hex);
    delete_unsigned_transaction(unsigned_tx);
    delete_unsigned_transaction(unsigned_tx_roundtrip_rv->value);
    free(unsigned_tx_roundtrip_rv);
    free_obj(signed_tx_rv->value);
    free(signed_tx_rv);
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
        auto* view_key_rv = gen_scalar(seed_base + 1);
        auto* spend_key_rv = gen_scalar(seed_base + 2);
        auto* input_spending_key_rv = gen_scalar(seed_base + 3);
        auto* gamma_rv = gen_scalar(seed_base + 4);
        auto* blinding_key_rv = gen_scalar(seed_base + 5);
        auto* default_token_id_rv = gen_default_token_id();

        BOOST_REQUIRE(view_key_rv != nullptr);
        BOOST_REQUIRE(spend_key_rv != nullptr);
        BOOST_REQUIRE(input_spending_key_rv != nullptr);
        BOOST_REQUIRE(gamma_rv != nullptr);
        BOOST_REQUIRE(blinding_key_rv != nullptr);
        BOOST_REQUIRE(default_token_id_rv != nullptr);
        BOOST_REQUIRE_EQUAL(default_token_id_rv->result, BLSCT_SUCCESS);

        const BlsctPubKey* spend_pub_key = scalar_to_pub_key(static_cast<const BlsctScalar*>(spend_key_rv->value));
        BOOST_REQUIRE(spend_pub_key != nullptr);

        auto* sub_addr_id = gen_sub_addr_id(0, seed_base);
        BOOST_REQUIRE(sub_addr_id != nullptr);
        auto* dest = derive_sub_address(static_cast<const BlsctScalar*>(view_key_rv->value), spend_pub_key, sub_addr_id);
        BOOST_REQUIRE(dest != nullptr);

        auto* out_point_rv = gen_out_point(out_point_hex);
        BOOST_REQUIRE(out_point_rv != nullptr);
        BOOST_REQUIRE_EQUAL(out_point_rv->result, BLSCT_SUCCESS);

        auto* tx_in_rv = build_tx_in(
            1000,
            static_cast<const BlsctScalar*>(gamma_rv->value),
            static_cast<const BlsctScalar*>(input_spending_key_rv->value),
            static_cast<const BlsctTokenId*>(default_token_id_rv->value),
            static_cast<const BlsctOutPoint*>(out_point_rv->value),
            false,
            false);
        BOOST_REQUIRE(tx_in_rv != nullptr);
        BOOST_REQUIRE_EQUAL(tx_in_rv->result, BLSCT_SUCCESS);

        auto* unsigned_input_rv = build_unsigned_input(static_cast<const BlsctTxIn*>(tx_in_rv->value));
        BOOST_REQUIRE(unsigned_input_rv != nullptr);
        BOOST_REQUIRE_EQUAL(unsigned_input_rv->result, BLSCT_SUCCESS);

        auto* tx_out_rv = build_tx_out(
            dest,
            output_amount,
            "aggregate",
            static_cast<const BlsctTokenId*>(default_token_id_rv->value),
            TxOutputType::Normal,
            0,
            false,
            static_cast<const BlsctScalar*>(blinding_key_rv->value));
        BOOST_REQUIRE(tx_out_rv != nullptr);
        BOOST_REQUIRE_EQUAL(tx_out_rv->result, BLSCT_SUCCESS);

        auto* unsigned_output_rv = build_unsigned_output(static_cast<const BlsctTxOut*>(tx_out_rv->value));
        BOOST_REQUIRE(unsigned_output_rv != nullptr);
        BOOST_REQUIRE_EQUAL(unsigned_output_rv->result, BLSCT_SUCCESS);

        void* unsigned_tx = create_unsigned_transaction();
        BOOST_REQUIRE(unsigned_tx != nullptr);
        add_unsigned_transaction_input(unsigned_tx, unsigned_input_rv->value);
        add_unsigned_transaction_output(unsigned_tx, unsigned_output_rv->value);
        set_unsigned_transaction_fee(unsigned_tx, fee);

        auto* signed_tx_rv = sign_unsigned_transaction(unsigned_tx);
        BOOST_REQUIRE(signed_tx_rv != nullptr);
        BOOST_REQUIRE_EQUAL(signed_tx_rv->result, BLSCT_SUCCESS);
        const std::string signed_tx_hex(static_cast<const char*>(signed_tx_rv->value));

        free_obj(view_key_rv->value);
        free(view_key_rv);
        free_obj(spend_key_rv->value);
        free(spend_key_rv);
        free_obj(input_spending_key_rv->value);
        free(input_spending_key_rv);
        free_obj(gamma_rv->value);
        free(gamma_rv);
        free_obj(blinding_key_rv->value);
        free(blinding_key_rv);
        free_obj(default_token_id_rv->value);
        free(default_token_id_rv);
        free_obj((void*)spend_pub_key);
        free_obj((void*)sub_addr_id);
        free_obj((void*)dest);
        free_obj(out_point_rv->value);
        free(out_point_rv);
        free_obj(tx_in_rv->value);
        free(tx_in_rv);
        delete_unsigned_input(unsigned_input_rv->value);
        free(unsigned_input_rv);
        free_obj(tx_out_rv->value);
        free(tx_out_rv);
        delete_unsigned_output(unsigned_output_rv->value);
        free(unsigned_output_rv);
        delete_unsigned_transaction(unsigned_tx);
        free_obj(signed_tx_rv->value);
        free(signed_tx_rv);

        return signed_tx_hex;
    };

    const std::string tx1 = build_signed_tx(31, "1111111111111111111111111111111111111111111111111111111111111111", 400, 125);
    const std::string tx2 = build_signed_tx(41, "2222222222222222222222222222222222222222222222222222222222222222", 300, 200);

    void* tx_hex_vec = create_tx_hex_vec();
    BOOST_REQUIRE(tx_hex_vec != nullptr);
    add_to_tx_hex_vec(tx_hex_vec, tx1.c_str());
    add_to_tx_hex_vec(tx_hex_vec, tx2.c_str());

    auto* aggregate_rv = aggregate_transactions(tx_hex_vec);
    BOOST_REQUIRE(aggregate_rv != nullptr);
    BOOST_REQUIRE_EQUAL(aggregate_rv->result, BLSCT_SUCCESS);
    const char* aggregate_hex = static_cast<const char*>(aggregate_rv->value);
    BOOST_REQUIRE(aggregate_hex != nullptr);

    CMutableTransaction decoded;
    BOOST_REQUIRE(DecodeHexTx(decoded, aggregate_hex));
    CTransaction aggregated_tx(decoded);
    BOOST_CHECK(aggregated_tx.IsBLSCT());
    BOOST_CHECK_EQUAL(aggregated_tx.vin.size(), 2U);
    BOOST_CHECK_EQUAL(aggregated_tx.vout.size(), 3U);
    BOOST_CHECK_EQUAL(aggregated_tx.vout.back().nValue, 325);
    auto fee_predicate = blsct::ParsePredicate(aggregated_tx.vout.back().predicate);
    BOOST_CHECK(fee_predicate.IsPayFeePredicate());

    delete_tx_hex_vec(tx_hex_vec);
    free_obj(aggregate_rv->value);
    free(aggregate_rv);
}

// Thin wrapper to test RETURN_ERR_IF_MEM_ALLOC_FAILED macro in isolation.
// With a correct macro, calling this with nullptr should return err(BLSCT_MEM_ALLOC_FAILED).
// With the buggy macro (missing return), err() is called but the result is discarded,
// and the function falls through to return succ(nullptr, 0) → BLSCT_SUCCESS.
static BlsctRetVal* test_return_err_if_mem_alloc_failed_macro()
{
    void* p = nullptr;
    RETURN_ERR_IF_MEM_ALLOC_FAILED(p);
    return succ(p, 0);
}

BOOST_AUTO_TEST_CASE(test_return_err_if_mem_alloc_failed_returns_error)
{
    auto* rv = test_return_err_if_mem_alloc_failed_macro();
    BOOST_REQUIRE(rv != nullptr);
    BOOST_CHECK_EQUAL(rv->result, BLSCT_MEM_ALLOC_FAILED);
    free_obj(rv);
}

BOOST_AUTO_TEST_SUITE_END()
