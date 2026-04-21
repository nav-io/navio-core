// Copyright (c) 2024 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVCOIN_BLSCT_EXTERNAL_API_BLSCT_H
#define NAVCOIN_BLSCT_EXTERNAL_API_BLSCT_H

#include <blsct/arith/elements.h>
#include <blsct/arith/mcl/mcl.h>
#include <blsct/chain.h>
#include <blsct/double_public_key.h>
#include <blsct/private_key.h>
#include <blsct/public_key.h>
#include <blsct/range_proof/setup.h>
#include <cstdint>
#include <primitives/transaction.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <tinyformat.h>
#include <util/strencodings.h>

/* constants */
#define PUBLIC_KEY_SIZE 48
#define DOUBLE_PUBLIC_KEY_SIZE PUBLIC_KEY_SIZE * 2
#define SUB_ADDR_SIZE DOUBLE_PUBLIC_KEY_SIZE
#define SUB_ADDR_ID_SIZE 16
#define KEY_ID_SIZE 20
#define POINT_SIZE 48
#define SCALAR_SIZE 32
#define TOKEN_ID_SIZE 40 // uint256 + uint64_t = 32 + 8 = 40
#define UINT256_SIZE 32
#define OUT_POINT_SIZE 32
#define SIGNATURE_SIZE 96
#define SCRIPT_SIZE 28
#define MAX_MEMO_LEN 100

#define BLSCT_SCALAR_HEX_SIZE (SCALAR_SIZE * 2 + 1)
#define BLSCT_POINT_HEX_SIZE (POINT_SIZE * 2 + 1)
#define BLSCT_DPK_HEX_SIZE (DOUBLE_PUBLIC_KEY_SIZE * 2 + 1)
#define BLSCT_KEY_ID_HEX_SIZE (KEY_ID_SIZE * 2 + 1)
#define BLSCT_SCRIPT_HEX_SIZE (SCRIPT_SIZE * 2 + 1)
#define BLSCT_TOKEN_ID_HEX_SIZE (TOKEN_ID_SIZE * 2 + 1)
#define BLSCT_CTX_ID_HEX_SIZE (CTX_ID_SIZE * 2 + 1)
#define BLSCT_OUT_POINT_HEX_SIZE (OUT_POINT_SIZE * 2 + 1)
#define BLSCT_SIGNATURE_HEX_SIZE (SIGNATURE_SIZE * 2 + 1)
#define BLSCT_SUB_ADDR_HEX_SIZE (SUB_ADDR_SIZE * 2 + 1)
#define BLSCT_SUB_ADDR_ID_HEX_SIZE (SUB_ADDR_ID_SIZE * 2 + 1)
#define MEMO_BUF_SIZE MAX_MEMO_LEN + 1
#define CTX_ID_SIZE UINT256_SIZE
#define CTX_ID_STR_LEN CTX_ID_SIZE * 2

/* return codes */
#define BLSCT_RESULT uint8_t
#define BLSCT_SUCCESS 0
#define BLSCT_FAILURE 1
#define BLSCT_EXCEPTION 2
#define BLSCT_BAD_SIZE 10
#define BLSCT_UNKNOWN_ENCODING 11
#define BLSCT_VALUE_OUTSIDE_THE_RANGE 12
#define BLSCT_DID_NOT_RUN_TO_COMPLETION 13
#define BLSCT_IN_AMOUNT_ERROR 14
#define BLSCT_OUT_AMOUNT_ERROR 15
#define BLSCT_BAD_OUT_TYPE 16
#define BLSCT_MEMO_TOO_LONG 17
#define BLSCT_MEM_ALLOC_FAILED 18
#define BLSCT_DESER_FAILED 19
#define BLSCT_INIT_NOT_CALLED 20

#define TRY_DEFINE_MCL_POINT_FROM(src, dest)         \
    Point dest;                                      \
    if (!from_blsct_point_to_mcl_point(src, dest)) { \
        return BLSCT_FAILURE;                        \
    }

#define TRY_DEFINE_MCL_SCALAR_FROM(src, dest) \
    Scalar dest;                              \
    from_blsct_scalar_to_mcl_scalar(src, dest)

#define SERIALIZE_AND_COPY(src, dest)                   \
    {                                                   \
        auto src_vec = src.GetVch();                    \
        std::memcpy(dest, &src_vec[0], src_vec.size()); \
    }

#define UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(src, src_size, dest) \
    {                                                                \
        Span buf(U8C(src), src_size);                                \
        DataStream st{};                                             \
        st << buf;                                                   \
        dest.Unserialize(st);                                        \
    }

#define SERIALIZE_AND_COPY_WITH_STREAM(src, dest) \
    {                                             \
        DataStream st{};                          \
        src.Serialize(st);                        \
        std::memcpy(dest, st.data(), st.size());  \
    }

#define UNSERIALIZE_AND_COPY_WITH_STREAM(src, src_size, dest) \
    {                                                         \
        DataStream st{};                                      \
        for (size_t i = 0; i < src_size; ++i) {               \
            st << src[i];                                     \
        }                                                     \
        dest.Unserialize(st);                                 \
    }

#define BLSCT_COPY(src, dest) std::memcpy(dest, src, sizeof(dest))
#define BLSCT_COPY_BYTES(src, dest, n) std::memcpy(dest, src, n)
#define MALLOC_BYTES(T, name, n) T* name = (T*)malloc(n)
#define RETURN_IF_MEM_ALLOC_FAILED(name)              \
    if (name == nullptr) {                            \
        fputs("Failed to allocate memory\n", stderr); \
        return nullptr;                               \
    }

#define U8C(name) reinterpret_cast<const uint8_t*>(name)

#define TO_VOID(name) reinterpret_cast<void*>(name)

#define UNVOID(T, name) const T* name = reinterpret_cast<const T*>(void_##name)

inline bool TryParseHexWrap(
    const std::string& hex,
    std::vector<uint8_t>& out_vec)
{
    auto maybe_vec = TryParseHex<uint8_t>(hex);
    if (!maybe_vec.has_value()) {
        return false;
    }
    out_vec = std::move(*maybe_vec);
    return true;
}


#ifdef __cplusplus
extern "C" {
#endif

enum BlsctChain {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
};

enum TxOutputType {
    Normal,
    StakedCommitment
};

enum AddressEncoding {
    Bech32,
    Bech32M
};

enum BlsctTokenType {
    BlsctToken = 0,
    BlsctNft = 1
};

enum BlsctPredicateType {
    BlsctCreateTokenPredicateType = 0,
    BlsctMintTokenPredicateType = 1,
    BlsctMintNftPredicateType = 2,
    BlsctPayFeePredicateType = 3,
    BlsctDataPredicateType = 4,
    BlsctInvalidPredicateType = 255
};

using Point = Mcl::Point;
using Scalar = Mcl::Scalar;
using Scalars = Elements<Scalar>;

typedef uint8_t BlsctCTxId[CTX_ID_SIZE];
typedef uint8_t BlsctDoublePubKey[DOUBLE_PUBLIC_KEY_SIZE];
typedef uint8_t BlsctKeyId[KEY_ID_SIZE]; // serialization of CKeyID which is based on uint160
typedef uint8_t BlsctOutPoint[OUT_POINT_SIZE];
typedef uint8_t BlsctPoint[POINT_SIZE];
typedef uint8_t BlsctPubKey[PUBLIC_KEY_SIZE];
typedef uint8_t BlsctScalar[SCALAR_SIZE];
typedef uint8_t BlsctScript[SCRIPT_SIZE];
typedef uint8_t BlsctSignature[SIGNATURE_SIZE];
typedef uint8_t BlsctSubAddr[SUB_ADDR_SIZE];
typedef uint8_t BlsctSubAddrId[SUB_ADDR_ID_SIZE];
typedef uint8_t BlsctTokenId[TOKEN_ID_SIZE];
typedef uint8_t BlsctUint256[UINT256_SIZE];

typedef char BlsctScalarHex[BLSCT_SCALAR_HEX_SIZE];
typedef char BlsctPointHex[BLSCT_POINT_HEX_SIZE];
typedef char BlsctDoublePubKeyHex[BLSCT_DPK_HEX_SIZE];
typedef char BlsctKeyIdHex[BLSCT_KEY_ID_HEX_SIZE];
typedef char BlsctScriptHex[BLSCT_SCRIPT_HEX_SIZE];
typedef char BlsctTokenIdHex[BLSCT_TOKEN_ID_HEX_SIZE];
typedef char BlsctCTxIdHex[BLSCT_CTX_ID_HEX_SIZE];
typedef char BlsctOutPointHex[BLSCT_OUT_POINT_HEX_SIZE];
typedef char BlsctSignatureHex[BLSCT_SIGNATURE_HEX_SIZE];
typedef char BlsctSubAddrHex[BLSCT_SUB_ADDR_HEX_SIZE];
typedef char BlsctSubAddrIdHex[BLSCT_SUB_ADDR_ID_HEX_SIZE];

typedef uint8_t BlsctCTx;
typedef uint8_t BlsctRangeProof;
typedef uint8_t BlsctVectorPredicate;

/* Fixed-size typed result structs (value embedded inline) */
typedef struct {
    BLSCT_RESULT result;
    BlsctDoublePubKey value;
} BlsctDoublePubKeyResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctKeyId value;
} BlsctKeyIdResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctOutPoint value;
} BlsctOutPointResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctPoint value;
} BlsctPointResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctPubKey value;
} BlsctPubKeyResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctScalar value;
} BlsctScalarResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctScript value;
} BlsctScriptResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctSignature value;
} BlsctSignatureResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctSubAddr value;
} BlsctSubAddrResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctSubAddrId value;
} BlsctSubAddrIdResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctTokenId value;
} BlsctTokenIdResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctUint256 value;
} BlsctUint256Result;
typedef struct {
    BLSCT_RESULT result;
    BlsctCTxId value;
} BlsctCTxIdResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctScalarHex value;
} BlsctScalarHexResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctPointHex value;
} BlsctPointHexResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctDoublePubKeyHex value;
} BlsctDoublePubKeyHexResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctKeyIdHex value;
} BlsctKeyIdHexResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctScriptHex value;
} BlsctScriptHexResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctTokenIdHex value;
} BlsctTokenIdHexResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctCTxIdHex value;
} BlsctCTxIdHexResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctOutPointHex value;
} BlsctOutPointHexResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctSignatureHex value;
} BlsctSignatureHexResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctSubAddrHex value;
} BlsctSubAddrHexResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctSubAddrIdHex value;
} BlsctSubAddrIdHexResult;

/* Heap-pointer result structs (opaque C++ objects) */
typedef struct {
    uint64_t amount;
    BlsctScalar gamma;
    BlsctScalar spending_key;
    BlsctTokenId token_id;
    BlsctOutPoint out_point;
    bool staked_commitment;
    bool rbf;
} BlsctTxInData;

typedef struct {
    BlsctSubAddr dest;
    uint64_t amount;
    char memo_c_str[MEMO_BUF_SIZE];
    BlsctTokenId token_id;
    TxOutputType output_type;
    uint64_t min_stake;
    bool subtract_fee_from_amount;
    BlsctScalar blinding_key;
} BlsctTxOutData;

typedef struct {
    BLSCT_RESULT result;
    BlsctTxInData value;
} BlsctTxInResult;
typedef struct {
    BLSCT_RESULT result;
    BlsctTxOutData value;
} BlsctTxOutResult;
typedef struct {
    BLSCT_RESULT result;
    bool value;
} BlsctBoolResult;
typedef struct {
    BLSCT_RESULT result;
    int64_t value;
} BlsctInt64Result;

typedef struct {
    BLSCT_RESULT result;
    uint64_t value;
} BlsctUint64Result;

typedef struct {
    BLSCT_RESULT result;
    uint32_t value;
} BlsctUint32Result;

typedef struct {
    BLSCT_RESULT result;
    uint16_t value;
} BlsctUint16Result;

typedef struct {
    BLSCT_RESULT result;
    size_t value;
} BlsctSizeTResult;

typedef struct {
    BLSCT_RESULT result;
    enum BlsctTokenType value;
} BlsctTokenTypeResult;

typedef struct {
    BLSCT_RESULT result;
    TxOutputType value;
} BlsctTxOutputTypeResult;

typedef struct {
    BLSCT_RESULT result;
    enum BlsctPredicateType value;
} BlsctPredicateTypeResult;

typedef struct {
    BLSCT_RESULT result;
    const char* value;
} BlsctStrResult;

typedef void (*BlsctStringMapCallback)(const char* key, const char* value, void* user_data);

typedef struct {
    BLSCT_RESULT result;
    size_t in_amount_err_index;
    size_t out_amount_err_index;
} BlsctCTxResult;

typedef struct {
    BlsctRangeProof* range_proof;
    size_t range_proof_size;
    BlsctPoint nonce;
    BlsctTokenId token_id;
} BlsctAmountRecoveryReq;

typedef struct {
    bool is_succ;
    char msg[MEMO_BUF_SIZE];
    uint64_t amount;
    BlsctScalar gamma;
} BlsctAmountRecoveryResult;

void free_obj(void* x);
void init();
void uninit();

enum BlsctChain get_blsct_chain();
void set_blsct_chain(enum BlsctChain chain);

BlsctSizeTResult serialize_raw_obj(const uint8_t* ser_obj, size_t ser_obj_size, char* buf, size_t buf_size);
BLSCT_RESULT deserialize_raw_obj(const char* hex, uint8_t* buf, size_t buf_size, size_t* out_len);

// address
BlsctDoublePubKeyResult decode_address(
    const char* blsct_enc_addr);

BLSCT_RESULT encode_address(
    const void* void_blsct_dpk,
    enum AddressEncoding encoding,
    char* buf,
    size_t buf_size,
    size_t* out_len);

// amount recovery
// reqs[i].range_proof must point to caller-owned bytes (not freed by this function)
// results must be an array of n elements; each entry is written inline
BLSCT_RESULT recover_amount(
    const BlsctAmountRecoveryReq* reqs,
    size_t n,
    BlsctAmountRecoveryResult* results);

// ctx
BlsctCTxResult build_ctx(
    const BlsctTxInData* tx_ins,
    size_t tx_ins_len,
    const BlsctTxOutData* tx_outs,
    size_t tx_outs_len,
    char* buf,
    size_t buf_size,
    size_t* out_len);
BlsctCTxIdHexResult get_ctx_id(const char* hex);

// ctx id
BlsctCTxIdHexResult serialize_ctx_id(const BlsctCTxId* blsct_ctx_id);
BlsctCTxIdResult deserialize_ctx_id(const char* hex);

// signed transaction aggregation
BLSCT_RESULT aggregate_transactions(const char* const* tx_hexes, size_t tx_count, char* buf, size_t buf_size, size_t* out_len);

// ctx_ins (indexed access via hex)
bool are_ctx_ins_equal(const char* hex_a, const char* hex_b);
BlsctSizeTResult get_ctx_ins_size(const char* hex);

// ctx in (raw pointer accessors — for direct C++ object use)
bool are_ctx_in_equal(const void* vp_a, const void* vp_b);
BlsctCTxIdResult get_ctx_in_prev_out_hash(const void* vp_ctx_in);
BlsctScriptResult get_ctx_in_script_sig(const void* vp_ctx_in);
BlsctUint32Result get_ctx_in_sequence(const void* vp_ctx_in);
BlsctScriptResult get_ctx_in_script_witness(const void* vp_ctx_in);

// ctx in (indexed access via hex)
BlsctCTxIdResult get_ctx_in_prev_out_hash_at(const char* hex, size_t i);
BlsctScriptResult get_ctx_in_script_sig_at(const char* hex, size_t i);
BlsctUint32Result get_ctx_in_sequence_at(const char* hex, size_t i);
BlsctScriptResult get_ctx_in_script_witness_at(const char* hex, size_t i);

// ctx_outs (indexed access via hex)
bool are_ctx_outs_equal(const char* hex_a, const char* hex_b);
BlsctSizeTResult get_ctx_outs_size(const char* hex);

// ctx out (raw pointer accessors — for direct C++ object use)
bool are_ctx_out_equal(const void* vp_a, const void* vp_b);
BlsctUint64Result get_ctx_out_value(const void* vp_ctx_out);
BlsctScriptResult get_ctx_out_script_pub_key(const void* vp_ctx_out);
BlsctTokenIdResult get_ctx_out_token_id(const void* vp_ctx_out);
BLSCT_RESULT get_ctx_out_vector_predicate(const void* vp_ctx_out, uint8_t* buf, size_t buf_size, size_t* out_len);
BlsctPointResult get_ctx_out_spending_key(const void* vp_ctx_out);
BlsctPointResult get_ctx_out_ephemeral_key(const void* vp_ctx_out);
BlsctPointResult get_ctx_out_blinding_key(const void* vp_ctx_out);
BLSCT_RESULT get_ctx_out_range_proof(const void* vp_ctx_out, uint8_t* buf, size_t buf_size, size_t* out_len);
BlsctUint16Result get_ctx_out_view_tag(const void* vp_ctx_out);

// ctx out (indexed access via hex)
BlsctUint64Result get_ctx_out_value_at(const char* hex, size_t i);
BlsctScriptResult get_ctx_out_script_pub_key_at(const char* hex, size_t i);
BlsctTokenIdResult get_ctx_out_token_id_at(const char* hex, size_t i);
BLSCT_RESULT get_ctx_out_vector_predicate_at(const char* hex, size_t i, uint8_t* buf, size_t buf_size, size_t* out_len);
BlsctPointResult get_ctx_out_spending_key_at(const char* hex, size_t i);
BlsctPointResult get_ctx_out_ephemeral_key_at(const char* hex, size_t i);
BlsctPointResult get_ctx_out_blinding_key_at(const char* hex, size_t i);
BLSCT_RESULT get_ctx_out_range_proof_at(const char* hex, size_t i, uint8_t* buf, size_t buf_size, size_t* out_len);
BlsctUint16Result get_ctx_out_view_tag_at(const char* hex, size_t i);

// double public key
BlsctDoublePubKeyResult gen_double_pub_key(
    const BlsctPubKey* blsct_pk1,
    const BlsctPubKey* blsct_pk2);

BlsctDoublePubKeyResult gen_dpk_with_keys_acct_addr(
    const BlsctScalar* blsct_view_key,
    const BlsctPubKey* blsct_spending_pub_key,
    const int64_t account,
    const uint64_t address);


BlsctSubAddrResult dpk_to_sub_addr(
    const BlsctDoublePubKey* blsct_dpk);

BlsctDoublePubKeyHexResult serialize_dpk(const BlsctDoublePubKey* blsct_dpk);
BlsctDoublePubKeyResult deserialize_dpk(const char* hex);

// key id (=Hash ID)
BlsctKeyIdResult calc_key_id(
    const BlsctPubKey* blsct_blinding_pub_key,
    const BlsctPubKey* blsct_spending_pub_key,
    const BlsctScalar* blsct_view_key);

BlsctKeyIdHexResult serialize_key_id(const BlsctKeyId* blsct_key_id);
BlsctKeyIdResult deserialize_key_id(const char* hex);

// out point
// txid is 32 bytes and represented as 64-char hex str
BlsctOutPointResult gen_out_point(
    const char* ctx_id_c_str);
BlsctOutPointHexResult serialize_out_point(const BlsctOutPoint* blsct_out_point);
BlsctOutPointResult deserialize_out_point(const char* hex);

// point
int are_point_equal(const BlsctPoint* a, const BlsctPoint* b);
BlsctPointResult gen_base_point();
BlsctPointResult gen_random_point();
BlsctPointResult scalar_muliply_point(
    const BlsctPoint* blsct_point,
    const BlsctScalar* blsct_scalar);
BlsctSizeTResult point_to_str(const BlsctPoint* blsct_point, char* buf, size_t buf_size);
BlsctPointResult point_from_scalar(const BlsctScalar* blsct_scalar);
bool is_valid_point(const BlsctPoint* blsct_point);

BlsctPointHexResult serialize_point(const BlsctPoint* blsct_point);
BlsctPointResult deserialize_point(const char* hex);

// public key
BlsctPubKeyResult gen_random_public_key();
BlsctPointResult get_public_key_point(const BlsctPubKey* blsct_pub_key);
BlsctPubKeyResult point_to_public_key(const BlsctPoint* blsct_point);
BlsctPointHexResult serialize_public_key(const BlsctPoint* blsct_point);
BlsctPubKeyResult deserialize_public_key(const char* hex);

// range proof
BLSCT_RESULT build_range_proof(
    const uint64_t* amounts,
    size_t amounts_len,
    const BlsctPoint* blsct_nonce,
    const char* blsct_msg,
    const BlsctTokenId* blsct_token_id,
    uint8_t* buf,
    size_t buf_size,
    size_t* out_len);

BlsctBoolResult verify_range_proofs(
    const BlsctRangeProof* const* proofs,
    const size_t* proof_sizes,
    size_t proof_count);

BlsctPointResult get_range_proof_A(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);
BlsctPointResult get_range_proof_A_wip(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);
BlsctPointResult get_range_proof_B(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);

BlsctScalarResult get_range_proof_r_prime(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);
BlsctScalarResult get_range_proof_s_prime(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);
BlsctScalarResult get_range_proof_delta_prime(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);
BlsctScalarResult get_range_proof_alpha_hat(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);
BlsctScalarResult get_range_proof_tau_x(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);


BlsctSizeTResult serialize_range_proof(
    const BlsctRangeProof* blsct_range_proof,
    size_t range_proof_size,
    char* buf,
    size_t buf_size);
BLSCT_RESULT deserialize_range_proof(
    const char* hex,
    const size_t range_proof_size,
    uint8_t* buf,
    size_t buf_size,
    size_t* out_len);

// scalar
int are_scalar_equal(const BlsctScalar* a, const BlsctScalar* b);
BlsctScalarResult gen_random_scalar();
BlsctScalarResult gen_scalar(const uint64_t n);
BlsctUint64Result scalar_to_uint64(const BlsctScalar* blsct_scalar);

BlsctSizeTResult scalar_to_str(const BlsctScalar* blsct_scalar, char* buf, size_t buf_size);
BlsctPubKeyResult scalar_to_pub_key(const BlsctScalar* blsct_scalar);

BlsctScalarHexResult serialize_scalar(const BlsctScalar* blsct_scalar);
BlsctScalarResult deserialize_scalar(const char* hex);

// script
BlsctScriptHexResult serialize_script(const BlsctScript* blsct_script);
BlsctScriptResult deserialize_script(const char* hex);

// signature
BlsctSignatureResult sign_message(
    const BlsctScalar* blsct_priv_key,
    const char* blsct_msg);

bool verify_msg_sig(
    const BlsctPubKey* blsct_pub_key,
    const char* blsct_msg,
    const BlsctSignature* blsct_signature);

BlsctSignatureHexResult serialize_signature(const BlsctSignature* blsct_signature);
BlsctSignatureResult deserialize_signature(const char* hex);

// sub addr
BlsctSubAddrResult derive_sub_address(
    const BlsctScalar* blsct_view_key,
    const BlsctPubKey* blsct_spending_pub_key,
    const BlsctSubAddrId* blsct_sub_addr_id);

BlsctDoublePubKeyResult sub_addr_to_dpk(
    const BlsctSubAddr* blsct_sub_addr);

BlsctSubAddrHexResult serialize_sub_addr(const BlsctSubAddr* blsct_sub_addr);
BlsctSubAddrResult deserialize_sub_addr(const char* hex);

// sub addr id
BlsctSubAddrIdResult gen_sub_addr_id(
    const int64_t account,
    const uint64_t address);

BlsctInt64Result get_sub_addr_id_account(
    const BlsctSubAddrId* blsct_sub_addr_id);

BlsctUint64Result get_sub_addr_id_address(
    const BlsctSubAddrId* blsct_sub_addr_id);

BlsctSubAddrIdHexResult serialize_sub_addr_id(const BlsctSubAddrId* blsct_sub_addr_id);
BlsctSubAddrIdResult deserialize_sub_addr_id(const char* hex);

// token id
BlsctTokenIdResult gen_token_id_with_token_and_subid(
    const uint64_t token,
    const uint64_t subid);

BlsctTokenIdResult gen_token_id(
    const uint64_t token);

BlsctTokenIdResult gen_default_token_id();
BlsctUint64Result get_token_id_token(const BlsctTokenId* blsct_token_id);
BlsctUint64Result get_token_id_subid(const BlsctTokenId* blsct_token_id);
BlsctTokenIdHexResult serialize_token_id(const BlsctTokenId* blsct_token_id);
BlsctTokenIdResult deserialize_token_id(const char* hex);

// token info helpers
BLSCT_RESULT build_token_info(
    enum BlsctTokenType type,
    const BlsctPubKey* blsct_public_key,
    const char* const* metadata_keys,
    const char* const* metadata_values,
    size_t metadata_count,
    const uint64_t total_supply,
    char* buf,
    size_t buf_size,
    size_t* out_len);
BlsctTokenTypeResult get_token_info_type(const char* hex);
BlsctPubKeyResult get_token_info_public_key(const char* hex);
BlsctUint64Result get_token_info_total_supply(const char* hex);
void get_token_info_metadata(const char* hex, BlsctStringMapCallback cb, void* user_data);

// collection token hash and token key derivation
BlsctUint256Result calc_collection_token_hash(
    const char* const* metadata_keys,
    const char* const* metadata_values,
    size_t metadata_count,
    const uint64_t total_supply);
BlsctScalarResult derive_collection_token_key(
    const BlsctScalar* blsct_master_token_key,
    const BlsctUint256* blsct_collection_token_hash);
BlsctPubKeyResult derive_collection_token_public_key(
    const BlsctScalar* blsct_master_token_key,
    const BlsctUint256* blsct_collection_token_hash);

// tx in
BlsctTxInResult build_tx_in(
    const uint64_t amount,
    const BlsctScalar* gamma,
    const BlsctScalar* spending_key,
    const BlsctTokenId* token_id,
    const BlsctOutPoint* out_point,
    const bool staked_commitment,
    const bool rbf);

BlsctUint64Result get_tx_in_amount(const BlsctTxInData* tx_in);
BlsctScalarResult get_tx_in_gamma(const BlsctTxInData* tx_in);
BlsctScalarResult get_tx_in_spending_key(const BlsctTxInData* tx_in);
BlsctTokenIdResult get_tx_in_token_id(const BlsctTxInData* tx_in);
BlsctOutPointResult get_tx_in_out_point(const BlsctTxInData* tx_in);
BlsctBoolResult get_tx_in_staked_commitment(const BlsctTxInData* tx_in);
BlsctBoolResult get_tx_in_rbf(const BlsctTxInData* tx_in);

// tx out
BlsctTxOutResult build_tx_out(
    const BlsctSubAddr* blsct_dest,
    const uint64_t amount,
    const char* memo_c_str,
    const BlsctTokenId* blsct_token_id,
    const TxOutputType output_type,
    const uint64_t min_stake,
    const bool subtract_fee_from_amount,
    const BlsctScalar* blsct_blinding_key);

BlsctSubAddrResult get_tx_out_destination(const BlsctTxOutData* tx_out);
BlsctUint64Result get_tx_out_amount(const BlsctTxOutData* tx_out);
BlsctStrResult get_tx_out_memo(const BlsctTxOutData* tx_out);
BlsctTokenIdResult get_tx_out_token_id(const BlsctTxOutData* tx_out);
BlsctTxOutputTypeResult get_tx_out_output_type(const BlsctTxOutData* tx_out);
BlsctUint64Result get_tx_out_min_stake(const BlsctTxOutData* tx_out);
BlsctBoolResult get_tx_out_subtract_fee_from_amount(const BlsctTxOutData* tx_out);
BlsctScalarResult get_tx_out_blinding_key(const BlsctTxOutData* tx_out);

// vector predicate
int are_vector_predicate_equal(
    const BlsctVectorPredicate* a,
    const size_t a_size,
    const BlsctVectorPredicate* b,
    const size_t b_size);
BlsctSizeTResult serialize_vector_predicate(
    const BlsctVectorPredicate* blsct_vector_predicate,
    size_t obj_size,
    char* buf,
    size_t buf_size);
BLSCT_RESULT deserialize_vector_predicate(
    const char* hex,
    uint8_t* buf,
    size_t buf_size,
    size_t* out_len);
BlsctPredicateTypeResult get_vector_predicate_type(
    const BlsctVectorPredicate* blsct_vector_predicate,
    size_t obj_size);
BLSCT_RESULT build_create_token_predicate(
    const char* token_info_hex,
    uint8_t* buf,
    size_t buf_size,
    size_t* out_len);
BLSCT_RESULT build_mint_token_predicate(
    const BlsctPubKey* blsct_token_public_key,
    const uint64_t amount,
    uint8_t* buf,
    size_t buf_size,
    size_t* out_len);
BLSCT_RESULT build_mint_nft_predicate(
    const BlsctPubKey* blsct_token_public_key,
    const uint64_t nft_id,
    const char* const* metadata_keys,
    const char* const* metadata_values,
    size_t metadata_count,
    uint8_t* buf,
    size_t buf_size,
    size_t* out_len);
BLSCT_RESULT get_create_token_predicate_token_info(
    const BlsctVectorPredicate* blsct_vector_predicate,
    size_t obj_size,
    char* buf,
    size_t buf_size,
    size_t* out_len);
BlsctPubKeyResult get_mint_token_predicate_public_key(
    const BlsctVectorPredicate* blsct_vector_predicate,
    size_t obj_size);
BlsctUint64Result get_mint_token_predicate_amount(
    const BlsctVectorPredicate* blsct_vector_predicate,
    size_t obj_size);
BlsctPubKeyResult get_mint_nft_predicate_public_key(
    const BlsctVectorPredicate* blsct_vector_predicate,
    size_t obj_size);
BlsctUint64Result get_mint_nft_predicate_nft_id(
    const BlsctVectorPredicate* blsct_vector_predicate,
    size_t obj_size);
void get_mint_nft_predicate_metadata(
    const BlsctVectorPredicate* blsct_vector_predicate,
    size_t obj_size,
    BlsctStringMapCallback cb,
    void* user_data);

// unsigned input/output/transaction helpers
BLSCT_RESULT build_unsigned_input(const BlsctTxInData* tx_in, char* buf, size_t buf_size, size_t* out_len);

BLSCT_RESULT build_unsigned_output(const BlsctTxOutData* tx_out, char* buf, size_t buf_size, size_t* out_len);
BLSCT_RESULT build_unsigned_create_token_output(
    const BlsctScalar* blsct_token_key,
    const char* token_info_hex,
    char* buf,
    size_t buf_size,
    size_t* out_len);
BLSCT_RESULT build_unsigned_mint_token_output(
    const BlsctSubAddr* blsct_dest,
    const uint64_t amount,
    const BlsctScalar* blsct_blinding_key,
    const BlsctScalar* blsct_token_key,
    const BlsctPubKey* blsct_token_public_key,
    char* buf,
    size_t buf_size,
    size_t* out_len);
BLSCT_RESULT build_unsigned_mint_nft_output(
    const BlsctSubAddr* blsct_dest,
    const BlsctScalar* blsct_blinding_key,
    const BlsctScalar* blsct_token_key,
    const BlsctPubKey* blsct_token_public_key,
    const uint64_t nft_id,
    const char* const* metadata_keys,
    const char* const* metadata_values,
    size_t metadata_count,
    char* buf,
    size_t buf_size,
    size_t* out_len);

// Build and sign a transaction from caller-supplied hex arrays.
// input_hexes: array of n_inputs serialized UnsignedInput hex strings
// output_hexes: array of n_outputs serialized UnsignedOutput hex strings
// fee: transaction fee in satoshis
BLSCT_RESULT sign_unsigned_transaction(
    const char* const* input_hexes, size_t n_inputs,
    const char* const* output_hexes, size_t n_outputs,
    uint64_t fee,
    char* buf, size_t buf_size, size_t* out_len);

// key derivation functions

// seed (scalar)
//  +---> child key (scalar)
//         +--------> blinding key (scalar)
//         +--------> token key (scalar)
//         +--------> tx key (scalar)
//                     +----> view key (scalar)
//                     +----> spending key (scalar)

// from seed
BlsctScalarResult from_seed_to_child_key(
    const BlsctScalar* blsct_seed);

// from child_key
BlsctScalarResult from_child_key_to_blinding_key(
    const BlsctScalar* blsct_child_key);

BlsctScalarResult from_child_key_to_token_key(
    const BlsctScalar* blsct_child_key);

BlsctScalarResult from_child_key_to_tx_key(
    const BlsctScalar* blsct_child_key);

// from tx key
BlsctScalarResult from_tx_key_to_view_key(
    const BlsctScalar* blsct_tx_key);

BlsctScalarResult from_tx_key_to_spending_key(
    const BlsctScalar* blsct_tx_key);

// from multiple keys and other info
BlsctScalarResult calc_priv_spending_key(
    const BlsctPubKey* blsct_blinding_pub_key,
    const BlsctScalar* blsct_view_key,
    const BlsctScalar* blsct_spending_key,
    const int64_t account,
    const uint64_t address);

// blsct/wallet/helpers delegators
BlsctUint64Result calc_view_tag(
    const BlsctPubKey* blinding_pub_key,
    const BlsctScalar* view_key);

BlsctPointResult calc_nonce(
    const BlsctPubKey* blsct_blinding_pub_key,
    const BlsctScalar* view_key);

// Misc helper functions and macros migrated from blist.i
#define HANDLE_MEM_ALLOC_FAILURE(name)             \
    if (name == nullptr) {                         \
        puts("ERROR: Memory allocation failed\n"); \
        return nullptr;                            \
    }

#define RETURN_RET_VAL_IF_NULL(p, ret_val) \
    if (p == nullptr) {                    \
        puts("ERROR: " #p " is null\n");   \
        return ret_val;                    \
    }
#define RETURN_IF_NULL(p)                \
    if (p == nullptr) {                  \
        puts("ERROR: " #p " is null\n"); \
        return;                          \
    }

size_t buf_to_hex(const uint8_t* buf, size_t size, char* out, size_t out_size);

// uint64 vector

} // extern "C"

#endif // NAVCOIN_BLSCT_EXTERNAL_API_BLSCT_H
