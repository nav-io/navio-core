// Copyright (c) 2024 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVCOIN_BLSCT_EXTERNAL_API_BLSCT_H
#define NAVCOIN_BLSCT_EXTERNAL_API_BLSCT_H

#include <blsct/double_public_key.h>
#include <blsct/private_key.h>
#include <blsct/public_key.h>
#include <blsct/arith/mcl/mcl.h>
#include <blsct/arith/elements.h>
#include <blsct/chain.h>
#include <blsct/range_proof/setup.h>
#include <primitives/transaction.h>
#include <tinyformat.h>
#include <cstdint>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <util/strencodings.h>

/* constants */
#define PUBLIC_KEY_SIZE 48
#define DOUBLE_PUBLIC_KEY_SIZE PUBLIC_KEY_SIZE * 2
#define SUB_ADDR_SIZE DOUBLE_PUBLIC_KEY_SIZE
#define SUB_ADDR_ID_SIZE 16
#define ENCODED_DPK_STR_SIZE 165
#define ENCODED_DPK_STR_BUF_SIZE ENCODED_DPK_STR_SIZE + 1 /* 1 for c-str null termination */
#define KEY_ID_SIZE 20
#define POINT_SIZE 48
#define SCALAR_SIZE 32
#define TOKEN_ID_SIZE 40  // uint256 + uint64_t = 32 + 8 = 40
#define UINT256_SIZE 32
#define VIEW_TAG_SIZE 8
#define OUT_POINT_SIZE 36
#define SIGNATURE_SIZE 96
#define SCRIPT_SIZE 28
#define MAX_MEMO_LEN 100
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

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  BLSCT_RESULT result;
  void* value;
  size_t value_size;
} BlsctRetVal;

BlsctRetVal* err(
    BLSCT_RESULT result
);

#ifdef __cplusplus
} // extern "C"
#endif

#define TRY_DEFINE_MCL_POINT_FROM(src, dest) \
    Point dest; \
    if (!from_blsct_point_to_mcl_point(src, dest)) { \
        return BLSCT_FAILURE; \
    }

#define TRY_DEFINE_MCL_SCALAR_FROM(src, dest) \
    Scalar dest; \
    from_blsct_scalar_to_mcl_scalar(src, dest)

#define SERIALIZE_AND_COPY(src, dest) \
{ \
    auto src_vec = src.GetVch(); \
    std::memcpy(dest, &src_vec[0], src_vec.size()); \
}

#define UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(src, src_size, dest) \
{ \
    Span buf(U8C(src), src_size); \
    DataStream st{}; \
    st << buf; \
    dest.Unserialize(st); \
}

#define SERIALIZE_AND_COPY_WITH_STREAM(src, dest) \
{ \
    DataStream st{}; \
    src.Serialize(st); \
    std::memcpy(dest, st.data(), st.size()); \
}

#define UNSERIALIZE_AND_COPY_WITH_STREAM(src, src_size, dest) \
{ \
    DataStream st{}; \
    for (size_t i=0; i<src_size; ++i) { \
        st << src[i]; \
    } \
    dest.Unserialize(st); \
}

#define BLSCT_COPY(src, dest) std::memcpy(dest, src, sizeof(dest))
#define BLSCT_COPY_BYTES(src, dest, n) std::memcpy(dest, src, n)

#define MALLOC(T, name) T* name = (T*) malloc(sizeof(T))
#define MALLOC_BYTES(T, name, n) T* name = (T*) malloc(n)
#define RETURN_IF_MEM_ALLOC_FAILED(name) \
if (name == nullptr) { \
    fputs("Failed to allocate memory\n", stderr); \
    return nullptr; \
}
#define RETURN_ERR_IF_MEM_ALLOC_FAILED(name) \
if (name == nullptr) err(BLSCT_MEM_ALLOC_FAILED);

#define U8C(name) reinterpret_cast<const uint8_t*>(name)

#define TO_VOID(name) reinterpret_cast<void*>(name)

#define UNVOID(T, name) const T* name = reinterpret_cast<const T*>(void_##name)

inline bool TryParseHexWrap(
    const std::string& hex,
    std::vector<uint8_t>& out_vec
) {
    auto maybe_vec = TryParseHex<uint8_t>(hex);
    if (!maybe_vec.has_value()) {
        return false;
    }
    out_vec = std::move(*maybe_vec);
    return true;
}

inline const char* StrToAllocCStr(const std::string& s) {
    size_t buf_size = s.size() + 1;
    MALLOC_BYTES(char, cstr_buf, buf_size);
    RETURN_IF_MEM_ALLOC_FAILED(cstr_buf);
    std::memcpy(cstr_buf, s.c_str(), buf_size); // also copies null at the end
    return cstr_buf;
}

inline const char* SerializeToHex(
    const uint8_t* blsct_obj,
    const size_t obj_size
) {
    if (blsct_obj == nullptr) return nullptr;

    std::vector<uint8_t> vec;
    vec.reserve(obj_size);
    for (size_t i=0; i<obj_size; ++i) {
        vec.push_back(blsct_obj[i]);
    }
    auto hex_str = HexStr(vec);
    return StrToAllocCStr(hex_str);
}

inline void* DeserializeFromHex(const char* hex, const size_t obj_size) {
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec)) {
        return err(BLSCT_FAILURE);
    }

    // check if the size is correct
    if (vec.size() != obj_size) {
        return err(BLSCT_BAD_SIZE);
    }

    void* blsct_obj = malloc(obj_size);
    if (blsct_obj == nullptr) {
        fputs("Failed to allocate memory\n", stderr);
        return nullptr;
    }
    std::memcpy(blsct_obj, &vec[0], obj_size);

    return blsct_obj;
}

#ifdef __cplusplus
extern "C" {
#endif

enum TxOutputType {
    Normal,
    StakedCommitment
};

enum AddressEncoding {
    Bech32,
    Bech32M
};

using Point = Mcl::Point;
using Scalar = Mcl::Scalar;
using Scalars = Elements<Scalar>;

typedef uint8_t BlsctKeyId[KEY_ID_SIZE];  // serialization of CKeyID which is based on uint160
typedef uint8_t BlsctPoint[POINT_SIZE];
typedef uint8_t BlsctPubKey[PUBLIC_KEY_SIZE];
typedef uint8_t BlsctDoublePubKey[DOUBLE_PUBLIC_KEY_SIZE];
typedef char BlsctAddrStr[ENCODED_DPK_STR_BUF_SIZE];
typedef uint8_t BlsctScalar[SCALAR_SIZE];
typedef uint8_t BlsctScript[SCRIPT_SIZE];
typedef uint8_t BlsctSubAddr[SUB_ADDR_SIZE];
typedef uint8_t BlsctSubAddrId[SUB_ADDR_ID_SIZE];
typedef uint8_t BlsctTokenId[TOKEN_ID_SIZE];
typedef uint8_t BlsctUint256[UINT256_SIZE];
typedef uint8_t BlsctCtxId[CTX_ID_SIZE];
typedef uint8_t BlsctViewTag[VIEW_TAG_SIZE];
typedef uint8_t BlsctOutPoint[OUT_POINT_SIZE];
typedef uint8_t BlsctSignature[SIGNATURE_SIZE];

typedef uint8_t BlsctRangeProof;

typedef struct {
  BLSCT_RESULT result;
  bool value;
} BlsctBoolRetVal;

typedef struct {
  BLSCT_RESULT result;
  void* value;  // = std::vector<BlsctAmountRecoveryResult>
} BlsctAmountsRetVal;

typedef struct {
  BLSCT_RESULT result;
  uint8_t* ser_ctx;
  size_t ser_ctx_size;

  size_t in_amount_err_index; // holds the first index of the tx_in whose amount exceeds the maximum
  size_t out_amount_err_index; // holds the first index of the tx_out whose amount exceeds the maximum
} BlsctCtxRetVal;

BlsctRetVal* succ(
    void* value,
    size_t value_size
);

BlsctBoolRetVal* succ_bool(
    bool value
);

BlsctBoolRetVal* err_bool(
    BLSCT_RESULT result
);

typedef struct {
  BlsctRangeProof* range_proof;
  size_t range_proof_size;
  BlsctPoint nonce;
} BlsctAmountRecoveryReq;

typedef struct {
  bool is_succ;
  char* msg;
  uint64_t amount;
} BlsctAmountRecoveryResult;

typedef struct {
    uint64_t amount;
    uint64_t gamma;
    BlsctScalar spending_key;
    BlsctTokenId token_id;
    BlsctOutPoint out_point;
    bool staked_commitment;
    bool rbf;
} BlsctTxIn;

typedef struct {
    BlsctSubAddr dest;
    uint64_t amount;
    char memo_c_str[MEMO_BUF_SIZE];
    BlsctTokenId token_id;
    TxOutputType output_type;
    uint64_t min_stake;
} BlsctTxOut;

// memory disposition
void free_obj(void* x);
void free_amounts_ret_val(BlsctAmountsRetVal* rv); // free attrs as well

// library initialization
void init();

// point
BlsctRetVal* gen_base_point();
BlsctRetVal* gen_random_point();
const char* serialize_point(const BlsctPoint* blsct_point);
BlsctRetVal* deserialize_point(const char* hex);
int is_point_equal(const BlsctPoint* a, const BlsctPoint* b);
const char* point_to_str(const BlsctPoint* blsct_point);
BlsctPoint* point_from_scalar(const BlsctScalar* blsct_scalar);

// scalar
BlsctRetVal* gen_random_scalar();
BlsctRetVal* gen_scalar(const uint64_t n);
uint64_t scalar_to_uint64(const BlsctScalar* blsct_scalar);
const char* serialize_scalar(const BlsctScalar* blsct_scalar);
BlsctRetVal* deserialize_scalar(const char* hex);
BlsctRetVal* deserialize_hex(const char* hex);
int is_scalar_equal(const BlsctScalar* a, const BlsctScalar* b);
const char* scalar_to_str(const BlsctScalar* blsct_scalar);

// public key
BlsctRetVal* gen_random_public_key();
BlsctPoint* get_public_key_point(const BlsctPubKey* blsct_pub_key);
BlsctPubKey* point_to_public_key(const BlsctPoint* blsct_point);

// address
BlsctRetVal* decode_address(
  const char* blsct_enc_addr
);

BlsctRetVal* encode_address(
  const void* void_blsct_dpk,
  const enum AddressEncoding encoding
);

// double public key
BlsctRetVal* gen_double_pub_key(
    const BlsctPubKey* blsct_pk1,
    const BlsctPubKey* blsct_pk2
);

const char* serialize_dpk(const BlsctDoublePubKey* blsct_dpk);
BlsctRetVal* deserialize_dpk(const char* hex);

// token id
BlsctRetVal* gen_token_id_with_subid(
    const uint64_t token,
    const uint64_t subid
);

BlsctRetVal* gen_token_id(
    const uint64_t token
);

BlsctRetVal* gen_default_token_id();
uint64_t get_token_id_token(const BlsctTokenId* blsct_token_id);
uint64_t get_token_id_subid(const BlsctTokenId* blsct_token_id);
const char* serialize_token_id(const BlsctTokenId* blsct_token_id);
BlsctRetVal* deserialize_token_id(const char* hex);

// range proof
BlsctRetVal* build_range_proof(
    const void* vp_uint64_vec,
    const BlsctPoint* blsct_nonce,
    const char* blsct_msg,
    const BlsctTokenId* blsct_token_id
);

BlsctBoolRetVal* verify_range_proofs(
    const void* vp_range_proofs
);

const BlsctPoint* get_range_proof_A(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);
const BlsctPoint* get_range_proof_A_wip(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);
const BlsctPoint* get_range_proof_B(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);

const BlsctScalar* get_range_proof_r_prime(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);
const BlsctScalar* get_range_proof_s_prime(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);
const BlsctScalar* get_range_proof_delta_prime(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);
const BlsctScalar* get_range_proof_alpha_hat(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);
const BlsctScalar* get_range_proof_tau_x(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);

const char* serialize_range_proof(
    const BlsctRangeProof* blsct_range_proof,
    const size_t obj_size
);
BlsctRetVal* deserialize_range_proof(
    const char* hex,
    const size_t obj_size
);

// amount recovery request
BlsctAmountRecoveryReq* gen_amount_recovery_req(
    const void* vp_blsct_range_proof,
    const size_t range_proof_size,
    const void* vp_blsct_nonce
);

// amountry recovery and the result result

// returns a structure whose value field is
// a vector of the same size as the input vector
BlsctAmountsRetVal* recover_amount(
    void* vp_amt_recovery_req_vec
);

// out point
// txid is 32 bytes and represented as 64-char hex str
BlsctRetVal* gen_out_point(
    const char* ctx_id_c_str,
    const uint32_t n
);

const char* serialize_out_point(const BlsctOutPoint* blsct_out_point);
BlsctRetVal* deserialize_out_point(const char* hex);

// script
const char* serialize_script(const BlsctScript* blsct_script);
BlsctRetVal* deserialize_script(const char* hex);

// signature
const char* serialize_signature(const BlsctSignature* blsct_signature);
BlsctRetVal* deserialize_signature(const char* hex);

// tx in

// returns BlsctTxIn
BlsctRetVal* build_tx_in(
    const uint64_t amount,
    const uint64_t gamma,
    const BlsctScalar* spending_key,
    const BlsctTokenId* token_id,
    const BlsctOutPoint* out_point,
    const bool staked_commitment,
    const bool rbf
);

BlsctRetVal* dpk_to_sub_addr(
    const void* blsct_dpk
);
uint64_t get_tx_in_amount(const BlsctTxIn* tx_in);
uint64_t get_tx_in_gamma(const BlsctTxIn* tx_in);
const BlsctScalar* get_tx_in_spending_key(const BlsctTxIn* tx_in);
const BlsctTokenId* get_tx_in_token_id(const BlsctTxIn* tx_in);
const BlsctOutPoint* get_tx_in_out_point(const BlsctTxIn* tx_in);
bool get_tx_in_staked_commitment(const BlsctTxIn* tx_in);
bool get_tx_in_rbf(const BlsctTxIn* tx_in);

// ctx in
const BlsctScript* get_ctx_in_script_sig(const CTxIn* ctx_in);
uint32_t get_ctx_in_sequence(const CTxIn* ctx_in);
const BlsctScript* get_ctx_in_script_witness(const CTxIn* ctx_in);
const BlsctCtxId* get_ctx_in_prev_out_hash(const CTxIn* ctx_in);
uint32_t get_ctx_in_prev_out_n(const CTxIn* ctx_in);

// tx out

// returns BlsctTxOut
BlsctRetVal* build_tx_out(
    const BlsctSubAddr* blsct_dest,
    const uint64_t amount,
    const char* memo_c_str,
    const BlsctTokenId* blsct_token_id,
    const TxOutputType output_type,
    const uint64_t min_stake
);

const BlsctSubAddr* get_tx_out_destination(const BlsctTxOut* tx_out);
uint64_t get_tx_out_amount(const BlsctTxOut* tx_out);
const char* get_tx_out_memo(const BlsctTxOut* tx_out);
const BlsctTokenId* get_tx_out_token_id(const BlsctTxOut* tx_out);
TxOutputType get_tx_out_output_type(const BlsctTxOut* tx_out);
uint64_t get_tx_out_min_stake(const BlsctTxOut* tx_out);

// ctx out
uint64_t get_ctx_out_value(const CTxOut* ctx_out);
const BlsctScript* get_ctx_out_script_pub_key(const CTxOut* ctx_out);
const BlsctScript* get_ctx_out_script_pubkey(const CTxOut* ctx_out);
const BlsctTokenId* get_ctx_out_token_id(const CTxOut* ctx_out);
const BlsctRetVal* get_ctx_out_vector_predicate(const CTxOut* ctx_out);

// ctx out blsct data
const BlsctPoint* get_ctx_out_spending_key(const CTxOut* ctx_out);
const BlsctPoint* get_ctx_out_ephemeral_key(const CTxOut* ctx_out);
const BlsctPoint* get_ctx_out_blinding_key(const CTxOut* ctx_out);
const BlsctRetVal* get_ctx_out_range_proof(const CTxOut* ctx_out);
uint16_t get_ctx_out_view_tag(const CTxOut* ctx_out);

// tx

// takes BlsctTxIn and BlsctTxOut vectors and
// returns a serialized CMutableTransaction
BlsctCtxRetVal* build_ctx(
    const void* void_tx_ins,
    const void* void_tx_outs
);

const char* get_ctx_id(
    const uint8_t* ser_ctx,
    const size_t ser_ctx_size
);

size_t get_ctx_in_count(const std::vector<CTxIn>* ctx_ins);
size_t get_ctx_out_count(const std::vector<CTxOut>* ctx_outs);

size_t get_tx_outs_size(const std::vector<CTxOut>* tx_outs);

const BlsctRetVal* get_tx_out(const std::vector<CTxOut>* tx_outs, const size_t i);

// TxIn
const BlsctScript* get_tx_in_script_sig(const CTxIn* tx_in);

uint32_t get_tx_in_sequence(const CTxIn* tx_in);

const BlsctScript* get_tx_in_script_witness(const CTxIn* tx_in);

const BlsctTxId* get_tx_in_prev_out_hash(const CTxIn* tx_in);

// TxOut
uint64_t get_tx_out_value(const CTxOut* tx_out);

const BlsctScript* get_tx_out_script_pub_key(const CTxOut* tx_out);

const std::vector<CTxIn>* get_ctx_ins(
    const uint8_t* ser_ctx,
    const size_t ser_ctx_size
);

const std::vector<CTxOut>* get_ctx_outs(
    const uint8_t* ser_ctx,
    const size_t ser_ctx_size
);

const BlsctRetVal* get_ctx_in(
    const std::vector<CTxIn>* ctx_ins,
    const size_t i
);

const BlsctRetVal* get_ctx_out(
    const std::vector<CTxOut>* ctx_outs,
    const size_t i
);

size_t get_ctx_in_count_c(
    const uint8_t* ser_ctx,
    const size_t ser_ctx_size
);

size_t get_ctx_out_count_c(
    const uint8_t* ser_ctx,
    const size_t ser_ctx_size
);

const BlsctRetVal* get_ctx_in_c(
    const uint8_t* ser_ctx,
    const size_t ser_ctx_size,
    const size_t i
);

const BlsctRetVal* get_ctx_out_c(
    const uint8_t* ser_ctx,
    const size_t ser_ctx_size,
    const size_t i
);

const BlsctSignature* sign_message(
    const BlsctScalar* blsct_priv_key,
    const char* blsct_msg
);

bool verify_msg_sig(
    const BlsctPubKey* blsct_pub_key,
    const char* blsct_msg,
    const BlsctSignature* blsct_signature
);

BlsctPubKey* scalar_to_pub_key(
    const BlsctScalar* blsct_scalar
);

// key derivation functions

// seed (scalar)
//  +---> child key (scalar)
//         +--------> blinding key (scalar)
//         +--------> token key (scalar)
//         +--------> tx key (scalar)
//                     +----> view key (scalar)
//                     +----> spending key (scalar)

// from seed
BlsctScalar* from_seed_to_child_key(
    const BlsctScalar* blsct_seed
);

// from child_key
BlsctScalar* from_child_key_to_blinding_key(
    const BlsctScalar* blsct_child_key
);

BlsctScalar* from_child_key_to_token_key(
    const BlsctScalar* blsct_child_key
);

BlsctScalar* from_child_key_to_tx_key(
    const BlsctScalar* blsct_child_key
);

// from tx key
BlsctScalar* from_tx_key_to_view_key(
    const BlsctScalar* blsct_tx_key
);

BlsctScalar* from_tx_key_to_spending_key(
    const BlsctScalar* blsct_tx_key
);

// from multiple keys and other info
BlsctScalar* calc_priv_spending_key(
    const BlsctPubKey* blsct_blinding_pub_key,
    const BlsctScalar* blsct_view_key,
    const BlsctScalar* blsct_spending_key,
    const int64_t account,
    const uint64_t address
);

// blsct/wallet/helpers delegators
uint64_t calc_view_tag(
    const BlsctPubKey* blinding_pub_key,
    const BlsctScalar* view_key
);

// Key ID (=Hash ID)
BlsctKeyId* calc_key_id(
    const BlsctPubKey* blsct_blinding_pub_key,
    const BlsctPubKey* blsct_spending_pub_key,
    const BlsctScalar* blsct_view_key
);

const char* serialize_key_id(
    const BlsctKeyId* blsct_key_id
);

BlsctRetVal* deserialize_key_id(
    const char* hex
);

BlsctPoint* calc_nonce(
    const BlsctPubKey* blsct_blinding_pub_key,
    const BlsctScalar* view_key
);

// sub addr
BlsctSubAddr* derive_sub_address(
    const BlsctScalar* blsct_view_key,
    const BlsctPubKey* blsct_spending_pub_key,
    const BlsctSubAddrId* blsct_sub_addr_id
);

const char* serialize_sub_addr(const BlsctSignature* blsct_sub_addr);

BlsctRetVal* deserialize_sub_addr(const char* hex);

// SubAddrId
BlsctSubAddrId* gen_sub_addr_id(
    const int64_t account,
    const uint64_t address
);

const char* serialize_sub_addr_id(const BlsctSubAddrId* blsct_sub_addr_id);
BlsctRetVal* deserialize_sub_addr_id(const char* hex);

int64_t get_sub_addr_id_account(
    const BlsctSubAddrId* blsct_sub_addr_id
);

uint64_t get_sub_addr_id_address(
    const BlsctSubAddrId* blsct_sub_addr_id
);

bool is_valid_point(
    const BlsctPoint* blsct_point
);

BlsctDoublePubKey* gen_dpk_with_keys_and_sub_addr_id(
    const BlsctScalar* blsct_view_key,
    const BlsctPubKey* blsct_spending_pub_key,
    const int64_t account,
    const uint64_t address
);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // NAVCOIN_BLSCT_EXTERNAL_API_BLSCT_H

