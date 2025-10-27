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
#define KEY_ID_SIZE 20
#define POINT_SIZE 48
#define SCALAR_SIZE 32
#define TOKEN_ID_SIZE 40  // uint256 + uint64_t = 32 + 8 = 40
#define UINT256_SIZE 32
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

typedef uint8_t BlsctCTxId[CTX_ID_SIZE];
typedef uint8_t BlsctDoublePubKey[DOUBLE_PUBLIC_KEY_SIZE];
typedef uint8_t BlsctKeyId[KEY_ID_SIZE];  // serialization of CKeyID which is based on uint160
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

typedef uint8_t BlsctRangeProof;
typedef uint8_t BlsctCTx;

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
  void* ctx;

  size_t in_amount_err_index; // holds the first index of the tx_in whose amount exceeds the maximum
  size_t out_amount_err_index; // holds the first index of the tx_out whose amount exceeds the maximum
} BlsctCTxRetVal;

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

typedef struct BlsctCTxIns BlsctCTxIns;
typedef struct BlsctCTxOuts BlsctCTxOuts;

void free_obj(void* x);
void free_amounts_ret_val(BlsctAmountsRetVal* rv); // free attrs as well
void init();

const char* serialize_raw_obj(const uint8_t* ser_obj, const size_t ser_obj_size);
BlsctRetVal* deserialize_raw_obj(const char* hex);

// address
BlsctRetVal* decode_address(
  const char* blsct_enc_addr
);

BlsctRetVal* encode_address(
  const void* void_blsct_dpk,
  const enum AddressEncoding encoding
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

// ctx
void* create_tx_in_vec();
void add_to_tx_in_vec(void* vp_tx_in_vec, const BlsctTxIn* tx_in);
void delete_tx_in_vec(void* vp_tx_in_vec);

void* create_tx_out_vec();
void add_to_tx_out_vec(void* vp_tx_out_vec, const BlsctTxOut* tx_out);
void delete_tx_out_vec(void* vp_tx_out_vec);

// returns a serialized CMutableTransaction
BlsctCTxRetVal* build_ctx(
    const void* void_tx_ins,
    const void* void_tx_outs
);
// using void* insetead of const void* to avoid const_cast
const char* get_ctx_id(void* vp_ctx);
const BlsctCTxIns* get_ctx_ins(void* vp_ctx);
const BlsctCTxOuts* get_ctx_outs(void* vp_ctx);
const char* serialize_ctx(void* vp_ctx);
BlsctRetVal* deserialize_ctx(const char* hex);
void delete_ctx(void* vp_ctx);

// ctx id
const char* serialize_ctx_id(const BlsctCTxId* blsct_ctx_id);
BlsctRetVal* deserialize_ctx_id(const char* hex);

// ctx_ins
bool are_ctx_ins_equal(const void* vp_a, const void* vp_b);
size_t get_ctx_ins_size(const void* blsct_ctx_ins);
const void* get_ctx_in_at(const void* vp_ctx_ins, const size_t i);

// ctx in
bool are_ctx_in_equal(const void* vp_a, const void* vp_b);
const BlsctCTxId* get_ctx_in_prev_out_hash(const void* vp_ctx_in);
uint32_t get_ctx_in_prev_out_n(const void* vp_ctx_in);
const BlsctScript* get_ctx_in_script_sig(const void* vp_ctx_in);
uint32_t get_ctx_in_sequence(const void* vp_ctx_in);
const BlsctScript* get_ctx_in_script_witness(const void* vp_ctx_in);

// ctx_outs
bool are_ctx_outs_equal(const void* vp_a, const void* vp_b);
size_t get_ctx_outs_size(const void* vp_ctx_outs);
const void* get_ctx_out_at(const void* vp_ctx_outs, const size_t i);

// ctx out
bool are_ctx_out_equal(const void* vp_a, const void* vp_b);
uint64_t get_ctx_out_value(const void* vp_ctx_out);
const BlsctScript* get_ctx_out_script_pub_key(const void* vp_ctx_out);
const BlsctScript* get_ctx_out_script_pubkey(const void* vp_ctx_out);
const BlsctTokenId* get_ctx_out_token_id(const void* vp_ctx_out);
const BlsctRetVal* get_ctx_out_vector_predicate(const void* vp_ctx_out);

// ctx out blsct data
const BlsctPoint* get_ctx_out_spending_key(void* vp_ctx_out);
const BlsctPoint* get_ctx_out_ephemeral_key(void* vp_jctx_out);
const BlsctPoint* get_ctx_out_blinding_key(void* vp_ctx_out);
const BlsctRetVal* get_ctx_out_range_proof(void* vp_ctx_out);
uint16_t get_ctx_out_view_tag(void* vp_ctx_out);

// double public key
BlsctRetVal* gen_double_pub_key(
    const BlsctPubKey* blsct_pk1,
    const BlsctPubKey* blsct_pk2
);

BlsctDoublePubKey* gen_dpk_with_keys_acct_addr(
    const BlsctScalar* blsct_view_key,
    const BlsctPubKey* blsct_spending_pub_key,
    const int64_t account,
    const uint64_t address
);

BlsctRetVal* dpk_to_sub_addr(
    const BlsctDoublePubKey* blsct_dpk
);

const char* serialize_dpk(const BlsctDoublePubKey* blsct_dpk);
BlsctRetVal* deserialize_dpk(const char* hex);

// key id (=Hash ID)
BlsctKeyId* calc_key_id(
    const BlsctPubKey* blsct_blinding_pub_key,
    const BlsctPubKey* blsct_spending_pub_key,
    const BlsctScalar* blsct_view_key
);

const char* serialize_key_id(const BlsctKeyId* blsct_key_id);
BlsctRetVal* deserialize_key_id(const char* hex);

// out point
// txid is 32 bytes and represented as 64-char hex str
BlsctRetVal* gen_out_point(
    const char* ctx_id_c_str,
    const uint32_t n
);
const char* serialize_out_point(const BlsctOutPoint* blsct_out_point);
BlsctRetVal* deserialize_out_point(const char* hex);
uint32_t get_out_point_n(const BlsctOutPoint* blsct_out_point);

// point
BlsctRetVal* gen_base_point();
BlsctRetVal* gen_random_point();
const char* serialize_point(const BlsctPoint* blsct_point);
BlsctRetVal* deserialize_point(const char* hex);
int is_point_equal(const BlsctPoint* a, const BlsctPoint* b);
const char* point_to_str(const BlsctPoint* blsct_point);
BlsctPoint* point_from_scalar(const BlsctScalar* blsct_scalar);
bool is_valid_point(const BlsctPoint* blsct_point);

// public key
BlsctRetVal* gen_random_public_key();
BlsctPoint* get_public_key_point(const BlsctPubKey* blsct_pub_key);
BlsctPubKey* point_to_public_key(const BlsctPoint* blsct_point);
const char* serialize_public_key(const BlsctPoint* blsct_point);
BlsctRetVal* deserialize_public_key(const char* hex);

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

BlsctPoint* get_range_proof_A(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);
BlsctPoint* get_range_proof_A_wip(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);
BlsctPoint* get_range_proof_B(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);

BlsctScalar* get_range_proof_r_prime(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);
BlsctScalar* get_range_proof_s_prime(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);
BlsctScalar* get_range_proof_delta_prime(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);
BlsctScalar* get_range_proof_alpha_hat(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);
BlsctScalar* get_range_proof_tau_x(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size);

const char* serialize_range_proof(
    const BlsctRangeProof* blsct_range_proof,
    const size_t obj_size
);
BlsctRetVal* deserialize_range_proof(
    const char* hex,
    const size_t obj_size
);

// scalar
BlsctRetVal* gen_random_scalar();
BlsctRetVal* gen_scalar(const uint64_t n);
uint64_t scalar_to_uint64(const BlsctScalar* blsct_scalar);
const char* serialize_scalar(const BlsctScalar* blsct_scalar);
BlsctRetVal* deserialize_scalar(const char* hex);
BlsctRetVal* deserialize_hex(const char* hex);
int is_scalar_equal(const BlsctScalar* a, const BlsctScalar* b);
const char* scalar_to_str(const BlsctScalar* blsct_scalar);
BlsctPubKey* scalar_to_pub_key(const BlsctScalar* blsct_scalar);

// script
const char* serialize_script(const BlsctScript* blsct_script);
BlsctRetVal* deserialize_script(const char* hex);

// signature
const char* serialize_signature(const BlsctSignature* blsct_signature);
BlsctRetVal* deserialize_signature(const char* hex);

const BlsctSignature* sign_message(
    const BlsctScalar* blsct_priv_key,
    const char* blsct_msg
);

bool verify_msg_sig(
    const BlsctPubKey* blsct_pub_key,
    const char* blsct_msg,
    const BlsctSignature* blsct_signature
);

// sub addr
BlsctSubAddr* derive_sub_address(
    const BlsctScalar* blsct_view_key,
    const BlsctPubKey* blsct_spending_pub_key,
    const BlsctSubAddrId* blsct_sub_addr_id
);

const char* serialize_sub_addr(const BlsctSignature* blsct_sub_addr);

BlsctRetVal* deserialize_sub_addr(const char* hex);

// sub addr id
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

// token id
BlsctRetVal* gen_token_id_with_token_and_subid(
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

uint64_t get_tx_in_amount(const BlsctTxIn* tx_in);
uint64_t get_tx_in_gamma(const BlsctTxIn* tx_in);
const BlsctScalar* get_tx_in_spending_key(const BlsctTxIn* tx_in);
const BlsctTokenId* get_tx_in_token_id(const BlsctTxIn* tx_in);
const BlsctOutPoint* get_tx_in_out_point(const BlsctTxIn* tx_in);
bool get_tx_in_staked_commitment(const BlsctTxIn* tx_in);
bool get_tx_in_rbf(const BlsctTxIn* tx_in);

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

BlsctPoint* calc_nonce(
    const BlsctPubKey* blsct_blinding_pub_key,
    const BlsctScalar* view_key
);

// Misc helper functions and macros migrated from blist.i
#define HANDLE_MEM_ALLOC_FAILURE(name) \
if (name == nullptr) { \
  printf("ERROR: Memory allocation failed\n"); \
  return nullptr; \
}

#define RETURN_RET_VAL_IF_NULL(p, ret_val) \
if (p == nullptr) { \
  printf("ERROR: " #p " is null\n"); \
  return ret_val; \
}
#define RETURN_IF_NULL(p) \
if (p == nullptr) { \
  printf("ERROR: " #p " is null\n"); \
  return; \
}

uint8_t* hex_to_malloced_buf(const char* hex);
const char* buf_to_malloced_hex_c_str(const uint8_t* buf, size_t size);

// uint64 vector
void* create_uint64_vec();
void add_to_uint64_vec(void* vp_uint64_vec, const uint64_t n);
void delete_uint64_vec(const void* vp_vec);

// range_proof vector
void* create_range_proof_vec();
void add_to_range_proof_vec(
    void* vp_range_proofs,
    const BlsctRangeProof* blsct_range_proof,
    size_t blsct_range_proof_size
);
void delete_range_proof_vec(const void* vp_range_proofs);

// amount recovery request vector
void* create_amount_recovery_req_vec();

void add_to_amount_recovery_req_vec(
    void* vp_amt_recovery_req_vec,
    void* vp_amt_recovery_req
);

void delete_amount_recovery_req_vec(void* vp_amt_recovery_req_vec);

int16_t get_amount_recovery_result_size(
    void* vp_amt_recovery_res_vec
);

bool get_amount_recovery_result_is_succ(
    void* vp_amt_recovery_req_vec,
    size_t idx
);

uint64_t get_amount_recovery_result_amount(
    void* vp_amt_recovery_req_vec,
    size_t idx
);

const char* get_amount_recovery_result_msg(
    void* vp_amt_recovery_req_vec,
    size_t idx
);

} // extern "C"

#endif // NAVCOIN_BLSCT_EXTERNAL_API_BLSCT_H

