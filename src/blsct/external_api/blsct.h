// Copyright (c) 2024 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVCOIN_BLSCT_EXTERNAL_API_BLSCT_H
#define NAVCOIN_BLSCT_EXTERNAL_API_BLSCT_H

#include <blsct/double_public_key.h>
#include <blsct/private_key.h>
#include <blsct/public_key.h>
#include <blsct/wallet/address.h>
#include <blsct/arith/mcl/mcl.h>
#include <blsct/arith/elements.h>
#include <blsct/range_proof/setup.h>
#include <cstdint>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* constants */
#define PUBLIC_KEY_SIZE 48
#define DOUBLE_PUBLIC_KEY_SIZE PUBLIC_KEY_SIZE * 2
#define SUBADDRESS_SIZE DOUBLE_PUBLIC_KEY_SIZE
#define SUBADDRESS_ID_SIZE 16
#define ENCODED_DPK_STR_SIZE 165
#define ENCODED_DPK_STR_BUF_SIZE ENCODED_DPK_STR_SIZE + 1 /* 1 for c-str null termination */
#define KEY_ID_SIZE 20
#define POINT_SIZE 48
#define SCALAR_SIZE 32
#define RANGE_PROOF_SIZE 1315  // needs to be at least 1315
#define PRIVATE_KEY_SIZE 32
#define TOKEN_ID_SIZE 40  // uint256 + uint64_t = 32 + 8 = 40
#define UINT256_SIZE 32
#define VIEW_TAG_SIZE 8
// #define UINT16_SIZE 2
// #define CTXOUT_BLSCT_DATA_SIZE \
//         POINT_SIZE * 3 + \
//         RANGE_PROOF_SIZE + \
//         UINT16_SIZE
// #define NORMAL_CSCRIPT_SIZE 1
// #define OP_SIZE 1
// #define STAKED_COMMITMENT_CSCRIPT_SIZE \
//         OP_SIZE * 3 + \
//         RANGE_PROOF_SIZE
// #define CTXOUT_SIZE CAMOUNT_SIZE + \
//         CSCRIPT_SIZE + \
//         CTXOUT_BLSCT_DATA_SIZE + \
//         TOKEN_ID_SIZE
// #define UNSIGNED_OUTPUT_SIZE SCALAR_SIZE * 3 + CTXOUT_SIZE
#define OUT_POINT_SIZE 36
#define SIGNATURE_SIZE 96
#define SCRIPT_SIZE 28
#define MAX_MEMO_LEN 100
#define MEMO_BUF_SIZE MAX_MEMO_LEN + 1

/* return codes */
#define BLSCT_RESULT uint8_t
#define BLSCT_SUCCESS 0
#define BLSCT_FAILURE 1
#define BLSCT_EXCEPTION 2
#define BLSCT_BAD_DPK_SIZE 10
#define BLSCT_UNKNOWN_ENCODING 11
#define BLSCT_VALUE_OUTSIDE_THE_RANGE 12
#define BLSCT_DID_NOT_RUN_TO_COMPLETION 13
#define BLSCT_IN_AMOUNT_ERROR 14
#define BLSCT_OUT_AMOUNT_ERROR 15
#define BLSCT_BAD_OUT_TYPE 16
#define BLSCT_MEMO_TOO_LONG 17

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

#define MALLOC(T, name) T* name = (T*) malloc(sizeof(T))
#define MALLOC_BYTES(T, name, n) T* name = (T*) malloc(n)

#define U8C(name) reinterpret_cast<const uint8_t*>(name)

#define VOID(name) reinterpret_cast<void*>(name)

#define UNVOID(T, name) const T* name = reinterpret_cast<const T*>(void_##name)


#ifdef __cplusplus
extern "C" {
#endif

enum Chain {
    MainNet,
    TestNet,
    SigNet,
    RegTest
};

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
typedef uint8_t BlsctPrivKey[PRIVATE_KEY_SIZE];
typedef uint8_t BlsctPubKey[PUBLIC_KEY_SIZE];
typedef uint8_t BlsctDoublePubKey[DOUBLE_PUBLIC_KEY_SIZE];
typedef char BlsctAddrStr[ENCODED_DPK_STR_BUF_SIZE];
typedef uint8_t BlsctRangeProof[RANGE_PROOF_SIZE];
typedef uint8_t BlsctScalar[SCALAR_SIZE];
typedef uint8_t BlsctSubAddr[SUBADDRESS_SIZE];
typedef uint8_t BlsctSubAddrId[SUBADDRESS_ID_SIZE];
typedef uint8_t BlsctTokenId[TOKEN_ID_SIZE];
typedef uint8_t BlsctUint256[UINT256_SIZE];
typedef uint8_t BlsctViewTag[VIEW_TAG_SIZE];
typedef uint8_t BlsctOutPoint[OUT_POINT_SIZE];
typedef uint8_t BlsctSignature[SIGNATURE_SIZE];

typedef struct {
    uint8_t script[SCRIPT_SIZE];
    size_t size;
} BlsctScript;

typedef struct {
    BlsctPoint A;
    BlsctPoint S;
    BlsctPoint T1;
    BlsctPoint T2;
    BlsctScalar mu;
    BlsctScalar tau_x;

    BlsctScalar a;
    BlsctScalar b;
    BlsctScalar t_hat;
} BlsctRangeProofDe;

typedef struct {
    BlsctPoint spending_key;
    BlsctPoint ephemeral_key;
    BlsctPoint blinding_key;
    BlsctRangeProofDe range_proof;
    uint16_t view_tag;
} BlsctBlsctData;

typedef struct {
    int64_t value;
    BlsctScript script_pubkey;
    BlsctBlsctData* blsct_data;
    BlsctTokenId token_id;
} BlsctCTxOut;

typedef struct {
    BlsctUint256 hash; // Txid
    uint32_t n;
} BlsctCOutPoint;

typedef struct {
    uint8_t* buf;
    size_t size;
} BlsctVector;

typedef struct {
    BlsctVector* stack;
    size_t size;
} BlsctScriptWitness;

typedef struct {
    BlsctCOutPoint prev_out;
    BlsctScript script_sig;
    uint32_t sequence;
    BlsctScriptWitness script_witness;
} BlsctCTxIn;

typedef struct {
    int32_t version;
    uint32_t lock_time;
    BlsctSignature tx_sig;
    BlsctCTxIn* ins;
    size_t num_ins;
    BlsctCTxOut* outs;
    size_t num_outs;
} BlsctTransaction;

typedef struct {
    uint64_t token;
    uint64_t subid;
} BlsctTokenIdDe;

///// BEG new pointer-based API

typedef struct {
  BLSCT_RESULT result;
  void* value;
} BlsctRetVal;

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
  uint8_t* ser_tx;
  size_t ser_tx_size;

  size_t in_amount_err_index; // holds the first index of the tx_in whose amount exceeds the maximum
  size_t out_amount_err_index; // holds the first index of the tx_out whose amount exceeds the maximum
} BlsctTxRetVal;

BlsctRetVal* err(
    BLSCT_RESULT result
);

BlsctRetVal* succ(
    void* value
);

BlsctBoolRetVal* err_bool(
    BLSCT_RESULT result
);

BlsctBoolRetVal* succ_bool(
    bool value
);

typedef struct {
  BlsctRangeProof range_proof;
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
void dispose_ret_val(BlsctRetVal* rv);
void dispose_bool_ret_val(BlsctBoolRetVal* rv);
void dispose_amounts_ret_val(BlsctAmountsRetVal* rv);
void dispose_scalar(BlsctScalar* x);
void dispose_point(BlsctPoint* x);
void dispose_token_id(BlsctTokenId* x);
void dispose_public_key(BlsctPubKey* x);
void dispose_double_pub_key(BlsctDoublePubKey* x);

// library initialization
void init();
bool set_chain(enum Chain chain);

// point/scalar generation/disposition
BlsctPoint* gen_random_point();
BlsctScalar* gen_random_scalar();

BlsctScalar* gen_scalar(const uint64_t n);

// type convertion
uint64_t scalar_to_uint64(const BlsctScalar* blsct_scalar);

// public key generation
BlsctPubKey* gen_random_public_key();

BlsctRetVal* decode_address(
  const char* blsct_enc_addr
);

BlsctRetVal* encode_address(
  const void* void_blsct_dpk,
  const enum AddressEncoding encoding
);

BlsctRetVal* gen_double_pub_key(
    const BlsctPubKey* blsct_pk1,
    const BlsctPubKey* blsct_pk2
);

BlsctTokenId* gen_token_id_with_subid(
    const uint64_t token,
    const uint64_t subid
);

BlsctTokenId* gen_token_id(
    const uint64_t token
);

BlsctTokenId* gen_default_token_id();

BlsctRetVal* build_range_proof(
    const void* vp_uint64_vec,
    const BlsctPoint* blsct_nonce,
    const char* blsct_msg,
    const BlsctTokenId* blsct_token_id
);

BlsctBoolRetVal* verify_range_proofs(
    const void* vp_range_proofs
);

BlsctAmountRecoveryReq* gen_recover_amount_req(
    const void* vp_blsct_range_proof,
    const void* vp_blsct_nonce
);

// returns a structure whose value field is
// a vector of the same size as the input vector
BlsctAmountsRetVal* recover_amount(
    void* vp_amt_recovery_req_vec
);

// txid is 32 bytes and represented as 64-char hex str
BlsctOutPoint* gen_out_point(
    const char* tx_id_c_str,
    const uint32_t n
);

BlsctTxIn* build_tx_in(
    uint64_t amount,
    uint64_t gamma,
    BlsctScalar* spending_key,
    BlsctTokenId* token_id,
    BlsctOutPoint* out_point,
    bool rbf
);

BlsctRetVal* build_tx_out(
    BlsctSubAddr* blsct_dest,
    uint64_t amount,
    char* memo_c_str,
    BlsctTokenId* blsct_token_id,
    TxOutputType output_type,
    uint64_t min_stake
);

BlsctTxRetVal* build_tx(
    const void* void_tx_ins,
    const void* void_tx_outs
);

///// END new pointer-based API

/*
void blsct_uint64_to_blsct_uint256(
    const uint64_t n,
    BlsctUint256 uint256
);

// Point/Scalar generation functions

bool blsct_is_valid_point(BlsctPoint blsct_point);

bool blsct_from_point_to_blsct_point(
    const Point& point,
    BlsctPoint blsct_point
);

//
// [in] src_str: source byte string
// [in] src_str_size: the size of the source byte string
// [out] public_key: randomly generated Public key
//
void blsct_hash_byte_str_to_public_key(
    const char* src_str,
    const size_t src_str_size,
    BlsctPubKey blsct_pub_key
);

void blsct_priv_key_to_pub_key(
    const BlsctPrivKey blsct_priv_key,
    BlsctPubKey blsct_pub_key
);

void blsct_gen_dpk_with_keys_and_sub_addr_id(
    const BlsctPrivKey blsct_view_key,
    const BlsctPubKey blsct_spending_key,
    const int64_t account,
    const uint64_t address,
    BlsctDoublePubKey dpk
);

void blsct_dpk_to_sub_addr(
    const BlsctDoublePubKey blsct_dpk,
    BlsctSubAddr blsct_sub_addr
);

// returns false and set uint64 max to token if token > uint64_t max
//
bool blsct_decode_token_id(
    const BlsctTokenId blsct_token_id,
    BlsctTokenIdDe* blsct_token_id_de
);

// [out] blsct_priv_key
//
void blsct_gen_random_priv_key(
    BlsctScalar blsct_priv_key
);

// [in] byte string of size 32
// [out] blsct_priv_key
//
void blsct_gen_priv_key(
    const uint8_t priv_key[PRIVATE_KEY_SIZE],
    BlsctScalar blsct_priv_key
);

void blsct_sign_message(
    const BlsctPrivKey blsct_priv_key,
    const uint8_t* blsct_msg,
    const size_t blsct_msg_size,
    BlsctSignature blsct_signature
);

bool blsct_verify_msg_sig(
    const BlsctPubKey blsct_pub_key,
    const uint8_t* blsct_msg,
    const size_t blsct_msg_size,
    const BlsctSignature blsct_signature
);

void blsct_deserialize_tx(
    const uint8_t* ser_tx,
    const size_t ser_tx_size,
    BlsctTransaction** const blsct_tx
);

void blsct_dispose_tx(
    BlsctTransaction** const blsct_tx
);

// helper functions to build a transaction

// seed (scalar)
//  +---> child key (scalar)
//         +--------> blinding key (scalar)
//         +--------> token key (scalar)
//         +--------> tx key (scalar)
//                     +----> view key (scalar)
//                     +----> spending key (scalar)

// key derivation functions

// from seed
BLSCT_RESULT blsct_from_seed_to_child_key(
    const BlsctScalar blsct_seed,
    BlsctScalar blsct_child_key
);

// from child_key
BLSCT_RESULT blsct_from_child_key_to_tx_key(
    const BlsctScalar blsct_child_key,
    BlsctScalar blsct_to_tx_key
);

BLSCT_RESULT blsct_from_child_key_to_master_blinding_key(
    const BlsctScalar blsct_child_key,
    BlsctScalar blsct_master_blinding_key
);

BLSCT_RESULT blsct_from_child_key_to_token_key(
    const BlsctScalar blsct_child_key,
    BlsctScalar blsct_token_key
);

// from tx_key
BLSCT_RESULT blsct_from_tx_key_to_view_key(
    const BlsctScalar blsct_tx_key,
    BlsctPrivKey blsct_view_key
);

BLSCT_RESULT blsct_from_tx_key_to_spending_key(
    const BlsctScalar blsct_tx_key,
    BlsctScalar blsct_spending_key
);

BLSCT_RESULT blsct_calc_priv_spending_key(
    const BlsctPoint blsct_blinding_pub_key,
    const BlsctPoint blsct_spending_key,
    const BlsctScalar blsct_view_key,
    const int64_t& account,
    const uint64_t& address,
    BlsctScalar blsct_priv_spending_key
);

BLSCT_RESULT blsct_derive_sub_addr(
    const BlsctPrivKey blsct_view_key,
    const BlsctPubKey blsct_spend_key,
    const BlsctSubAddrId blsct_sub_addr_id,
    BlsctSubAddr blsct_sub_addr
);

BLSCT_RESULT blsct_calculate_nonce(
    const BlsctPoint blsct_blinding_pub_key,
    const BlsctScalar blsct_view_key,
    BlsctPoint blect_nonce
);

BLSCT_RESULT blsct_calculate_view_tag(
    const BlsctPoint blinding_pub_key,
    const BlsctScalar view_key,
    BlsctViewTag blsct_view_tag
);

BLSCT_RESULT blsct_calculate_hash_id(
    const BlsctPoint blsct_blinding_pub_key,
    const BlsctPoint blsct_spending_key,
    const BlsctScalar blsct_view_key,
    BlsctKeyId blsct_hash_id
);
*/

#ifdef __cplusplus
} // extern "C"
#endif

#endif // NAVCOIN_BLSCT_EXTERNAL_API_BLSCT_H

