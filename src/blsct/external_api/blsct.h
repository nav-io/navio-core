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
#include <primitives/transaction.h>
#include <tinyformat.h>
#include <cstdint>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

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
#define RANGE_PROOF_SIZE 1315  // needs to be at least 1315
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
#define TX_ID_SIZE UINT256_SIZE
#define TX_ID_STR_LEN TX_ID_SIZE * 2

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
#define BLSCT_MEM_ALLOC_FAILED 18

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
#define RETURN_IF_MEM_ALLOC_FAILED(name) \
if (name == nullptr) { \
    printf("Failed to allocate memory"); \
    return nullptr; \
}
#define RETURN_ERR_IF_MEM_ALLOC_FAILED(name) \
if (name == nullptr) err(BLSCT_MEM_ALLOC_FAILED);

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
typedef uint8_t BlsctPubKey[PUBLIC_KEY_SIZE];
typedef uint8_t BlsctDoublePubKey[DOUBLE_PUBLIC_KEY_SIZE];
typedef char BlsctAddrStr[ENCODED_DPK_STR_BUF_SIZE];
typedef uint8_t BlsctRangeProof[RANGE_PROOF_SIZE];
typedef uint8_t BlsctScalar[SCALAR_SIZE];
typedef uint8_t BlsctScript[SCRIPT_SIZE];
typedef uint8_t BlsctSubAddr[SUB_ADDR_SIZE];
typedef uint8_t BlsctSubAddrId[SUB_ADDR_ID_SIZE];
typedef uint8_t BlsctTokenId[TOKEN_ID_SIZE];
typedef uint8_t BlsctUint256[UINT256_SIZE];
typedef uint8_t BlsctTxId[TX_ID_SIZE];
typedef uint8_t BlsctViewTag[VIEW_TAG_SIZE];
typedef uint8_t BlsctOutPoint[OUT_POINT_SIZE];
typedef uint8_t BlsctSignature[SIGNATURE_SIZE];

/*
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
*/

///// BEG new pointer-based API

typedef struct {
  BLSCT_RESULT result;
  void* value;
  size_t value_size;
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

BlsctRetVal* succ(
    void* value,
    size_t value_size
);

BlsctRetVal* err(
    BLSCT_RESULT result
);

BlsctBoolRetVal* succ_bool(
    bool value
);

BlsctBoolRetVal* err_bool(
    BLSCT_RESULT result
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
void free_obj(void* x);
void free_amounts_ret_val(BlsctAmountsRetVal* rv); // free attrs as well

// library initialization
void init();
bool set_chain(enum Chain chain);

// point
BlsctRetVal* gen_random_point();
const char* point_to_hex(const BlsctPoint* blsct_point);

// scalar
BlsctRetVal* gen_random_scalar();
BlsctRetVal* gen_scalar(const uint64_t n);
uint64_t scalar_to_uint64(const BlsctScalar* blsct_scalar);
const char* scalar_to_hex(const BlsctScalar* blsct_scalar);

// public key generation
BlsctRetVal* gen_random_public_key();

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

// amount recovery
BlsctAmountRecoveryReq* gen_recover_amount_req(
    const void* vp_blsct_range_proof,
    const void* vp_blsct_nonce
);

// returns a structure whose value field is
// a vector of the same size as the input vector
BlsctAmountsRetVal* recover_amount(
    void* vp_amt_recovery_req_vec
);

// out point
// txid is 32 bytes and represented as 64-char hex str
BlsctRetVal* gen_out_point(
    const char* tx_id_c_str,
    const uint32_t n
);

BlsctRetVal* build_tx_in(
    const uint64_t amount,
    const uint64_t gamma,
    const BlsctScalar* spending_key,
    const BlsctTokenId* token_id,
    const BlsctOutPoint* out_point,
    const bool rbf
);

BlsctRetVal* dpk_to_sub_addr(
    const void* blsct_dpk
);

BlsctRetVal* build_tx_out(
    const BlsctSubAddr* blsct_dest,
    const uint64_t amount,
    const char* memo_c_str,
    const BlsctTokenId* blsct_token_id,
    const TxOutputType output_type,
    const uint64_t min_stake
);

BlsctTxRetVal* build_tx(
    const void* void_tx_ins,
    const void* void_tx_outs
);

// must free the returned object after use
CMutableTransaction* deserialize_tx(
    const uint8_t* ser_tx,
    const size_t ser_tx_size
);

const std::vector<CTxIn>* get_tx_ins(const CMutableTransaction* tx);

size_t get_tx_ins_size(const std::vector<CTxIn>* tx_ins);

const BlsctRetVal* get_tx_in(const std::vector<CTxIn>* tx_ins, const size_t i);

const std::vector<CTxOut>* get_tx_outs(const CMutableTransaction* tx);

size_t get_tx_outs_size(const std::vector<CTxOut>* tx_outs);

const BlsctRetVal* get_tx_out(const std::vector<CTxOut>* tx_outs, const size_t i);

// TxIn
const BlsctScript* get_tx_in_script_sig(const CTxIn* tx_in);

uint32_t get_tx_in_sequence(const CTxIn* tx_in);

const BlsctScript* get_tx_in_script_witness(const CTxIn* tx_in);

const BlsctTxId* get_tx_in_prev_out_hash(const CTxIn* tx_in);

uint32_t get_tx_in_prev_out_n(const CTxIn* tx_in);

// TxOut
uint64_t get_tx_out_value(const CTxOut* tx_out);

const BlsctScript* get_tx_out_script_pub_key(const CTxOut* tx_out);

const BlsctTokenId* get_tx_out_token_id(const CTxOut* tx_out);

const BlsctScript* get_tx_out_script_pubkey(const CTxOut* tx_out);

const BlsctPoint* get_tx_out_spending_key(const CTxOut* tx_out);

const BlsctPoint* get_tx_out_ephemeral_key(const CTxOut* tx_out);

const BlsctPoint* get_tx_out_blinding_key(const CTxOut* tx_out);

uint16_t get_tx_out_view_tag(const CTxOut* tx_out);

const BlsctPoint* get_tx_out_range_proof_A(const CTxOut* tx_out);
const BlsctPoint* get_tx_out_range_proof_S(const CTxOut* tx_out);
const BlsctPoint* get_tx_out_range_proof_T1(const CTxOut* tx_out);
const BlsctPoint* get_tx_out_range_proof_T2(const CTxOut* tx_out);

const BlsctScalar* get_tx_out_range_proof_mu(const CTxOut* tx_out);
const BlsctScalar* get_tx_out_range_proof_a(const CTxOut* tx_out);
const BlsctScalar* get_tx_out_range_proof_b(const CTxOut* tx_out);
const BlsctScalar* get_tx_out_range_proof_t_hat(const CTxOut* tx_out);

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

BlsctKeyId* calc_hash_id(
    const BlsctPubKey* blsct_blinding_pub_key,
    const BlsctPubKey* blsct_spending_pub_key,
    const BlsctScalar* blsct_view_key
);

const char* get_key_id_hex(
    const BlsctKeyId* blsct_key_id
);

BlsctPoint* calc_nonce(
    const BlsctPubKey* blsct_blinding_pub_key,
    const BlsctScalar* view_key
);

BlsctSubAddr* derive_sub_address(
    const BlsctScalar* blsct_view_key,
    const BlsctPubKey* blsct_spending_pub_key,
    const BlsctSubAddrId* blsct_sub_addr_id
);

BlsctSubAddrId* gen_sub_addr_id(
    const int64_t account,
    const uint64_t address
);

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

