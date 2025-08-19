#include <blsct/bech32_mod.h>
#include <blsct/common.h>
#include <blsct/double_public_key.h>
#include <blsct/external_api/blsct.h>
#include <blsct/key_io.h>
#include <blsct/private_key.h>
#include <blsct/public_key.h>
#include <blsct/range_proof/bulletproofs_plus/amount_recovery_request.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof_logic.h>
#include <blsct/signature.h>
#include <blsct/wallet/address.h>
#include <blsct/wallet/helpers.h>
#include <blsct/wallet/txfactory_base.h>
#include <common/url.h>
#include <crypto/common.h>
#include <memory.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <util/transaction_identifier.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

static std::mutex g_init_mutex;
static bulletproofs_plus::RangeProofLogic<Mcl>* g_rpl;
static bool g_is_little_endian;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;
UrlDecodeFn* const URL_DECODE = nullptr;

static bool is_little_endian() {
    uint16_t n = 1;
    uint8_t* p = (uint8_t*) &n;
    return *p == 1;
}

void init()
{
    std::lock_guard<std::mutex> lock(g_init_mutex);

    Mcl::Init for_side_effect_only;

    if (!set_chain(Chain::MainNet)) {
        throw std::runtime_error("Chain has already been set");
    }
    g_is_little_endian = is_little_endian();
    g_rpl = new(std::nothrow) bulletproofs_plus::RangeProofLogic<Mcl>();
}

BlsctRetVal* succ(
    void* value,
    size_t value_size
) {
    MALLOC(BlsctRetVal, p);
    RETURN_IF_MEM_ALLOC_FAILED(p);

    p->result = BLSCT_SUCCESS;
    p->value = value;
    p->value_size = value_size;
    return p;
}

BlsctRetVal* err(
    BLSCT_RESULT result
) {
    MALLOC(BlsctRetVal, p);
    RETURN_IF_MEM_ALLOC_FAILED(p);

    p->result = result;
    p->value = nullptr;
    return p;
}

BlsctBoolRetVal* succ_bool(
    const bool value
) {
    MALLOC(BlsctBoolRetVal, p);
    RETURN_IF_MEM_ALLOC_FAILED(p);

    p->result = BLSCT_SUCCESS;
    p->value = value;
    return p;
}

BlsctBoolRetVal* err_bool(
    const BLSCT_RESULT result
) {
    MALLOC(BlsctBoolRetVal, p);
    RETURN_IF_MEM_ALLOC_FAILED(p);

    p->result = result;
    p->value = false;
    return p;
}

void free_obj(void* x) {
    if (x != nullptr) free(x);
}

void free_amounts_ret_val(BlsctAmountsRetVal* rv) {
    auto result_vec = static_cast<const std::vector<BlsctAmountRecoveryResult>*>(rv->value);

    for(auto res: *result_vec) {
        free(res.msg);
    }
    delete result_vec;
    free(rv);
}

BlsctRetVal* gen_base_point() {
    MALLOC(BlsctPoint, blsct_point);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_point);

    auto x = Point::GetBasePoint();
    SERIALIZE_AND_COPY(x, blsct_point);

    return succ(blsct_point, POINT_SIZE);
}

BlsctRetVal* gen_random_point() {
    MALLOC(BlsctPoint, blsct_point);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_point);

    auto x = Point::Rand();
    SERIALIZE_AND_COPY(x, blsct_point);

    return succ(blsct_point, POINT_SIZE);
}

BlsctRetVal* gen_random_scalar() {
    MALLOC(BlsctScalar, blsct_scalar);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_scalar);

    auto x = Scalar::Rand(true);
    SERIALIZE_AND_COPY(x, blsct_scalar);

    return succ(blsct_scalar, SCALAR_SIZE);
}

BlsctRetVal* gen_scalar(
    const uint64_t n
) {
    Scalar scalar(n);
    MALLOC(BlsctScalar, blsct_scalar);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_scalar);
    SERIALIZE_AND_COPY(scalar, blsct_scalar);

    return succ(blsct_scalar, SCALAR_SIZE);
}

uint64_t scalar_to_uint64(const BlsctScalar* blsct_scalar)
{
    Scalar scalar;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_scalar, SCALAR_SIZE, scalar);
    return scalar.GetUint64();
}

BlsctRetVal* gen_random_public_key() {
    auto vec = Point::Rand().GetVch();
    blsct::PublicKey pub_key(vec);

    MALLOC(BlsctPubKey, blsct_pub_key);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_pub_key);
    SERIALIZE_AND_COPY(pub_key, blsct_pub_key);

    return succ(blsct_pub_key, PUBLIC_KEY_SIZE);
}

BlsctPoint* get_public_key_point(const BlsctPubKey* blsct_pub_key) {
    blsct::PublicKey pub_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_pub_key, PUBLIC_KEY_SIZE, pub_key);
    auto point = pub_key.GetG1Point();

    MALLOC(BlsctPoint, blsct_point);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_point);
    SERIALIZE_AND_COPY(point, blsct_point);

    return blsct_point;
}

BlsctPubKey* point_to_public_key(const BlsctPoint* blsct_point) {
    Point point;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_point, POINT_SIZE, point);
    blsct::PublicKey pub_key(point);

    MALLOC(BlsctPubKey, blsct_pub_key);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_pub_key);
    SERIALIZE_AND_COPY(pub_key, blsct_pub_key);

    return blsct_pub_key;
}

const char* serialize_point(const BlsctPoint* blsct_point) {
    Point point;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_point, POINT_SIZE, point);
    auto ser_point = point.GetVch();
    auto hex = HexStr(ser_point);

    return StrToAllocCStr(hex);
}

BlsctRetVal* deserialize_point(const char* hex) {
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec)) {
        return err(BLSCT_FAILURE);
    }
    Point point;
    if (!point.SetVch(vec)) {
        return err(BLSCT_DESER_FAILED);
    }

    MALLOC(BlsctPoint, blsct_point);
    RETURN_ERR_IF_MEM_ALLOC_FAILED(blsct_point);
    SERIALIZE_AND_COPY(point, blsct_point);

    return succ(blsct_point, POINT_SIZE);
}

int is_point_equal(const BlsctPoint* blsct_a, const BlsctPoint* blsct_b) {
    if (blsct_a == nullptr || blsct_b == nullptr) {
        return 0;
    }
    Point a, b;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_a, POINT_SIZE, a);
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_b, POINT_SIZE, b);
    return a == b ? 1 : 0;
}

const char* point_to_str(const BlsctPoint* blsct_point) {
    Point point;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_point, POINT_SIZE, point);
    auto str = point.GetString();
    return StrToAllocCStr(str);
}

BlsctPoint* point_from_scalar(const BlsctScalar* blsct_scalar) {
    Scalar scalar;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_scalar, SCALAR_SIZE, scalar);

    Point g = Point::GetBasePoint();
    Point point = g * scalar;

    MALLOC(BlsctPoint, blsct_point);
    RETURN_ERR_IF_MEM_ALLOC_FAILED(blsct_point);
    SERIALIZE_AND_COPY(point, blsct_point);

    return blsct_point;
}

const char* serialize_scalar(const BlsctScalar* blsct_scalar) {
    Scalar scalar;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_scalar, SCALAR_SIZE, scalar);
    auto hex = scalar.GetString();
    return StrToAllocCStr(hex);
}

BlsctRetVal* deserialize_scalar(const char* hex) {
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec)) {
        return err(BLSCT_FAILURE);
    }
    Scalar scalar;
    scalar.SetVch(vec);

    MALLOC(BlsctScalar, blsct_scalar);
    RETURN_ERR_IF_MEM_ALLOC_FAILED(blsct_scalar);
    SERIALIZE_AND_COPY(scalar, blsct_scalar);

    return succ(blsct_scalar, SCALAR_SIZE);
}

int is_scalar_equal(const BlsctScalar* blsct_a, const BlsctScalar* blsct_b) {
    if (blsct_a == nullptr || blsct_b == nullptr) {
        return 0;
    }
    Scalar a, b;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_a, SCALAR_SIZE, a);
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_b, SCALAR_SIZE, b);
    return a == b ? 1 : 0;
}

const char* scalar_to_str(const BlsctScalar* blsct_scalar) {
    Scalar scalar;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_scalar, SCALAR_SIZE, scalar);
    auto str = scalar.GetString(10);
    return StrToAllocCStr(str);
}

BlsctRetVal* decode_address(
    const char* blsct_enc_addr
) {
    try {
        std::string enc_addr(blsct_enc_addr);
        auto& chain = get_chain();
        auto maybe_dpk = blsct::DecodeDoublePublicKey(chain, enc_addr);
        if (maybe_dpk) {
            auto dpk = maybe_dpk.value();
            if (dpk.IsValid()) {
                auto buf = dpk.GetVch();
                MALLOC(BlsctDoublePubKey, dec_addr);
                RETURN_ERR_IF_MEM_ALLOC_FAILED(dec_addr);
                std::memcpy(dec_addr, &buf[0], DOUBLE_PUBLIC_KEY_SIZE);

                return succ(dec_addr, DOUBLE_PUBLIC_KEY_SIZE);
            }
        }
    } catch(...) {}

    return err(BLSCT_EXCEPTION);
}

BlsctRetVal* encode_address(
    const void* void_blsct_dpk,
    const enum AddressEncoding encoding
) {
    if (encoding != Bech32 && encoding != Bech32M) {
        return err(BLSCT_UNKNOWN_ENCODING);
    }
    try {
        UNVOID(BlsctDoublePubKey, blsct_dpk);

        auto blsct_dpk_u8 = U8C(blsct_dpk);
        std::vector<uint8_t> dpk_vec(blsct_dpk_u8, blsct_dpk_u8 + sizeof(BlsctDoublePubKey));
        auto dpk = blsct::DoublePublicKey(dpk_vec);

        auto bech32_encoding = encoding == Bech32 ?
            bech32_mod::Encoding::BECH32 : bech32_mod::Encoding::BECH32M;
        auto& chain = get_chain();
        auto enc_dpk_str = EncodeDoublePublicKey(chain, bech32_encoding, dpk);
        size_t BUF_SIZE = enc_dpk_str.size() + 1;
        MALLOC_BYTES(char, enc_addr, BUF_SIZE);
        RETURN_ERR_IF_MEM_ALLOC_FAILED(enc_addr);
        std::memcpy(enc_addr, enc_dpk_str.c_str(), BUF_SIZE); // also copies null at the end

        return succ(enc_addr, BUF_SIZE);

    } catch(...) {}

    return err(BLSCT_EXCEPTION);
}

BlsctRetVal* gen_double_pub_key(
    const BlsctPubKey* blsct_pk1,
    const BlsctPubKey* blsct_pk2
) {
    auto blsct_pk1_u8 = U8C(blsct_pk1);
    auto blsct_pk2_u8 = U8C(blsct_pk2);

    blsct::PublicKey pk1, pk2;
    std::vector<uint8_t> blsct_pk1_vec {
        blsct_pk1_u8,
        blsct_pk1_u8 + blsct::PublicKey::SIZE
    };
    std::vector<uint8_t> blsct_pk2_vec {
        blsct_pk2_u8,
        blsct_pk2_u8 + blsct::PublicKey::SIZE
    };
    pk1.SetVch(blsct_pk1_vec);
    pk2.SetVch(blsct_pk2_vec);

    MALLOC(BlsctDoublePubKey, blsct_dpk);
    RETURN_ERR_IF_MEM_ALLOC_FAILED(blsct_dpk);
    blsct::DoublePublicKey dpk(pk1, pk2);
    SERIALIZE_AND_COPY(dpk, blsct_dpk);

    return succ(blsct_dpk, sizeof(BlsctDoublePubKey));
}

const char* serialize_dpk(const BlsctDoublePubKey* blsct_dpk) {
    return SerializeToHex(*blsct_dpk, DOUBLE_PUBLIC_KEY_SIZE);
}

BlsctRetVal* deserialize_dpk(const char* hex) {
    BlsctDoublePubKey* blsct_dpk = static_cast<BlsctDoublePubKey*>(
        DeserializeFromHex(hex, DOUBLE_PUBLIC_KEY_SIZE)
    );
    return succ(blsct_dpk, DOUBLE_PUBLIC_KEY_SIZE);
}

BlsctRetVal* gen_token_id_with_subid(
    const uint64_t token,
    const uint64_t subid
) {
    uint256 token_uint256;
    auto data = token_uint256.data();
    uint64_t n = token;
    for (size_t i=0; i<8; i++) {
        data[i] = n & 0xFF;
        n >>= 8; // Shift the value right by 8 bits to process the next byte
    }
    TokenId token_id(token_uint256, subid);
    MALLOC(BlsctTokenId, blsct_token_id);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_token_id);
    SERIALIZE_AND_COPY_WITH_STREAM(token_id, blsct_token_id);

    return succ(blsct_token_id, TOKEN_ID_SIZE);
}

BlsctRetVal* gen_token_id(
    const uint64_t token
) {
    return gen_token_id_with_subid(
        token,
        UINT64_MAX
    );
}

BlsctRetVal* gen_default_token_id() {
    TokenId token_id;
    MALLOC(BlsctTokenId, blsct_token_id);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_token_id);
    SERIALIZE_AND_COPY_WITH_STREAM(token_id, blsct_token_id);

    return succ(blsct_token_id, TOKEN_ID_SIZE);
}

uint64_t get_token_id_token(const BlsctTokenId* blsct_token_id) {
    TokenId token_id;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_token_id, TOKEN_ID_SIZE, token_id);
    return token_id.token.GetUint64(0);
}

uint64_t get_token_id_subid(const BlsctTokenId* blsct_token_id) {
    TokenId token_id;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_token_id, TOKEN_ID_SIZE, token_id);
    return token_id.subid;
}

const char* serialize_token_id(const BlsctTokenId* blsct_token_id) {
    // BlsctTokenId is a serialization of TokenId
    // so just need to convert it to hex
    std::vector<uint8_t> vec((*blsct_token_id), (*blsct_token_id) + TOKEN_ID_SIZE);
    auto hex_str = HexStr(vec);
    return StrToAllocCStr(hex_str);
}

BlsctRetVal* deserialize_token_id(const char* hex) {
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec)) {
        return err(BLSCT_FAILURE);
    }
    MALLOC(BlsctTokenId, blsct_token_id);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_token_id);
    std::memcpy(blsct_token_id, &vec[0], vec.size());

    return succ(blsct_token_id, TOKEN_ID_SIZE);
}

// range proof

BlsctRetVal* build_range_proof(
    const void* vp_uint64_vec,
    const BlsctPoint* blsct_nonce,
    const char* blsct_msg,
    const BlsctTokenId* blsct_token_id
) {
    try {
        auto uint64_vec = static_cast<const std::vector<uint64_t>*>(vp_uint64_vec);
        // uint64_t to Scalar
        Scalars vs;
        for (uint64_t v : *uint64_vec) {
            if (v > INT64_MAX) {
                return err(BLSCT_VALUE_OUTSIDE_THE_RANGE);
            }
            Mcl::Scalar x(static_cast<int64_t>(v));
            vs.Add(x);
        }

        // blsct_nonce to nonce
        Mcl::Point nonce = Mcl::Point::GetBasePoint();
        auto blsct_nonce_u8 = U8C(blsct_nonce);
        std::vector<uint8_t> ser_point(
            blsct_nonce_u8, blsct_nonce_u8 + POINT_SIZE
        );
        nonce.SetVch(ser_point);

        // blsct_message to message
        std::string msg(blsct_msg);
        std::vector<uint8_t> msg_vec(msg.begin(), msg.end());

        // blsct_token_id to token_id
        TokenId token_id;
        auto blsct_token_id_u8 = U8C(blsct_token_id);
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_token_id_u8, TOKEN_ID_SIZE, token_id);

        // range_proof to blsct_range_proof
        auto range_proof = g_rpl->Prove(
            vs,
            nonce,
            msg_vec,
            token_id
        );
        DataStream size_st{};
        range_proof.Serialize(size_st);
        size_t range_proof_size = size_st.size();

        MALLOC_BYTES(BlsctRangeProof, blsct_range_proof, range_proof_size);
        RETURN_ERR_IF_MEM_ALLOC_FAILED(blsct_range_proof);
        SERIALIZE_AND_COPY_WITH_STREAM(range_proof, blsct_range_proof);

        return succ(blsct_range_proof, range_proof_size);

    } catch(...) {}

    return err(BLSCT_EXCEPTION);
}

BlsctBoolRetVal* verify_range_proofs(
    const void* vp_range_proofs
) {
    try {
        auto range_proofs = static_cast<const std::vector<bulletproofs_plus::RangeProof<Mcl>>*>(vp_range_proofs);

        std::vector<bulletproofs_plus::RangeProofWithSeed<Mcl>> range_proof_w_seeds;

        for(const auto& rp: *range_proofs) {
            auto rp_w_seed = bulletproofs_plus::RangeProofWithSeed<Mcl>(rp);
            range_proof_w_seeds.push_back(rp_w_seed);
        }
        bool is_valid = g_rpl->Verify(range_proof_w_seeds);
        return succ_bool(is_valid);

    } catch(...) {}

    return err_bool(BLSCT_EXCEPTION);
}

#define DEFINE_RANGE_PROOF_POINT_GETTER(field) \
const BlsctPoint* get_range_proof_##field(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size) \
{ \
    bulletproofs_plus::RangeProof<Mcl> range_proof; \
    UNSERIALIZE_AND_COPY_WITH_STREAM(blsct_range_proof, range_proof_size, range_proof); \
    auto copy = static_cast<BlsctPoint*>(malloc(POINT_SIZE)); \
    auto org = range_proof.field.GetVch(); \
    std::memcpy(copy, &org[0], POINT_SIZE); \
    return copy; \
}

DEFINE_RANGE_PROOF_POINT_GETTER(A)
DEFINE_RANGE_PROOF_POINT_GETTER(A_wip)
DEFINE_RANGE_PROOF_POINT_GETTER(B)

#undef DEFINE_RANGE_PROOF_POINT_GETTER

#define DEFINE_RANGE_PROOF_SCALAR_GETTER(field) \
const BlsctScalar* get_range_proof_##field(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size) \
{ \
    bulletproofs_plus::RangeProof<Mcl> range_proof; \
    UNSERIALIZE_AND_COPY_WITH_STREAM(blsct_range_proof, range_proof_size, range_proof); \
    auto copy = static_cast<BlsctScalar*>(malloc(SCALAR_SIZE)); \
    auto org = range_proof.field.GetVch(); \
    std::memcpy(copy, &org[0], SCALAR_SIZE); \
    return copy; \
}

DEFINE_RANGE_PROOF_SCALAR_GETTER(r_prime)
DEFINE_RANGE_PROOF_SCALAR_GETTER(s_prime)
DEFINE_RANGE_PROOF_SCALAR_GETTER(delta_prime)
DEFINE_RANGE_PROOF_SCALAR_GETTER(alpha_hat)
DEFINE_RANGE_PROOF_SCALAR_GETTER(tau_x)

#undef DEFINE_RANGE_PROOF_SCALAR_GETTER

const char* serialize_range_proof(
    const BlsctRangeProof* blsct_range_proof,
    const size_t range_proof_size
) {
    return SerializeToHex(blsct_range_proof, range_proof_size);
}

BlsctRetVal* deserialize_range_proof(
    const char* hex,
    const size_t range_proof_size
) {
    BlsctRangeProof* blsct_range_proof =
        static_cast<BlsctRangeProof*>(DeserializeFromHex(hex, range_proof_size));
    return succ(blsct_range_proof, range_proof_size);
}

BlsctAmountRecoveryReq* gen_amount_recovery_req(
    const void* vp_blsct_range_proof,
    const size_t range_proof_size,
    const void* vp_blsct_nonce
) {
    auto req = new(std::nothrow) BlsctAmountRecoveryReq;
    RETURN_IF_MEM_ALLOC_FAILED(req);

    req->range_proof = const_cast<BlsctRangeProof*>(
        static_cast<const BlsctRangeProof*>(vp_blsct_range_proof)
    );

    BLSCT_COPY_BYTES(vp_blsct_range_proof, req->range_proof, range_proof_size);
    req->range_proof_size = range_proof_size;
    BLSCT_COPY(vp_blsct_nonce, req->nonce);
    return req;
}

BlsctAmountsRetVal* recover_amount(
    void* vp_amt_recovery_req_vec
) {
    MALLOC(BlsctAmountsRetVal, rv);
    RETURN_IF_MEM_ALLOC_FAILED(rv);
    try {
        auto amt_recovery_req_vec =
            static_cast<const std::vector<BlsctAmountRecoveryReq>*>(vp_amt_recovery_req_vec);

        // construct AmountRecoveryRequest vector
        std::vector<bulletproofs_plus::AmountRecoveryRequest<Mcl>> reqs;

        for (auto ar_req: *amt_recovery_req_vec) {
            bulletproofs_plus::RangeProof<Mcl> range_proof;
            UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(ar_req.range_proof, ar_req.range_proof_size, range_proof);

            Mcl::Point nonce;
            UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(ar_req.nonce, POINT_SIZE, nonce);

            auto req = bulletproofs_plus::AmountRecoveryRequest<Mcl>::of(
                range_proof,
                nonce
            );
            reqs.push_back(req);
        }

        // try recover amount for all requests
        // vector containing only the successful results is returned
        auto recovery_results = g_rpl->RecoverAmounts(reqs);

        // return error if it failed in the middle
        if (!recovery_results.is_completed) {
            rv->result = BLSCT_DID_NOT_RUN_TO_COMPLETION;
            return rv;
        }

        // the vector to return has the same size as the request vector
        auto result_vec = new(std::nothrow) std::vector<BlsctAmountRecoveryResult>;
        RETURN_ERR_IF_MEM_ALLOC_FAILED(result_vec);
        result_vec->resize(amt_recovery_req_vec->size());

        // mark all the results as failed
        for(auto result: *result_vec) {
            result.is_succ = false;
        }

        // write successful recovery results to the corresponding
        // index of the return vector
        for(size_t i=0; i<recovery_results.amounts.size(); ++i) {
            // get the successful recovery result
            auto succ_res = recovery_results.amounts[i];

            // get the entry of the return vector corresponding
            // to the successful result
            auto& result = result_vec->at(succ_res.id);

            // mark the result as success and set the amount
            result.is_succ = true;

            // write amount to the result
            result.amount = succ_res.amount;

            // write message to the result
            result.msg = (char*) malloc(succ_res.message.size() + 1);
            std::memcpy(
                result.msg,
                succ_res.message.c_str(),
                succ_res.message.size() + 1
            );

            // gamma is omitted since it's a scalar
        }

        rv->result = BLSCT_SUCCESS;
        rv->value = TO_VOID(result_vec);
        return rv;

    } catch(...) {}

    rv->result = BLSCT_EXCEPTION;
    return rv;
}

BlsctRetVal* gen_out_point(
    const char* ctx_id_c_str,
    const uint32_t out_index
) {
    MALLOC(BlsctOutPoint, blsct_out_point);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_out_point);

    std::string ctx_id_str(ctx_id_c_str, CTX_ID_STR_LEN);

    auto ctx_id = TxidFromString(ctx_id_str);
    COutPoint out_point { ctx_id, out_index };

    SERIALIZE_AND_COPY_WITH_STREAM(
        out_point,
        blsct_out_point
    );
    return succ(blsct_out_point, OUT_POINT_SIZE);
}

const char* serialize_out_point(const BlsctOutPoint* blsct_out_point) {
     return SerializeToHex(*blsct_out_point, OUT_POINT_SIZE);
}

BlsctRetVal* deserialize_out_point(const char* hex) {
    BlsctOutPoint* blsct_out_point =
        static_cast<BlsctOutPoint*>(DeserializeFromHex(hex, OUT_POINT_SIZE));
    return succ(blsct_out_point, OUT_POINT_SIZE);
}

// script
const char* serialize_script(const BlsctScript* blsct_script) {
     return SerializeToHex(*blsct_script, SCRIPT_SIZE);
}

BlsctRetVal* deserialize_script(const char* hex) {
    BlsctScript* blsct_script =
        static_cast<BlsctScript*>(DeserializeFromHex(hex, SCRIPT_SIZE));
    return succ(blsct_script, SCRIPT_SIZE);
}

const char* serialize_signature(const BlsctSignature* blsct_signature) {
    return SerializeToHex(*blsct_signature, SIGNATURE_SIZE);
}

BlsctRetVal* deserialize_signature(const char* hex) {
    BlsctSignature* blsct_signature =
        static_cast<BlsctSignature*>(DeserializeFromHex(hex, SIGNATURE_SIZE));
    return succ(blsct_signature, SIGNATURE_SIZE);
}

BlsctRetVal* dpk_to_sub_addr(
    const void* blsct_dpk
) {
    // unserialize double public key
    blsct::DoublePublicKey dpk;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
        blsct_dpk, DOUBLE_PUBLIC_KEY_SIZE, dpk
    );

    // create sub address from dpk
    blsct::SubAddress sub_addr(dpk);

    // allocate memory for serialized sub address
    MALLOC(BlsctSubAddr, blsct_sub_addr);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_sub_addr);

    // serialize sub address
    SERIALIZE_AND_COPY_WITH_STREAM(sub_addr, blsct_sub_addr);

    return succ(blsct_sub_addr, sizeof(blsct::SubAddress));
}

static blsct::PrivateKey blsct_scalar_to_priv_key(
    const BlsctScalar* blsct_scalar
) {
    // unserialize blsct_scalar to Scalar
    Scalar scalar;
    auto u8_blsct_scalar = U8C(blsct_scalar);
    std::vector<uint8_t> vec {u8_blsct_scalar, u8_blsct_scalar + SCALAR_SIZE};
    scalar.SetVch(vec);

    // build private key from the scalar
    blsct::PrivateKey priv_key(scalar);
    return priv_key;
}

// tx_in
BlsctRetVal* build_tx_in(
    const uint64_t amount,
    const uint64_t gamma,
    const BlsctScalar* spending_key,
    const BlsctTokenId* token_id,
    const BlsctOutPoint* out_point,
    const bool staked_commitment,
    const bool rbf
) {
    MALLOC(BlsctTxIn, tx_in);
    RETURN_IF_MEM_ALLOC_FAILED(tx_in);

    tx_in->amount = amount;
    tx_in->gamma = gamma;
    BLSCT_COPY(spending_key, tx_in->spending_key);
    BLSCT_COPY(token_id, tx_in->token_id);
    BLSCT_COPY(out_point, tx_in->out_point);
    tx_in->staked_commitment = staked_commitment;
    tx_in->rbf = rbf;

    return succ(tx_in, sizeof(BlsctTxIn));
}

uint64_t get_tx_in_amount(const BlsctTxIn* tx_in) {
    return tx_in->amount;
}

uint64_t get_tx_in_gamma(const BlsctTxIn* tx_in) {
    return tx_in->gamma;
}

const BlsctScalar* get_tx_in_spending_key(const BlsctTxIn* tx_in) {
    MALLOC(BlsctScalar, spending_key);
    RETURN_IF_MEM_ALLOC_FAILED(spending_key);
    BLSCT_COPY(tx_in->spending_key, *spending_key);
    return spending_key;
}

const BlsctTokenId* get_tx_in_token_id(const BlsctTxIn* tx_in) {
    MALLOC(BlsctTokenId, token_id);
    RETURN_IF_MEM_ALLOC_FAILED(token_id);
    BLSCT_COPY(tx_in->token_id, *token_id);
    return token_id;
}

const BlsctOutPoint* get_tx_in_out_point(const BlsctTxIn* tx_in) {
    MALLOC(BlsctOutPoint, out_point);
    RETURN_IF_MEM_ALLOC_FAILED(out_point);
    BLSCT_COPY(tx_in->out_point, *out_point);
    return out_point;
}

bool get_tx_in_staked_commitment(const BlsctTxIn* tx_in) {
    return tx_in->staked_commitment;
}

bool get_tx_in_rbf(const BlsctTxIn* tx_in) {
    return tx_in->rbf;
}

// ctx in (c++)
const BlsctScript* get_ctx_in_script_sig(const CTxIn* ctx_in) {
    auto copy = static_cast<BlsctScript*>(malloc(SCRIPT_SIZE));
    std::memcpy(copy, &ctx_in->scriptSig, SCRIPT_SIZE);
    return copy;
}

uint32_t get_ctx_in_sequence(const CTxIn* ctx_in) {
    return ctx_in->nSequence;
}

const BlsctScript* get_ctx_in_script_witness(const CTxIn* ctx_in) {
    auto copy = static_cast<BlsctScript*>(malloc(SCRIPT_SIZE));
    std::memcpy(copy, &ctx_in->scriptWitness, SCRIPT_SIZE);
    return copy;
}

const BlsctCtxId* get_ctx_in_prev_out_hash(const CTxIn* ctx_in) {
    auto copy = static_cast<BlsctCtxId*>(malloc(CTX_ID_SIZE));
    std::memcpy(copy, &ctx_in->prevout.hash, CTX_ID_SIZE);
    return copy;
}

uint32_t get_ctx_in_prev_out_n(const CTxIn* ctx_in) {
    return ctx_in->prevout.n;
}

// tx out
BlsctRetVal* build_tx_out(
    const BlsctSubAddr* blsct_dest,
    const uint64_t amount,
    const char* memo_c_str,
    const BlsctTokenId* blsct_token_id,
    const TxOutputType output_type,
    const uint64_t min_stake
) {
    MALLOC(BlsctTxOut, tx_out);
    RETURN_IF_MEM_ALLOC_FAILED(tx_out);

    BLSCT_COPY(blsct_dest, tx_out->dest);
    tx_out->amount = amount;

    // copy memo to tx_out
    size_t memo_c_str_len = std::strlen(memo_c_str);
    if (memo_c_str_len > MAX_MEMO_LEN) {
        return err(BLSCT_MEMO_TOO_LONG);
    }
    std::memcpy(tx_out->memo_c_str, memo_c_str, memo_c_str_len + 1);

    BLSCT_COPY(blsct_token_id, tx_out->token_id);
    tx_out->output_type = output_type;
    tx_out->min_stake = min_stake;

    return succ(tx_out, sizeof(BlsctTxOut));
}

const BlsctSubAddr* get_tx_out_destination(const BlsctTxOut* tx_out) {
    MALLOC(BlsctSubAddr, sub_addr);
    RETURN_IF_MEM_ALLOC_FAILED(sub_addr);
    BLSCT_COPY(tx_out->dest, *sub_addr);
    return sub_addr;
}

uint64_t get_tx_out_amount(const BlsctTxOut* tx_out) {
    return tx_out->amount;
}

const char* get_tx_out_memo(const BlsctTxOut* tx_out) {
    size_t memo_c_str_len = std::strlen(tx_out->memo_c_str);
    char* memo_c_str = (char*) malloc(memo_c_str_len + 1);
    RETURN_IF_MEM_ALLOC_FAILED(memo_c_str);
    std::memcpy(memo_c_str, tx_out->memo_c_str, memo_c_str_len + 1);
    return memo_c_str;
}

const BlsctTokenId* get_tx_out_token_id(const BlsctTxOut* tx_out) {
    MALLOC(BlsctTokenId, token_id);
    RETURN_IF_MEM_ALLOC_FAILED(token_id);
    BLSCT_COPY(tx_out->token_id, *token_id);
    return token_id;
}

TxOutputType get_tx_out_output_type(const BlsctTxOut* tx_out) {
    return tx_out->output_type;
}

uint64_t get_tx_out_min_stake(const BlsctTxOut* tx_out) {
    return tx_out->min_stake;
}

// ctx out (c++)
uint64_t get_ctx_out_value(const CTxOut* tx_out) {
    return tx_out->nValue;
}

const BlsctScript* get_ctx_out_script_pub_key(const CTxOut* ctx_out) {
    auto copy = static_cast<BlsctScript*>(malloc(SCRIPT_SIZE));
    std::memcpy(copy, &ctx_out->scriptPubKey, SCRIPT_SIZE);
    return copy;
}

const BlsctScript* get_ctx_out_script_pubkey(const CTxOut* ctx_out) {
    auto copy = static_cast<BlsctScript*>(malloc(SCRIPT_SIZE));
    std::memcpy(copy, &ctx_out->scriptPubKey, SCRIPT_SIZE);
    return copy;
}

const BlsctPoint* get_ctx_out_spending_key(const CTxOut* ctx_out) {
    auto copy = static_cast<BlsctPoint*>(malloc(POINT_SIZE));
    auto org = ctx_out->blsctData.spendingKey.GetVch();
    std::memcpy(copy, &org[0], POINT_SIZE);
    return copy;
}

const BlsctPoint* get_ctx_out_ephemeral_key(const CTxOut* ctx_out) {
    auto copy = static_cast<BlsctPoint*>(malloc(POINT_SIZE));
    auto org = ctx_out->blsctData.ephemeralKey.GetVch();
    std::memcpy(copy, &org[0], POINT_SIZE);
    return copy;
}

const BlsctPoint* get_ctx_out_blinding_key(const CTxOut* ctx_out) {
    auto copy = static_cast<BlsctPoint*>(malloc(POINT_SIZE));
    auto org = ctx_out->blsctData.blindingKey.GetVch();
    std::memcpy(copy, &org[0], POINT_SIZE);
    return copy;
}

const BlsctRetVal* get_ctx_out_range_proof(const CTxOut* ctx_out) {
    DataStream st{};
    ctx_out->blsctData.rangeProof.Serialize(st);
    auto copy = static_cast<BlsctRangeProof*>(malloc(st.size()));
    std::memcpy(copy, st.data(), st.size());
    return succ(copy, st.size());;
};

uint16_t get_ctx_out_view_tag(const CTxOut* ctx_out) {
    return ctx_out->blsctData.viewTag;
}

const BlsctTokenId* get_ctx_out_token_id(const CTxOut* ctx_out) {
    auto copy = static_cast<BlsctTokenId*>(malloc(TOKEN_ID_SIZE));
    std::memcpy(copy, &ctx_out->tokenId, TOKEN_ID_SIZE);
    return copy;
}

const BlsctRetVal* get_ctx_out_vector_predicate(const CTxOut* ctx_out) {
    auto& pred = ctx_out->predicate;
    MALLOC_BYTES(uint8_t, buf, pred.size());
    RETURN_IF_MEM_ALLOC_FAILED(buf)

    std::memcpy(buf, pred.data(), pred.size());
    return succ(buf, pred.size());
}

// tx
BlsctCtxRetVal* build_ctx(
    const void* void_tx_ins,
    const void* void_tx_outs
) {
    UNVOID(std::vector<BlsctTxIn>, tx_ins);
    UNVOID(std::vector<BlsctTxOut>, tx_outs);

    blsct::TxFactoryBase psbt;
    MALLOC(BlsctCtxRetVal, rv);
    RETURN_IF_MEM_ALLOC_FAILED(rv);

    for (size_t i=0; i<tx_ins->size(); ++i) {
        // unserialize tx_in fields and add to TxFactoryBase
        const BlsctTxIn& tx_in = tx_ins->at(i);

        // check if the amount is within the range
        // amount is uint64_t and not serialized
        if (tx_in.amount > std::numeric_limits<int64_t>::max()) {
            rv->result = BLSCT_IN_AMOUNT_ERROR;
            rv->in_amount_err_index = i;
            return rv;
        }

        // gamma is uint64_t and not serialized
        Scalar gamma(tx_in.gamma);

        // unserialize spending_key
        blsct::PrivateKey spending_key =
            blsct_scalar_to_priv_key(&tx_in.spending_key);

        // unserialize token_id
        TokenId token_id;
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
            tx_in.token_id, TOKEN_ID_SIZE, token_id
        );

        // unserialize out_point
        COutPoint out_point;
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
            tx_in.out_point, OUT_POINT_SIZE, out_point
        );

        // add all to TxFactoryBase
        psbt.AddInput(
            tx_in.amount,
            gamma,
            spending_key,
            token_id,
            out_point,
            tx_in.staked_commitment,
            tx_in.rbf
        );
    }

    for (size_t i=0; i<tx_outs->size(); ++i) {
        // unserialize tx_out fields and add to TxFactoryBase
        const BlsctTxOut& tx_out = tx_outs->at(i);

        // check if the amount is within the range
        // amount is uint64_t and not serialized
        if (tx_out.amount > std::numeric_limits<int64_t>::max()) {
            rv->result = BLSCT_OUT_AMOUNT_ERROR;
            rv->out_amount_err_index = i;
            return rv;
        }

        // unserialize destination
        blsct::DoublePublicKey dest;
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
            tx_out.dest, DOUBLE_PUBLIC_KEY_SIZE, dest
        );

        // create memo std::string from memo c_str
        std::string memo_str(tx_out.memo_c_str);

        // unserialize token_id
        TokenId token_id;
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
            tx_out.token_id, TOKEN_ID_SIZE, token_id
        );

        // create out_type from blsct::TxOutputType
        blsct::CreateTransactionType out_type;
        if (tx_out.output_type == TxOutputType::Normal) {
            out_type = blsct::CreateTransactionType::NORMAL;
        } else if (tx_out.output_type == TxOutputType::StakedCommitment) {
            out_type = blsct::CreateTransactionType::STAKED_COMMITMENT;
        } else {
            rv->result = BLSCT_BAD_OUT_TYPE;
            return rv;
        }

        // add all to TxFactoryBase
        psbt.AddOutput(
            dest,
            tx_out.amount,
            memo_str,
            token_id,
            out_type,
            tx_out.min_stake
        );
    }

    // build tx
    blsct::DoublePublicKey change_amt_dest;
    auto maybe_ctx = psbt.BuildTx(change_amt_dest);
    if (!maybe_ctx.has_value()) {
        rv->result = BLSCT_FAILURE;
        return rv;
    }
    auto& ctx = maybe_ctx.value();

    // serialize tx
    DataStream st{};
    TransactionSerParams params { .allow_witness = true };
    ParamsStream ps {params, st};
    ctx.Serialize(ps);

    // copy the buffer containing serializef tx to the result
    rv->result = BLSCT_SUCCESS;
    rv->ser_ctx_size = st.size();
    rv->ser_ctx = (uint8_t*) malloc(st.size());
    std::memcpy(rv->ser_ctx, st.data(), st.size());

    return rv;
}

inline void UnserializeCMutableTx(
    CMutableTransaction& ctx,
    const uint8_t* ser_ctx,
    const size_t ser_ctx_size
) {
    DataStream st{};
    TransactionSerParams params { .allow_witness = true };
    ParamsStream ps {params, st};

    for(size_t i=0; i<ser_ctx_size; ++i) {
        ps << ser_ctx[i];
    }
    ctx.Unserialize(ps);
}

const char* get_ctx_id(
    const uint8_t* ser_ctx,
    const size_t ser_ctx_size
) {
    CMutableTransaction ctx;
    UnserializeCMutableTx(ctx, ser_ctx, ser_ctx_size);
    Txid ctxid = ctx.GetHash();
    std::string ctxid_hex = ctxid.GetHex();

    return StrToAllocCStr(ctxid_hex);
}

size_t get_ctx_in_count(const std::vector<CTxIn>* ctx_ins) {
    return ctx_ins->size();
}

size_t get_ctx_out_count(const std::vector<CTxOut>* ctx_outs) {
    return ctx_outs->size();
}

const std::vector<CTxIn>* get_ctx_ins(
    const uint8_t* ser_ctx,
    const size_t ser_ctx_size
) {
    CMutableTransaction ctx;
    UnserializeCMutableTx(ctx, ser_ctx, ser_ctx_size);
    return new std::vector<CTxIn>(ctx.vin);
}

const std::vector<CTxOut>* get_ctx_outs(
    const uint8_t* ser_ctx,
    const size_t ser_ctx_size
) {
    CMutableTransaction ctx;
    UnserializeCMutableTx(ctx, ser_ctx, ser_ctx_size);
    return new std::vector<CTxOut>(ctx.vout);
}

const BlsctRetVal* get_ctx_in(const std::vector<CTxIn>* ctx_ins, const size_t i) {
    auto ctx_in = &ctx_ins->at(i);
    auto ctx_in_size = sizeof(*ctx_in);
    auto ctx_in_copy = static_cast<CTxIn*>(malloc(ctx_in_size));
    std::memcpy(ctx_in_copy, ctx_in, ctx_in_size);
    return succ(ctx_in_copy, ctx_in_size);
}

const BlsctRetVal* get_ctx_out(const std::vector<CTxOut>* ctx_outs, const size_t i) {
    auto ctx_out = &ctx_outs->at(i);
    auto ctx_out_size = sizeof(*ctx_out);
    auto ctx_out_copy = static_cast<CTxOut*>(malloc(ctx_out_size));
    std::memcpy(ctx_out_copy, ctx_out, ctx_out_size);
    return succ(ctx_out_copy, ctx_out_size);
}

size_t get_ctx_in_count_c(
    const uint8_t* ser_ctx,
    const size_t ser_ctx_size
) {
    CMutableTransaction ctx;
    UnserializeCMutableTx(ctx, ser_ctx, ser_ctx_size);
    return ctx.vin.size();
}

size_t get_ctx_out_count_c(
    const uint8_t* ser_ctx,
    const size_t ser_ctx_size
) {
    CMutableTransaction ctx;
    UnserializeCMutableTx(ctx, ser_ctx, ser_ctx_size);
    return ctx.vout.size();
}

const BlsctRetVal* get_ctx_in_c(
    const uint8_t* ser_ctx,
    const size_t ser_ctx_size,
    const size_t i
) {
    CMutableTransaction ctx;
    UnserializeCMutableTx(ctx, ser_ctx, ser_ctx_size);

    // return serialized CTxIn at index i
    auto ctx_in = ctx.vin.at(i);
    DataStream st{};
    ctx_in.Serialize(st);
    size_t ser_ctx_in_size = st.size();

    MALLOC_BYTES(CTxIn, ser_ctx_in, ser_ctx_in_size);
    std::memcpy(ser_ctx_in, st.data(), ser_ctx_in_size);

    return succ(ser_ctx_in, ser_ctx_in_size);
}

const BlsctRetVal* get_ctx_out_c(
    const uint8_t* ser_ctx,
    const size_t ser_ctx_size,
    const size_t i
) {
    CMutableTransaction ctx;
    UnserializeCMutableTx(ctx, ser_ctx, ser_ctx_size);

    // return serialized CTxOut at index i
    auto ctx_out = ctx.vout.at(i);
    DataStream st{};
    ctx_out.Serialize(st);
    size_t ser_ctx_out_size = st.size();

    MALLOC_BYTES(CTxOut, ser_ctx_out, ser_ctx_out_size);
    std::memcpy(ser_ctx_out, st.data(), ser_ctx_out_size);

    return succ(ser_ctx_out, ser_ctx_out_size);
}

// signature
const BlsctSignature* sign_message(
    const BlsctScalar* blsct_priv_key,
    const char* blsct_msg
) {
    Scalar scalar_priv_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
        blsct_priv_key, SCALAR_SIZE, scalar_priv_key
    );
    auto priv_key = blsct::PrivateKey(scalar_priv_key);

    std::string msg_str(blsct_msg);
    blsct::Message msg(msg_str.begin(), msg_str.end());
    blsct::Signature sig = priv_key.Sign(msg);

    BlsctSignature* blsct_sig = static_cast<BlsctSignature*>(
        malloc(SIGNATURE_SIZE)
    );
    SERIALIZE_AND_COPY(sig, blsct_sig);

    return blsct_sig;
}

bool verify_msg_sig(
    const BlsctPubKey *blsct_pub_key,
    const char* blsct_msg,
    const BlsctSignature* blsct_signature
) {
    blsct::PublicKey pub_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_pub_key, PUBLIC_KEY_SIZE, pub_key);

    std::string msg_str(blsct_msg);
    blsct::Message msg(msg_str.begin(), msg_str.end());

    blsct::Signature signature;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_signature, SIGNATURE_SIZE, signature);

    return pub_key.Verify(msg, signature);
}

BlsctPubKey* scalar_to_pub_key(
    const BlsctScalar* blsct_scalar
) {
    Scalar scalar;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
        blsct_scalar, SCALAR_SIZE, scalar
    );
    auto priv_key = blsct::PrivateKey(scalar);
    auto pub_key = priv_key.GetPublicKey();

    BlsctPubKey* blsct_pub_key = static_cast<BlsctPubKey*>(
        malloc(PUBLIC_KEY_SIZE)
    );
    SERIALIZE_AND_COPY(pub_key, blsct_pub_key);
    return blsct_pub_key;
}

BlsctScalar* from_seed_to_child_key(
    const BlsctScalar* blsct_seed
) {
    Scalar seed;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_seed, SCALAR_SIZE, seed);

    auto child_key = blsct::FromSeedToChildKey(seed);
    BlsctScalar* blsct_child_key = static_cast<BlsctScalar*>(
        malloc(SCALAR_SIZE)
    );
    SERIALIZE_AND_COPY(child_key, blsct_child_key);

    return blsct_child_key;
}

BlsctScalar* from_child_key_to_blinding_key(
    const BlsctScalar* blsct_child_key
) {
    Scalar child_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_child_key, SCALAR_SIZE, child_key);

    Scalar blinding_key = blsct::FromChildToBlindingKey(child_key);
    BlsctScalar* blsct_blinding_key = static_cast<BlsctScalar*>(
        malloc(SCALAR_SIZE)
    );
    SERIALIZE_AND_COPY(blinding_key, blsct_blinding_key);

    return blsct_blinding_key;
}

BlsctScalar* from_child_key_to_token_key(
    const BlsctScalar* blsct_child_key
) {
    Scalar child_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_child_key, SCALAR_SIZE, child_key);

    auto token_key = blsct::FromChildToTokenKey(child_key);
    BlsctScalar* blsct_token_key = static_cast<BlsctScalar*>(
        malloc(SCALAR_SIZE)
    );
    SERIALIZE_AND_COPY(token_key, blsct_token_key);

    return blsct_token_key;
}

BlsctScalar* from_child_key_to_tx_key(
    const BlsctScalar* blsct_child_key
) {
    Scalar child_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_child_key, SCALAR_SIZE, child_key);

    auto tx_key = blsct::FromChildToTransactionKey(child_key);
    BlsctScalar* blsct_tx_key = static_cast<BlsctScalar*>(
        malloc(SCALAR_SIZE)
    );
    SERIALIZE_AND_COPY(tx_key, blsct_tx_key);

    return blsct_tx_key;
}

BlsctScalar* from_tx_key_to_view_key(
    const BlsctScalar* blsct_tx_key
) {
    Scalar tx_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_tx_key, SCALAR_SIZE, tx_key);

    auto view_key = blsct::FromTransactionToViewKey(tx_key);
    BlsctScalar* blsct_view_key = static_cast<BlsctScalar*>(
        malloc(SCALAR_SIZE)
    );
    SERIALIZE_AND_COPY(view_key, blsct_view_key);

    return blsct_view_key;
}

BlsctScalar* from_tx_key_to_spending_key(
    const BlsctScalar* blsct_tx_key
) {
    Scalar tx_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_tx_key, SCALAR_SIZE, tx_key);

    auto spending_key = blsct::FromTransactionToSpendKey(tx_key);
    BlsctScalar* blsct_spending_key = static_cast<BlsctScalar*>(
        malloc(SCALAR_SIZE)
    );
    SERIALIZE_AND_COPY(spending_key, blsct_spending_key);

    return blsct_spending_key;
}

BlsctScalar* calc_priv_spending_key(
    const BlsctPubKey* blsct_blinding_pub_key,
    const BlsctScalar* blsct_view_key,
    const BlsctScalar* blsct_spending_key,
    const int64_t account,
    const uint64_t address
) {
    blsct::PublicKey blinding_pub_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_blinding_pub_key, PUBLIC_KEY_SIZE, blinding_pub_key);

    Scalar view_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_view_key, SCALAR_SIZE, view_key);

    Scalar spending_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_spending_key, SCALAR_SIZE, spending_key);

    auto priv_spending_key = blsct::CalculatePrivateSpendingKey(
        blinding_pub_key.GetG1Point(),
        view_key,
        spending_key,
        account,
        address
    );
    BlsctScalar* blsct_priv_spending_key = static_cast<BlsctScalar*>(
        malloc(SCALAR_SIZE)
    );
    SERIALIZE_AND_COPY(priv_spending_key, blsct_priv_spending_key);

    return blsct_priv_spending_key;
}

uint64_t calc_view_tag(
    const BlsctPubKey* blsct_blinding_pub_key,
    const BlsctScalar* blsct_view_key
) {
    blsct::PublicKey blinding_pub_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_blinding_pub_key, PUBLIC_KEY_SIZE, blinding_pub_key);

    Scalar view_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_view_key, SCALAR_SIZE, view_key);

    return blsct::CalculateViewTag(
        blinding_pub_key.GetG1Point(),
        view_key
    );
}

BlsctKeyId* calc_key_id(
    const BlsctPubKey* blsct_blinding_pub_key,
    const BlsctPubKey* blsct_spending_pub_key,
    const BlsctScalar* blsct_view_key
) {
    blsct::PublicKey blinding_pub_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_blinding_pub_key, PUBLIC_KEY_SIZE, blinding_pub_key);

    blsct::PublicKey spending_pub_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_spending_pub_key, PUBLIC_KEY_SIZE, spending_pub_key);

    Scalar view_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_view_key, SCALAR_SIZE, view_key);

    auto key_id = blsct::CalculateHashId(
        blinding_pub_key.GetG1Point(),
        spending_pub_key.GetG1Point(),
        view_key
    );
    BlsctKeyId* blsct_key_id = static_cast<BlsctKeyId*>(
        malloc(KEY_ID_SIZE)
    );
    SERIALIZE_AND_COPY_WITH_STREAM(key_id, blsct_key_id);

    return blsct_key_id;
}

const char* serialize_key_id(
    const BlsctKeyId* blsct_key_id
) {
    return SerializeToHex(*blsct_key_id, KEY_ID_SIZE);
}

BlsctRetVal* deserialize_key_id(const char* hex) {
    BlsctKeyId* blsct_key_id = static_cast<BlsctKeyId*>(
        DeserializeFromHex(hex, KEY_ID_SIZE)
    );
    return succ(blsct_key_id, KEY_ID_SIZE);
}

BlsctPoint* calc_nonce(
    const BlsctPubKey* blsct_blinding_pub_key,
    const BlsctScalar* blsct_view_key
) {
    blsct::PublicKey blinding_pub_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_blinding_pub_key, PUBLIC_KEY_SIZE, blinding_pub_key);

    Scalar view_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_view_key, SCALAR_SIZE, view_key);

    auto nonce = blsct::CalculateNonce(
        blinding_pub_key.GetG1Point(),
        view_key
    );
    BlsctPoint* blsct_nonce = static_cast<BlsctPoint*>(
        malloc(POINT_SIZE)
    );
    SERIALIZE_AND_COPY(nonce, blsct_nonce);

    return blsct_nonce;
}

BlsctSubAddr* derive_sub_address(
    const BlsctScalar* blsct_view_key,
    const BlsctPubKey* blsct_spending_pub_key,
    const BlsctSubAddrId* blsct_sub_addr_id
) {
    Scalar view_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_view_key, SCALAR_SIZE, view_key);

    blsct::PublicKey spending_pub_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_spending_pub_key, PUBLIC_KEY_SIZE, spending_pub_key);

    blsct::SubAddressIdentifier sub_addr_id;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_sub_addr_id, SUB_ADDR_ID_SIZE, sub_addr_id);

    auto sub_addr = blsct::DeriveSubAddress(view_key, spending_pub_key, sub_addr_id);
    BlsctSubAddr* blsct_sub_addr = static_cast<BlsctSubAddr*>(
        malloc(SUB_ADDR_SIZE)
    );
    SERIALIZE_AND_COPY_WITH_STREAM(sub_addr, blsct_sub_addr);

    return blsct_sub_addr;
}

const char* serialize_sub_addr(const BlsctSubAddr* blsct_sub_addr) {
    return SerializeToHex(*blsct_sub_addr, SUB_ADDR_SIZE);
}

BlsctRetVal* deserialize_sub_addr(const char* hex) {
    BlsctSubAddr* blsct_sub_addr =
        static_cast<BlsctSubAddr*>(DeserializeFromHex(hex, SUB_ADDR_SIZE));
    return succ(blsct_sub_addr, SUB_ADDR_SIZE);
}

BlsctSubAddrId* gen_sub_addr_id(
    const int64_t account,
    const uint64_t address
) {
    blsct::SubAddressIdentifier sub_addr_id;
    sub_addr_id.account = account;
    sub_addr_id.address = address;

    MALLOC(BlsctSubAddrId, blsct_sub_addr_id);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_sub_addr_id);
    SERIALIZE_AND_COPY_WITH_STREAM(sub_addr_id, blsct_sub_addr_id);

    return blsct_sub_addr_id;
}

const char* serialize_sub_addr_id(const BlsctSubAddrId* blsct_sub_addr_id) {
    return SerializeToHex(*blsct_sub_addr_id, SUB_ADDR_ID_SIZE);
}

BlsctRetVal* deserialize_sub_addr_id(const char* hex) {
    BlsctSubAddrId* blsct_sub_addr_id =
        static_cast<BlsctSubAddrId*>(DeserializeFromHex(hex, SUB_ADDR_ID_SIZE));
    return succ(blsct_sub_addr_id, SUB_ADDR_ID_SIZE);
}

int64_t get_sub_addr_id_account(
    const BlsctSubAddrId* blsct_sub_addr_id
) {
    blsct::SubAddressIdentifier sub_addr_id;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_sub_addr_id, SUB_ADDR_ID_SIZE, sub_addr_id);
    return sub_addr_id.account;
}

uint64_t get_sub_addr_id_address(
    const BlsctSubAddrId* blsct_sub_addr_id
) {
    blsct::SubAddressIdentifier sub_addr_id;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_sub_addr_id, SUB_ADDR_ID_SIZE, sub_addr_id);
    return sub_addr_id.address;
}

bool is_valid_point(
    const BlsctPoint* blsct_point
) {
    Point point;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_point, POINT_SIZE, point);

    return point.IsValid();
}

BlsctDoublePubKey* gen_dpk_with_keys_and_sub_addr_id(
    const BlsctScalar* blsct_view_key,
    const BlsctPubKey* blsct_spending_pub_key,
    const int64_t account,
    const uint64_t address
) {
    Scalar view_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_view_key, SCALAR_SIZE, view_key);

    blsct::PublicKey spending_pub_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_spending_pub_key, PUBLIC_KEY_SIZE, spending_pub_key);

    blsct::SubAddressIdentifier sub_addr_id { account, address };
    blsct::SubAddress sub_addr(view_key, spending_pub_key, sub_addr_id);

    auto dpk = std::get<blsct::DoublePublicKey>(sub_addr.GetDestination());
    BlsctDoublePubKey* blsct_dpk = static_cast<BlsctDoublePubKey*>(
        malloc(DOUBLE_PUBLIC_KEY_SIZE)
    );
    SERIALIZE_AND_COPY_WITH_STREAM(dpk, blsct_dpk);

    return blsct_dpk;
}

