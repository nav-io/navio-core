#include "blsct.h"
#include <crypto/common.h>
#include <blsct/bech32_mod.h>
#include <blsct/common.h>
#include <blsct/double_public_key.h>
#include <blsct/external_api/blsct.h>
#include <blsct/key_io.h>
#include <blsct/private_key.h>
#include <blsct/public_key.h>
#include <blsct/range_proof/bulletproofs/amount_recovery_request.h>
#include <blsct/range_proof/bulletproofs/range_proof.h>
#include <blsct/range_proof/bulletproofs/range_proof_logic.h>
#include <blsct/signature.h>
#include <blsct/wallet/address.h>
#include <blsct/wallet/helpers.h>
#include <blsct/wallet/txfactory.h>
#include <blsct/wallet/txfactory_global.h>
#include <common/args.h>
#include <common/url.h>
#include <memory.h>
#include <primitives/transaction.h>
#include <streams.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

static std::string g_chain;
static std::mutex g_init_mutex;
static std::mutex g_set_chain_mutex;
static bulletproofs::RangeProofLogic<Mcl>* g_rpl;
static bool g_is_little_endian;

const std::function<std::string(const char*)> G_TRANSLATION_FUN = nullptr;
UrlDecodeFn* const URL_DECODE = urlDecode;

extern "C" {

static bool is_little_endian() {
    uint16_t n = 1;
    uint8_t* p = (uint8_t*) &n;
    return *p == 1;
}

void init()
{
    std::lock_guard<std::mutex> lock(g_init_mutex);

    Mcl::Init for_side_effect_only;

    g_chain = blsct::bech32_hrp::Main;
    g_is_little_endian = is_little_endian();
    g_rpl = new(std::nothrow) bulletproofs::RangeProofLogic<Mcl>();
}

bool set_chain(enum Chain chain)
{
    std::lock_guard<std::mutex> lock(g_set_chain_mutex);
    if (!g_chain.empty()) {
        return false;
    }

    switch (chain) {
        case MainNet:
            g_chain = blsct::bech32_hrp::Main;
            break;

        case TestNet:
            g_chain = blsct::bech32_hrp::TestNet;
            break;

        case SigNet:
            g_chain = blsct::bech32_hrp::SigNet;
            break;

        case RegTest:
            g_chain = blsct::bech32_hrp::RegTest;
            break;
    }
    return true;
}

BlsctRetVal* succ(
    void* value
) {
    MALLOC(BlsctRetVal, p);
    RETURN_IF_MEM_ALLOC_FAILED(p);

    p->result = BLSCT_SUCCESS;
    p->value = value;
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

BlsctPoint* gen_random_point() {
    MALLOC(BlsctPoint, blsct_point);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_point);

    auto x = Point::Rand();
    SERIALIZE_AND_COPY(x, blsct_point);
    return blsct_point;
}

BlsctScalar* gen_random_scalar() {
    MALLOC(BlsctScalar, blsct_scalar);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_scalar);

    auto x = Scalar::Rand(true);
    SERIALIZE_AND_COPY(x, blsct_scalar);
    return blsct_scalar;
}

BlsctScalar* gen_scalar(
    const uint64_t n
) {
    Scalar scalar_n(n);
    MALLOC(BlsctScalar, blsct_scalar);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_scalar);
    SERIALIZE_AND_COPY(scalar_n, blsct_scalar);
    return blsct_scalar;
}

uint64_t scalar_to_uint64(const BlsctScalar* blsct_scalar)
{
    Scalar scalar;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_scalar, SCALAR_SIZE, scalar);
    return scalar.GetUint64();
}

BlsctPubKey* gen_random_public_key() {
    auto vec = Point::Rand().GetVch();
    blsct::PublicKey pub_key(vec);

    MALLOC(BlsctPubKey, blsct_pub_key);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_pub_key);
    SERIALIZE_AND_COPY(pub_key, blsct_pub_key);

    return blsct_pub_key;
}

BlsctRetVal* decode_address(
    const char* blsct_enc_addr
) {
    try {
        if (strlen(blsct_enc_addr) != ENCODED_DPK_STR_SIZE) {
            return err(BLSCT_BAD_DPK_SIZE);
        }
        std::string enc_addr(blsct_enc_addr);
        auto maybe_dpk = blsct::DecodeDoublePublicKey(g_chain, enc_addr);
        if (maybe_dpk) {
            auto dpk = maybe_dpk.value();
            if (dpk.IsValid()) {
                auto buf = dpk.GetVch();
                MALLOC(BlsctDoublePubKey, dec_addr);
                RETURN_ERR_IF_MEM_ALLOC_FAILED(dec_addr);
                std::memcpy(dec_addr, &buf[0], DOUBLE_PUBLIC_KEY_SIZE);

                return succ(dec_addr);
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
        auto enc_dpk_str = EncodeDoublePublicKey(g_chain, bech32_encoding, dpk);
        size_t BUF_SIZE = enc_dpk_str.size() + 1;
        MALLOC_BYTES(char, enc_addr, BUF_SIZE);
        RETURN_ERR_IF_MEM_ALLOC_FAILED(enc_addr);
        std::memcpy(enc_addr, enc_dpk_str.c_str(), BUF_SIZE);

        return succ(enc_addr);

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

    return succ(blsct_dpk);
}

BlsctTokenId* gen_token_id_with_subid(
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

    return blsct_token_id;
}

BlsctTokenId* gen_token_id(
    const uint64_t token
) {
    return gen_token_id_with_subid(
        token,
        UINT64_MAX
    );
}

BlsctTokenId* gen_default_token_id() {
    TokenId token_id;
    MALLOC(BlsctTokenId, blsct_token_id);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_token_id);
    SERIALIZE_AND_COPY_WITH_STREAM(token_id, blsct_token_id);

    return blsct_token_id;
}

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
        MALLOC(BlsctRangeProof, blsct_range_proof);
        RETURN_ERR_IF_MEM_ALLOC_FAILED(blsct_range_proof);
        SERIALIZE_AND_COPY_WITH_STREAM(range_proof, blsct_range_proof);
        return succ(blsct_range_proof);

    } catch(...) {}

    return err(BLSCT_EXCEPTION);
}

BlsctBoolRetVal* verify_range_proofs(
    const void* vp_range_proofs
) {
    try {
        auto range_proofs = static_cast<const std::vector<bulletproofs::RangeProof<Mcl>>*>(vp_range_proofs);

        std::vector<bulletproofs::RangeProofWithSeed<Mcl>> range_proof_w_seeds;

        for(auto rp: *range_proofs) {
            auto rp_w_seed = bulletproofs::RangeProofWithSeed<Mcl>(rp);
            range_proof_w_seeds.push_back(rp_w_seed);
        }
        bool is_valid = g_rpl->Verify(range_proof_w_seeds);
        return succ_bool(is_valid);

    } catch(...) {}

    return err_bool(BLSCT_EXCEPTION);
}

BlsctAmountRecoveryReq* gen_recover_amount_req(
    const void* vp_blsct_range_proof,
    const void* vp_blsct_nonce
) {
    auto req = new(std::nothrow) BlsctAmountRecoveryReq;
    RETURN_IF_MEM_ALLOC_FAILED(req);
    BLSCT_COPY(vp_blsct_range_proof, req->range_proof);
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
        std::vector<bulletproofs::AmountRecoveryRequest<Mcl>> reqs;

        for (auto ar_req: *amt_recovery_req_vec) {
            bulletproofs::RangeProof<Mcl> range_proof;
            UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(ar_req.range_proof, RANGE_PROOF_SIZE, range_proof);

            Mcl::Point nonce;
            UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(ar_req.nonce, POINT_SIZE, nonce);

            auto req = bulletproofs::AmountRecoveryRequest<Mcl>::of(
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
        rv->value = VOID(result_vec);
        return rv;

    } catch(...) {}

    rv->result = BLSCT_EXCEPTION;
    return rv;
}

BlsctOutPoint* gen_out_point(
    const char* tx_id_c_str,
    const uint32_t out_index
) {
    MALLOC(BlsctOutPoint, blsct_out_point);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_out_point);

    std::string tx_id_str(tx_id_c_str, TXID_STR_LEN);

    auto tx_id = TxidFromString(tx_id_str);
    COutPoint out_point { tx_id, out_index };

    SERIALIZE_AND_COPY_WITH_STREAM(
        out_point,
        blsct_out_point
    );
    return blsct_out_point;
}

BlsctTxIn* build_tx_in(
    const uint64_t amount,
    const uint64_t gamma,
    const BlsctScalar* spending_key,
    const BlsctTokenId* token_id,
    const BlsctOutPoint* out_point,
    const bool rbf
) {
    MALLOC(BlsctTxIn, tx_in);
    RETURN_IF_MEM_ALLOC_FAILED(tx_in);

    tx_in->amount = amount;
    tx_in->gamma = gamma;
    BLSCT_COPY(spending_key, tx_in->spending_key);
    BLSCT_COPY(token_id, tx_in->token_id);
    BLSCT_COPY(out_point, tx_in->out_point);
    tx_in->rbf = rbf;

    return tx_in;
}

BlsctSubAddr* dpk_to_sub_addr(
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

    return blsct_sub_addr;
}

BlsctRetVal* build_tx_out(
    const BlsctSubAddr* blsct_dest,
    const uint64_t amount,
    const char* in_memo_c_str,
    const BlsctTokenId* blsct_token_id,
    const TxOutputType output_type,
    const uint64_t min_stake
) {
    MALLOC(BlsctTxOut, tx_out);
    RETURN_IF_MEM_ALLOC_FAILED(tx_out);

    BLSCT_COPY(blsct_dest, tx_out->dest);
    tx_out->amount = amount;

    // copy memo to tx_out
    size_t in_memo_c_str_len = std::strlen(in_memo_c_str);
    if (in_memo_c_str_len > MAX_MEMO_LEN) {
        return err(BLSCT_MEMO_TOO_LONG);
    }
    std::memcpy(tx_out->memo_c_str, in_memo_c_str, in_memo_c_str_len + 1);

    BLSCT_COPY(blsct_token_id, tx_out->token_id);
    tx_out->output_type = output_type;
    tx_out->min_stake = min_stake;

    return succ(tx_out);
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

BlsctTxRetVal* build_tx(
    const void* void_tx_ins,
    const void* void_tx_outs
) {
    UNVOID(std::vector<BlsctTxIn>, tx_ins);
    UNVOID(std::vector<BlsctTxOut>, tx_outs);

    blsct::TxFactoryBase psbt;
    MALLOC(BlsctTxRetVal, rv);
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
            out_point
        );
    }

    // printf("----> 10\n");
    // for (size_t i=0; i<tx_outs->size(); ++i) {
    //     // unserialize tx_out fields and add to TxFactoryBase
    //     const BlsctTxOut& tx_out = tx_outs->at(i);
    //
    //     // check if the amount is within the range
    //     // amount is uint64_t and not serialized
    //     if (tx_out.amount > std::numeric_limits<int64_t>::max()) {
    //         rv->result = BLSCT_OUT_AMOUNT_ERROR;
    //         rv->out_amount_err_index = i;
    //         return rv;
    //     }
    //
    //     // unserialize destination
    //     blsct::DoublePublicKey dest;
    //     UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
    //         tx_out.dest, DOUBLE_PUBLIC_KEY_SIZE, dest
    //     );
    //
    //     // create memo std::string from memo c_str
    //     std::string memo_str(tx_out.memo_c_str);
    //
    //     // unserialize token_id
    //     TokenId token_id;
    //     UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
    //         tx_out.token_id, TOKEN_ID_SIZE, token_id
    //     );
    //
    //     // create out_type from blsct::TxOutputType
    //     blsct::CreateOutputType out_type;
    //     if (tx_out.output_type == TxOutputType::Normal) {
    //         out_type = blsct::CreateOutputType::NORMAL;
    //     } else if (tx_out.output_type == TxOutputType::StakedCommitment) {
    //         out_type = blsct::CreateOutputType::STAKED_COMMITMENT;
    //     } else {
    //         rv->result = BLSCT_BAD_OUT_TYPE;
    //         return rv;
    //     }
    //
    //     // add all to TxFactoryBase
    //     psbt.AddOutput(
    //         dest,
    //         tx_out.amount,
    //         memo_str,
    //         token_id,
    //         out_type,
    //         tx_out.min_stake
    //     );
    // }
    //
    // printf("----> 100\n");
    //
    // // build tx
    // blsct::DoublePublicKey change_amt_dest;
    // auto maybe_tx = psbt.BuildTx(change_amt_dest);
    // if (!maybe_tx.has_value()) {
    //     rv->result = BLSCT_FAILURE;
    //     return rv;
    // }
    // auto tx = maybe_tx.value();
    //
    // // serialize tx
    // DataStream st{};
    // TransactionSerParams params { .allow_witness = true };
    // ParamsStream ps {params, st};
    // tx.Serialize(ps);
    //
    // // copy serialize tx to the result
    // rv->result = BLSCT_SUCCESS;
    // rv->ser_tx_size = st.size();
    // rv->ser_tx = (uint8_t*) malloc(st.size());
    // std::memcpy(rv->ser_tx, st.data(), st.size());

    return rv;
}

/*
void blsct_gen_random_priv_key(
    BlsctScalar blsct_priv_key
) {
    Scalar priv_key = Scalar::Rand();
    SERIALIZE_AND_COPY(priv_key, blsct_priv_key);
}

void blsct_gen_priv_key(
    const uint8_t priv_key[PRIVATE_KEY_SIZE],
    BlsctScalar blsct_priv_key
) {
    std::vector<uint8_t> vec { priv_key, priv_key + PRIVATE_KEY_SIZE };
    Scalar tmp(vec);
    SERIALIZE_AND_COPY(tmp, blsct_priv_key);
}

void blsct_uint64_to_blsct_uint256(
    const uint64_t n,
    BlsctUint256 blsct_uint256
) {
    std::memset(blsct_uint256, 0, UINT256_SIZE);
    uint64_t tmp = n;

    // BlsctUint256 is little-endian
    for (size_t i=0; i<8; ++i) {
        blsct_uint256[g_is_little_endian ? i : 32 - i] =
            static_cast<uint8_t>(tmp & 0xFF);
        tmp >>= 8;
    }
}

bool blsct_is_valid_point(BlsctPoint blsct_point)
{
    std::vector<uint8_t> ser_point {blsct_point, blsct_point + POINT_SIZE};
    Point p;
    p.SetVch(ser_point);
    return p.IsValid();
}

void blsjct_hash_byte_str_to_public_key(
    const char* src_str,
    const size_t src_str_size,
    BlsctPubKey blsct_pub_key
) {
    std::vector<uint8_t> src_vec {src_str, src_str + src_str_size};
    auto point = Point::HashAndMap(src_vec);
    SERIALIZE_AND_COPY(point, blsct_pub_key);
}

void blsct_gen_dpk_with_keys_and_sub_addr_id(
    const BlsctPrivKey blsct_view_key,
    const BlsctPubKey blsct_spending_key,
    const int64_t account,
    const uint64_t address,
    BlsctDoublePubKey blsct_dpk
) {
    blsct::PrivateKey view_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_view_key, PRIVATE_KEY_SIZE, view_key);

    blsct::PublicKey spending_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_spending_key, PUBLIC_KEY_SIZE, spending_key);

    blsct::SubAddressIdentifier sub_addr_id { account, address };
    blsct::SubAddress sub_addr(view_key, spending_key, sub_addr_id);

    auto dpk = std::get<blsct::DoublePublicKey>(sub_addr.GetDestination());
    SERIALIZE_AND_COPY(dpk, blsct_dpk);
}

bool blsct_decode_token_id(
    const BlsctTokenId blsct_token_id,
    BlsctTokenIdDe* blsct_token_id_de
) {
    TokenId token_id;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
        blsct_token_id,
        TOKEN_ID_SIZE,
        token_id
    );
    auto& token = token_id.token;
    blsct_token_id_de->token = token.GetUint64(0);

    bool is_token_within_uint64_range = true;
    for (auto it = token.begin() + 8; it != token.end(); ++it) {
        if (*it != 0) {
            is_token_within_uint64_range = false;
            blsct_token_id_de->token = std::numeric_limits<uint64_t>::max();
        }
    }
    blsct_token_id_de->subid = token_id.subid;

    return is_token_within_uint64_range;
}

void blsct_priv_key_to_pub_key(
    const BlsctPrivKey blsct_priv_key,
    BlsctPubKey blsct_pub_key
) {
    blsct::PrivateKey priv_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
        blsct_priv_key, PRIVATE_KEY_SIZE, priv_key
    );
    auto pub_key = priv_key.GetPublicKey();
    SERIALIZE_AND_COPY(pub_key, blsct_pub_key);
}

static inline bool from_blsct_point_to_mcl_point(
    const BlsctPoint blsct_point,
    Point& point
) {
    std::vector<uint8_t> vec(
        blsct_point,
        blsct_point + Point::SERIALIZATION_SIZE
    );
    return point.SetVch(vec);
}

static inline void from_blsct_scalar_to_mcl_scalar(
    const BlsctScalar blsct_scalar,
    Scalar& scalar
) {
    std::vector<uint8_t> vec(
        blsct_scalar,
        blsct_scalar + Scalar::SERIALIZATION_SIZE
    );
    scalar.SetVch(vec);
}

BLSCT_RESULT blsct_derive_sub_addr(
    const BlsctPrivKey blsct_view_key,
    const BlsctPubKey blsct_spend_key,
    const BlsctSubAddrId blsct_sub_addr_id,
    BlsctSubAddr blsct_sub_addr
) {
    blsct::PrivateKey view_key;
    UNSERIALIZE_AND_COPY_WITH_STREAM(
        blsct_view_key,
        blsct::PrivateKey::SIZE,
        view_key
    );

    blsct::PublicKey spend_key;
    UNSERIALIZE_AND_COPY_WITH_STREAM(
        blsct_spend_key,
        blsct::PublicKey::SIZE,
        spend_key
    );

    blsct::SubAddressIdentifier sub_addr_id;
    UNSERIALIZE_AND_COPY_WITH_STREAM(
        blsct_sub_addr_id,
        blsct::SubAddressIdentifier::SIZE,
        sub_addr_id
    );

    auto sub_addr = blsct::DeriveSubAddress(view_key, spend_key, sub_addr_id);
    SERIALIZE_AND_COPY_WITH_STREAM(
        sub_addr,
        blsct_sub_addr
    );

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_calculate_nonce(
    const BlsctPoint blsct_blinding_pub_key,
    const BlsctScalar blsct_view_key,
    BlsctPoint blsct_nonce
) {
    TRY_DEFINE_MCL_POINT_FROM(blsct_blinding_pub_key, blinding_pub_key);
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_view_key, view_key);

    auto nonce = blsct::CalculateNonce(blinding_pub_key, view_key);
    SERIALIZE_AND_COPY(nonce, blsct_nonce);

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_from_seed_to_child_key(
    const BlsctScalar blsct_seed,
    BlsctScalar blsct_child_key
) {
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_seed, seed);

    auto child_key = blsct::FromSeedToChildKey(seed);
    SERIALIZE_AND_COPY(child_key, blsct_child_key);

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_from_child_key_to_tx_key(
    const BlsctScalar blsct_child_key,
    BlsctScalar blsct_tx_key
) {
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_child_key, child_key);

    auto tx_key = blsct::FromChildToTransactionKey(child_key);
    SERIALIZE_AND_COPY(tx_key, blsct_tx_key);

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_from_child_key_to_master_blinding_key(
    const BlsctScalar blsct_child_key,
    BlsctScalar blsct_master_blinding_key
) {
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_child_key, child_key);

    Scalar master_blinding_key =
        blsct::FromChildToMasterBlindingKey(child_key);

    SERIALIZE_AND_COPY(master_blinding_key, blsct_master_blinding_key);

    return BLSCT_SUCCESS;
};

BLSCT_RESULT blsct_from_child_key_to_token_key(
    const BlsctScalar blsct_child_key,
    BlsctScalar blsct_token_key
) {
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_child_key, child_key);

    auto token_key = blsct::FromChildToTokenKey(child_key);
    SERIALIZE_AND_COPY(token_key, blsct_token_key);

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_from_tx_key_to_view_key(
    const BlsctScalar blsct_tx_key,
    BlsctPrivKey blsct_view_key
) {
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_tx_key, tx_key);

    auto scalar_view_key =
        blsct::FromTransactionToViewKey(tx_key);
    blsct::PrivateKey view_key(scalar_view_key);

    SERIALIZE_AND_COPY(scalar_view_key, blsct_view_key);

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_from_tx_key_to_spending_key(
    const BlsctScalar blsct_tx_key,
    BlsctScalar blsct_spending_key
) {
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_tx_key, tx_key);

    auto spending_key = blsct::FromTransactionToSpendingKey(tx_key);
    SERIALIZE_AND_COPY(spending_key, blsct_spending_key);

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_calculate_view_tag(
    const BlsctPoint blsct_blinding_pub_key,
    const BlsctScalar blsct_view_key,
    BlsctViewTag blsct_view_tag
) {
    TRY_DEFINE_MCL_POINT_FROM(blsct_blinding_pub_key, blinding_pub_key);
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_view_key, view_key);

    *blsct_view_tag = blsct::CalculateViewTag(blinding_pub_key, view_key);

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_calculate_hash_id(
    const BlsctPoint blsct_blinding_pub_key,
    const BlsctPoint blsct_spending_key,
    const BlsctScalar blsct_view_key,
    BlsctKeyId blsct_hash_id
) {
    TRY_DEFINE_MCL_POINT_FROM(blsct_blinding_pub_key, blinding_pub_key);
    TRY_DEFINE_MCL_POINT_FROM(blsct_spending_key, spending_key);
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_view_key, view_key);

    auto hash_id = blsct::CalculateHashId(blinding_pub_key, spending_key, view_key);
    SERIALIZE_AND_COPY_WITH_STREAM(hash_id, blsct_hash_id);

    return BLSCT_SUCCESS;
}

BLSCT_RESULT blsct_calc_priv_spending_key(
    const BlsctPoint blsct_blinding_pub_key,
    const BlsctPoint blsct_spending_key,
    const BlsctScalar blsct_view_key,
    const int64_t& account,
    const uint64_t& address,
    BlsctScalar blsct_priv_spending_key
) {
    TRY_DEFINE_MCL_POINT_FROM(blsct_blinding_pub_key, blinding_pub_key);
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_view_key, view_key);
    TRY_DEFINE_MCL_SCALAR_FROM(blsct_spending_key, spending_key);

    auto priv_spending_key = blsct::CalculatePrivateSpendingKey(
        blinding_pub_key,
        view_key,
        spending_key,
        account,
        address
    );
    SERIALIZE_AND_COPY(priv_spending_key, blsct_priv_spending_key);

    return BLSCT_SUCCESS;
}

void blsct_deserialize_tx(
    const uint8_t* ser_tx,
    const size_t ser_tx_size,
    BlsctTransaction** const blsct_tx
) {
    // deserialize CMutableTransaction
    CMutableTransaction tx;
    DataStream st{};
    TransactionSerParams params { .allow_witness = true };
    ParamsStream ps {params, st};

    for (size_t i=0; i<ser_tx_size; ++i) {
        ps << ser_tx[i];
    }
    tx.Unserialize(ps);

    // construct BlsctTransaction from CMutableTransaction
    *blsct_tx = new BlsctTransaction;

    (*blsct_tx)->version = tx.nVersion;
    (*blsct_tx)->lock_time = tx.nLockTime;

    // tx signature
    SERIALIZE_AND_COPY(tx.txSig, (*blsct_tx)->tx_sig);

    // CTxIn
    (*blsct_tx)->num_ins = tx.vin.size();
    (*blsct_tx)->ins = new BlsctCTxIn[tx.vin.size()];

    for (size_t i=0; i<tx.vin.size(); ++i) {
        auto& in = (*blsct_tx)->ins[i];
        auto& tx_in = tx.vin[i];

        in.sequence = tx_in.nSequence;

        // prev out
        in.prev_out.n = tx_in.prevout.n;
        std::memcpy(
            in.prev_out.hash,
            tx_in.prevout.hash.data(),
            UINT256_SIZE
        );

        // script_sig
        in.script_sig.size = tx_in.scriptSig.size();
        std::memcpy(
            in.script_sig.script,
            tx_in.scriptSig.data(),
            tx_in.scriptSig.size()
        );

        // script witness
        in.script_witness.size = tx_in.scriptWitness.stack.size();
        in.script_witness.stack = new BlsctVector[in.script_witness.size];

        for (size_t i=0; i<in.script_witness.size; ++i) {
            auto& dest = in.script_witness.stack[i];
            auto& src = tx_in.scriptWitness.stack[i];

            dest.size = src.size();
            dest.buf = new uint8_t[dest.size];
            std::memcpy(dest.buf, &src[0], dest.size);
        }
    }

    // CTxOut
    (*blsct_tx)->num_outs = tx.vout.size();
    (*blsct_tx)->outs = new BlsctCTxOut[tx.vout.size()];

    for (size_t i=0; i<tx.vout.size(); ++i) {
        auto& out = (*blsct_tx)->outs[i];
        auto& tx_out = tx.vout[i];

        // value
        out.value = tx_out.nValue;

        // script_pubkey
        out.script_pubkey.size = tx_out.scriptPubKey.size();
        std::memcpy(
            out.script_pubkey.script,
            tx_out.scriptPubKey.data(),
            tx_out.scriptPubKey.size()
        );

        // token_id
        SERIALIZE_AND_COPY_WITH_STREAM(tx_out.tokenId, out.token_id);

        // blsct_data
        if (!tx_out.IsBLSCT()) {
            out.blsct_data = nullptr;
            continue;
        }
        out.blsct_data = new BlsctBlsctData();
        auto& blsct_data = *out.blsct_data;

        blsct_data.view_tag = tx_out.blsctData.viewTag;

        SERIALIZE_AND_COPY(
            tx_out.blsctData.spendingKey,
            blsct_data.spending_key
        );
        SERIALIZE_AND_COPY(
            tx_out.blsctData.ephemeralKey,
            blsct_data.ephemeral_key
        );
        SERIALIZE_AND_COPY(
            tx_out.blsctData.blindingKey,
            blsct_data.blinding_key
        );

        // range_proof
        auto& tx_range_proof = tx_out.blsctData.rangeProof;
        auto& range_proof = blsct_data.range_proof;

        SERIALIZE_AND_COPY(tx_range_proof.A, range_proof.A);
        SERIALIZE_AND_COPY(tx_range_proof.S, range_proof.S);
        SERIALIZE_AND_COPY(tx_range_proof.T1, range_proof.T1);
        SERIALIZE_AND_COPY(tx_range_proof.T2, range_proof.T2);
        SERIALIZE_AND_COPY(tx_range_proof.mu, range_proof.mu);
        SERIALIZE_AND_COPY(tx_range_proof.tau_x, range_proof.tau_x);
        SERIALIZE_AND_COPY(tx_range_proof.a, range_proof.a);
        SERIALIZE_AND_COPY(tx_range_proof.b, range_proof.b);
        SERIALIZE_AND_COPY(tx_range_proof.t_hat, range_proof.t_hat);
    }
}

void blsct_dispose_tx(
    BlsctTransaction** const blsct_tx
) {
    auto& tx = *(*blsct_tx);

    if (tx.ins) {
        // dispose memory dynamically allocated to script_witness
        for (size_t i=0; i<tx.num_ins; ++i) {
            auto& in = tx.ins[i];

            for (size_t j=0; j<in.script_witness.size; ++j) {
                auto& vec = in.script_witness.stack[j];
                delete[] vec.buf;
                vec.buf = nullptr;
            }
            delete[] in.script_witness.stack;
            in.script_witness.stack = nullptr;
        }

        delete[] tx.ins;
        tx.ins = nullptr;
    }
    if (tx.outs) {
        for (size_t i=0; i<tx.num_outs; ++i) {
            auto& out = tx.outs[i];
            // dispose memory conditionally allocated to blsct_data
            if (out.blsct_data != nullptr) {
                delete out.blsct_data;
                out.blsct_data = nullptr;
            }
        }
        delete[] tx.outs;
        tx.outs = nullptr;
    }
    delete *blsct_tx;
    *blsct_tx = nullptr;
}

void blsct_sign_message(
    const BlsctPrivKey blsct_priv_key,
    const uint8_t* blsct_msg,
    const size_t blsct_msg_size,
    BlsctSignature blsct_signature
) {
    blsct::PrivateKey priv_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
        blsct_priv_key, PRIVATE_KEY_SIZE, priv_key
    );

    blsct::Message msg {blsct_msg, blsct_msg + blsct_msg_size};
    blsct::Signature sig = priv_key.Sign(msg);

    SERIALIZE_AND_COPY(sig, blsct_signature);
}

bool blsct_verify_msg_sig(
    const BlsctPubKey blsct_pub_key,
    const uint8_t* blsct_msg,
    const size_t blsct_msg_size,
    const BlsctSignature blsct_signature
) {
    blsct::PublicKey pub_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_pub_key, PUBLIC_KEY_SIZE, pub_key);

    blsct::Message msg {blsct_msg, blsct_msg + blsct_msg_size};

    blsct::Signature signature;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_signature, SIGNATURE_SIZE, signature);

    return pub_key.Verify(msg, signature);
}
*/

} // extern "C"

