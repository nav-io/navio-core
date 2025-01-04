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
#include <blsct/wallet/txfactory_base.h>
#include <common/url.h>
#include <crypto/common.h>
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

static std::mutex g_init_mutex;
static bulletproofs::RangeProofLogic<Mcl>* g_rpl;
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
    g_rpl = new(std::nothrow) bulletproofs::RangeProofLogic<Mcl>();
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

const char* point_to_hex(const BlsctPoint* blsct_point) {
    Point point;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_point, POINT_SIZE, point);
    auto hex = point.GetString();

    size_t BUF_SIZE = hex.size() + 1;
    MALLOC_BYTES(char, hex_buf, BUF_SIZE);
    RETURN_ERR_IF_MEM_ALLOC_FAILED(hex_buf);
    std::memcpy(hex_buf, hex.c_str(), BUF_SIZE); // also copies null at the end

    return hex_buf;
}

const char* scalar_to_hex(const BlsctScalar* blsct_scalar) {
    Scalar scalar;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_scalar, SCALAR_SIZE, scalar);
    auto hex = scalar.GetString();

    size_t BUF_SIZE = hex.size() + 1;
    MALLOC_BYTES(char, hex_buf, BUF_SIZE);
    RETURN_ERR_IF_MEM_ALLOC_FAILED(hex_buf);
    std::memcpy(hex_buf, hex.c_str(), BUF_SIZE); // also copies null at the end

    return hex_buf;
}

BlsctRetVal* decode_address(
    const char* blsct_enc_addr
) {
    try {
        if (strlen(blsct_enc_addr) != ENCODED_DPK_STR_SIZE) {
            return err(BLSCT_BAD_DPK_SIZE);
        }
        std::string enc_addr(blsct_enc_addr);
        auto chain = get_chain();
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
        auto chain = get_chain();
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
        return succ(blsct_range_proof, RANGE_PROOF_SIZE);

    } catch(...) {}

    return err(BLSCT_EXCEPTION);
}

BlsctBoolRetVal* verify_range_proofs(
    const void* vp_range_proofs
) {
    try {
        auto range_proofs = static_cast<const std::vector<bulletproofs::RangeProof<Mcl>>*>(vp_range_proofs);

        std::vector<bulletproofs::RangeProofWithSeed<Mcl>> range_proof_w_seeds;

        for(const auto& rp: *range_proofs) {
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
        rv->value = TO_VOID(result_vec);
        return rv;

    } catch(...) {}

    rv->result = BLSCT_EXCEPTION;
    return rv;
}

BlsctRetVal* gen_out_point(
    const char* tx_id_c_str,
    const uint32_t out_index
) {
    MALLOC(BlsctOutPoint, blsct_out_point);
    RETURN_IF_MEM_ALLOC_FAILED(blsct_out_point);

    std::string tx_id_str(tx_id_c_str, TX_ID_STR_LEN);

    auto tx_id = TxidFromString(tx_id_str);
    COutPoint out_point { tx_id, out_index };

    SERIALIZE_AND_COPY_WITH_STREAM(
        out_point,
        blsct_out_point
    );
    return succ(blsct_out_point, OUT_POINT_SIZE);
}

BlsctRetVal* build_tx_in(
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

    return succ(tx_in, sizeof(BlsctTxIn));
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

    return succ(tx_out, sizeof(BlsctTxOut));
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
    auto maybe_tx = psbt.BuildTx(change_amt_dest);
    if (!maybe_tx.has_value()) {
        rv->result = BLSCT_FAILURE;
        return rv;
    }
    auto tx = maybe_tx.value();

    // serialize tx
    DataStream st{};
    TransactionSerParams params { .allow_witness = true };
    ParamsStream ps {params, st};
    tx.Serialize(ps);

    // copy serialize tx to the result
    rv->result = BLSCT_SUCCESS;
    rv->ser_tx_size = st.size();
    rv->ser_tx = (uint8_t*) malloc(st.size());
    std::memcpy(rv->ser_tx, st.data(), st.size());

    return rv;
}

CMutableTransaction* deserialize_tx(
    const uint8_t* ser_tx,
    const size_t ser_tx_size
) {
    CMutableTransaction* tx = static_cast<CMutableTransaction*>(
        malloc(sizeof(CMutableTransaction))
    );
    CMutableTransaction empty_tx;
    std::memcpy(tx, &empty_tx, sizeof(CMutableTransaction));

    DataStream st{};
    TransactionSerParams params { .allow_witness = true };
    ParamsStream ps {params, st};

    for(size_t i=0; i<ser_tx_size; ++i) {
        ps << ser_tx[i];
    }
    tx->Unserialize(ps);

    return tx;
}

// tx in
const std::vector<CTxIn>* get_tx_ins(const CMutableTransaction* tx) {
    return &tx->vin;
}

size_t get_tx_ins_size(const std::vector<CTxIn>* tx_ins) {
    return tx_ins->size();
}

const BlsctRetVal* get_tx_in(const std::vector<CTxIn>* tx_ins, const size_t i) {
    auto tx_in = &tx_ins->at(i);
    auto tx_in_size = sizeof(*tx_in);
    auto tx_in_copy = static_cast<CTxIn*>(malloc(tx_in_size));
    std::memcpy(tx_in_copy, tx_in, tx_in_size);
    return succ(tx_in_copy, tx_in_size);
}

const BlsctScript* get_tx_in_script_sig(const CTxIn* tx_in) {
    auto copy = static_cast<BlsctScript*>(malloc(SCRIPT_SIZE));
    std::memcpy(copy, &tx_in->scriptSig, SCRIPT_SIZE);
    return copy;
}

uint32_t get_tx_in_sequence(const CTxIn* tx_in) {
    return tx_in->nSequence;
}

const BlsctScript* get_tx_in_script_witness(const CTxIn* tx_in) {
    auto copy = static_cast<BlsctScript*>(malloc(SCRIPT_SIZE));
    std::memcpy(copy, &tx_in->scriptWitness, SCRIPT_SIZE);
    return copy;
}

const BlsctTxId* get_tx_in_prev_out_hash(const CTxIn* tx_in) {
    auto copy = static_cast<BlsctTxId*>(malloc(TX_ID_SIZE));
    std::memcpy(copy, &tx_in->prevout.hash, TX_ID_SIZE);
    return copy;
}

uint32_t get_tx_in_prev_out_n(const CTxIn* tx_in) {
    return tx_in->prevout.n;
}

// tx out
const std::vector<CTxOut>* get_tx_outs(const CMutableTransaction* tx) {
    return &tx->vout;
}

size_t get_tx_outs_size(const std::vector<CTxOut>* tx_outs) {
    return tx_outs->size();
}

const BlsctRetVal* get_tx_out(const std::vector<CTxOut>* tx_outs, const size_t i) {
    auto tx_out = &tx_outs->at(i);
    auto tx_out_size = sizeof(*tx_out);
    auto tx_out_copy = static_cast<CTxOut*>(malloc(tx_out_size));
    std::memcpy(tx_out_copy, tx_out, tx_out_size);
    return succ(tx_out_copy, tx_out_size);
}

uint64_t get_tx_out_value(const CTxOut* tx_out) {
    return tx_out->nValue;
}

const BlsctScript* get_tx_out_script_pub_key(const CTxOut* tx_out) {
    auto copy = static_cast<BlsctScript*>(malloc(SCRIPT_SIZE));
    std::memcpy(copy, &tx_out->scriptPubKey, SCRIPT_SIZE);
    return copy;
}

const BlsctTokenId* get_tx_out_token_id(const CTxOut* tx_out) {
    auto copy = static_cast<BlsctTokenId*>(malloc(TOKEN_ID_SIZE));
    std::memcpy(copy, &tx_out->tokenId, TOKEN_ID_SIZE);
    return copy;
}

const BlsctScript* get_tx_out_script_pubkey(const CTxOut* tx_out) {
    auto copy = static_cast<BlsctScript*>(malloc(SCRIPT_SIZE));
    std::memcpy(copy, &tx_out->scriptPubKey, SCRIPT_SIZE);
    return copy;
}

const BlsctPoint* get_tx_out_spending_key(const CTxOut* tx_out) {
    auto copy = static_cast<BlsctPoint*>(malloc(POINT_SIZE));
    auto org = tx_out->blsctData.spendingKey.GetVch();
    std::memcpy(copy, &org[0], POINT_SIZE);
    return copy;
}

const BlsctPoint* get_tx_out_ephemeral_key(const CTxOut* tx_out) {
    auto copy = static_cast<BlsctPoint*>(malloc(POINT_SIZE));
    auto org = tx_out->blsctData.ephemeralKey.GetVch();
    std::memcpy(copy, &org[0], POINT_SIZE);
    return copy;
}

const BlsctPoint* get_tx_out_blinding_key(const CTxOut* tx_out) {
    auto copy = static_cast<BlsctPoint*>(malloc(POINT_SIZE));
    auto org = tx_out->blsctData.blindingKey.GetVch();
    std::memcpy(copy, &org[0], POINT_SIZE);
    return copy;
}

uint16_t get_tx_out_view_tag(const CTxOut* tx_out) {
    return tx_out->blsctData.viewTag;
}

//// range proof

const BlsctPoint* get_tx_out_range_proof_A(const CTxOut* tx_out) {
    auto copy = static_cast<BlsctPoint*>(malloc(POINT_SIZE));
    auto org = tx_out->blsctData.rangeProof.A.GetVch();
    std::memcpy(copy, &org[0], POINT_SIZE);
    return copy;
}

const BlsctPoint* get_tx_out_range_proof_A_wip(const CTxOut* tx_out)
{
    auto copy = static_cast<BlsctPoint*>(malloc(POINT_SIZE));
    auto org = tx_out->blsctData.rangeProof.A_wip.GetVch();
    std::memcpy(copy, &org[0], POINT_SIZE);
    return copy;
}

const BlsctPoint* get_tx_out_range_proof_B(const CTxOut* tx_out)
{
    auto copy = static_cast<BlsctPoint*>(malloc(POINT_SIZE));
    auto org = tx_out->blsctData.rangeProof.B.GetVch();
    std::memcpy(copy, &org[0], POINT_SIZE);
    return copy;
}

const BlsctScalar* get_tx_out_range_proof_r_prime(const CTxOut* tx_out)
{
    auto copy = static_cast<BlsctScalar*>(malloc(SCALAR_SIZE));
    auto org = tx_out->blsctData.rangeProof.r_prime.GetVch();
    std::memcpy(copy, &org[0], SCALAR_SIZE);
    return copy;
}

const BlsctScalar* get_tx_out_range_proof_s_prime(const CTxOut* tx_out)
{
    auto copy = static_cast<BlsctScalar*>(malloc(SCALAR_SIZE));
    auto org = tx_out->blsctData.rangeProof.s_prime.GetVch();
    std::memcpy(copy, &org[0], SCALAR_SIZE);
    return copy;
}

const BlsctScalar* get_tx_out_range_proof_delta_prime(const CTxOut* tx_out)
{
    auto copy = static_cast<BlsctScalar*>(malloc(SCALAR_SIZE));
    auto org = tx_out->blsctData.rangeProof.delta_prime.GetVch();
    std::memcpy(copy, &org[0], SCALAR_SIZE);
    return copy;
}

const BlsctScalar* get_tx_out_range_proof_alpha_hat(const CTxOut* tx_out)
{
    auto copy = static_cast<BlsctScalar*>(malloc(SCALAR_SIZE));
    auto org = tx_out->blsctData.rangeProof.alpha_hat.GetVch();
    std::memcpy(copy, &org[0], SCALAR_SIZE);
    return copy;
}

const BlsctScalar* get_tx_out_range_proof_tau_x(const CTxOut* tx_out)
{
    auto copy = static_cast<BlsctScalar*>(malloc(SCALAR_SIZE));
    auto org = tx_out->blsctData.rangeProof.tau_x.GetVch();
    std::memcpy(copy, &org[0], SCALAR_SIZE);
    return copy;
}

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

BlsctKeyId* calc_hash_id(
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

    auto hash_id = blsct::CalculateHashId(
        blinding_pub_key.GetG1Point(),
        spending_pub_key.GetG1Point(),
        view_key
    );
    BlsctKeyId* blsct_hash_id = static_cast<BlsctKeyId*>(
        malloc(KEY_ID_SIZE)
    );
    SERIALIZE_AND_COPY_WITH_STREAM(hash_id, blsct_hash_id);

    return blsct_hash_id;
}

const char* get_key_id_hex(
    const BlsctKeyId* blsct_key_id
) {
    CKeyID key_id;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_key_id, KEY_ID_SIZE, key_id);

    auto hex = key_id.GetHex();

    size_t BUF_SIZE = hex.size() + 1;
    MALLOC_BYTES(char, hex_buf, BUF_SIZE);
    RETURN_ERR_IF_MEM_ALLOC_FAILED(hex_buf);
    std::memcpy(hex_buf, hex.c_str(), BUF_SIZE); // also copies null at the end

    return hex_buf;
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

BlsctSubAddrId* gen_sub_addr_id(
    const int64_t account,
    const uint64_t address
) {
    blsct::SubAddressIdentifier sub_addr_id;
    sub_addr_id.account = account;
    sub_addr_id.address = address;

    BlsctSubAddrId* blsct_sub_addr_id = static_cast<BlsctSubAddrId*>(
        malloc(SUB_ADDR_ID_SIZE)
    );
    SERIALIZE_AND_COPY_WITH_STREAM(sub_addr_id, blsct_sub_addr_id);

    return blsct_sub_addr_id;
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

