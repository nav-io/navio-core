// NOTE: Scalar locals in this file are not zeroed after use. MclScalar has no
// destructor and is upstream code we cannot modify. A blsct::Scalar wrapper
// with memory_cleanse on destruction is tracked in:
// https://github.com/nav-io/navio-core/issues/206
#include <blsct/bech32_mod.h>
#include <blsct/chain.h>
#include <blsct/common.h>
#include <blsct/double_public_key.h>
#include <blsct/eip_2333/bls12_381_keygen.h>
#include <blsct/external_api/blsct.h>
#include <blsct/key_io.h>
#include <blsct/private_key.h>
#include <blsct/public_key.h>
#include <blsct/range_proof/bulletproofs_plus/amount_recovery_request.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof_logic.h>
#include <blsct/signature.h>
#include <blsct/tokens/info.h>
#include <blsct/tokens/predicate_parser.h>
#include <blsct/wallet/address.h>
#include <blsct/wallet/helpers.h>
#include <blsct/wallet/txfactory_base.h>
#include <blsct/wallet/unsigned_transaction.h>
#include <common/url.h>
#include <crypto/common.h>
#include <memory.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <util/rbf.h>
#include <util/transaction_identifier.h>

#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>

static inline void FillHexBuf(const uint8_t* data, size_t size, char* out)
{
    auto hex = HexStr(Span<const uint8_t>(data, size));
    std::memcpy(out, hex.c_str(), hex.size() + 1);
}

static inline size_t WriteHexBuf(const uint8_t* data, size_t size, char* buf, size_t buf_size)
{
    auto hex = HexStr(Span<const uint8_t>(data, size));
    if (buf != nullptr && buf_size > hex.size()) {
        std::memcpy(buf, hex.c_str(), hex.size() + 1);
    }
    return hex.size();
}

static inline size_t WriteStrBuf(const std::string& s, char* buf, size_t buf_size)
{
    if (buf != nullptr && buf_size > s.size()) {
        std::memcpy(buf, s.c_str(), s.size() + 1);
    }
    return s.size();
}

template <typename T>
static size_t SerializeObjToHexBuf(const T& obj, char* buf, size_t buf_size)
{
    DataStream st{};
    st << obj;
    return WriteHexBuf(reinterpret_cast<const uint8_t*>(st.data()), st.size(), buf, buf_size);
}

template <typename T>
static size_t SerializeObjToByteBuf(const T& obj, uint8_t* buf, size_t buf_size)
{
    DataStream st{};
    st << obj;
    if (buf != nullptr && buf_size >= st.size())
        std::memcpy(buf, st.data(), st.size());
    return st.size();
}

static size_t SerializeCtxToHexBuf(const CMutableTransaction& ctx, char* buf, size_t buf_size)
{
    DataStream st{};
    TransactionSerParams params{.allow_witness = true};
    ParamsStream ps{params, st};
    ctx.Serialize(ps);
    return WriteStrBuf(HexStr(MakeByteSpan(st)), buf, buf_size);
}

static std::shared_mutex g_rpl_mutex;
static bulletproofs_plus::RangeProofLogic<Mcl>* g_rpl;

void init()
{
    std::unique_lock<std::shared_mutex> lock(g_rpl_mutex);
    Mcl::Init for_side_effect_only;

    set_chain(blsct::bech32_hrp::Mainnet);
    g_rpl = new (std::nothrow) bulletproofs_plus::RangeProofLogic<Mcl>();
}

void uninit()
{
    std::unique_lock<std::shared_mutex> lock(g_rpl_mutex);
    delete g_rpl;
    g_rpl = nullptr;
}

enum BlsctChain get_blsct_chain()
{
    auto& chain = get_chain();

    if (chain == blsct::bech32_hrp::Mainnet) {
        return Mainnet;
    } else if (chain == blsct::bech32_hrp::Testnet) {
        return Testnet;
    } else if (chain == blsct::bech32_hrp::Signet) {
        return Signet;
    } else if (chain == blsct::bech32_hrp::Regtest) {
        return Regtest;
    } else { /* should not be visited */
        return Mainnet;
    }
}

void set_blsct_chain(enum BlsctChain chain)
{
    if (chain == Mainnet)
        set_chain(blsct::bech32_hrp::Mainnet);
    else if (chain == Testnet)
        set_chain(blsct::bech32_hrp::Testnet);
    else if (chain == Signet)
        set_chain(blsct::bech32_hrp::Signet);
    else if (chain == Regtest)
        set_chain(blsct::bech32_hrp::Regtest);
}

// R r{} zero-initializes all fields including value, so callers need not
// check value when result != BLSCT_SUCCESS — it will be zeroed, not garbage.
template <typename R>
static inline R typed_err(BLSCT_RESULT result)
{
    R r{};
    r.result = result;
    return r;
}

template <typename R>
static inline R typed_err_as(const char* msg, BLSCT_RESULT result)
{
    if (msg) {
        fputs(msg, stderr);
        fputc('\n', stderr);
    }
    return typed_err<R>(result);
}

static inline BlsctBoolResult succ_bool(bool value)
{
    return {BLSCT_SUCCESS, value};
}

// TODO: need to investigate why this was not being used
[[maybe_unused]] static inline DataStream set_up_data_stream_with_hex(const char* hex)
{
    // set up a stream with the given hex
    DataStream st{};
    std::vector<uint8_t> hex_vec;
    if (!TryParseHexWrap(hex, hex_vec)) {
        return st;
    }
    st << hex_vec;
    return st;
}

static blsct::PrivateKey blsct_scalar_to_priv_key(
    const BlsctScalar* blsct_scalar)
{
    // unserialize blsct_scalar to Scalar
    Scalar scalar;
    auto u8_blsct_scalar = U8C(blsct_scalar);
    std::vector<uint8_t> vec{u8_blsct_scalar, u8_blsct_scalar + SCALAR_SIZE};
    scalar.SetVch(vec);

    // build private key from the scalar
    blsct::PrivateKey priv_key(scalar);
    return priv_key;
}

static inline bool AmountFromUint64Checked(
    const uint64_t amount,
    CAmount& out)
{
    if (amount > static_cast<uint64_t>(std::numeric_limits<CAmount>::max())) {
        return false;
    }
    out = static_cast<CAmount>(amount);
    return true;
}


template <typename T>
static std::optional<T> DeserializeObj(const char* hex)
{
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec)) return std::nullopt;
    try {
        DataStream st{vec};
        T obj{};
        st >> obj;
        return obj;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

static blsct::TokenType TokenTypeFromC(const BlsctTokenType type)
{
    return type == BlsctNft ? blsct::TokenType::NFT : blsct::TokenType::TOKEN;
}

static BlsctTokenType TokenTypeToC(const blsct::TokenType type)
{
    return type == blsct::TokenType::NFT ? BlsctNft : BlsctToken;
}

static BlsctPredicateType PredicateTypeToC(const blsct::ParsedPredicate& predicate)
{
    if (predicate.IsCreateTokenPredicate()) return BlsctCreateTokenPredicateType;
    if (predicate.IsMintTokenPredicate()) return BlsctMintTokenPredicateType;
    if (predicate.IsMintNftPredicate()) return BlsctMintNftPredicateType;
    if (predicate.IsPayFeePredicate()) return BlsctPayFeePredicateType;
    if (predicate.IsDataPredicate()) return BlsctDataPredicateType;
    return BlsctInvalidPredicateType;
}

static std::optional<blsct::ParsedPredicate> ParseOpaquePredicate(
    const BlsctVectorPredicate* blsct_vector_predicate,
    const size_t obj_size)
{
    try {
        blsct::VectorPredicate predicate;
        predicate.reserve(obj_size);
        for (size_t i = 0; i < obj_size; ++i) {
            predicate.push_back(static_cast<std::byte>(blsct_vector_predicate[i]));
        }
        return blsct::ParsePredicate(predicate);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

static std::map<std::string, std::string> StringMapFromArrays(
    const char* const* keys, const char* const* values, size_t count)
{
    std::map<std::string, std::string> result;
    if (keys == nullptr || values == nullptr) return result;
    for (size_t i = 0; i < count; ++i) {
        if (keys[i] != nullptr && values[i] != nullptr)
            result[keys[i]] = values[i];
    }
    return result;
}

static void InvokeCallbackForMap(
    const std::map<std::string, std::string>& m,
    BlsctStringMapCallback cb, void* user_data)
{
    if (cb == nullptr) return;
    for (const auto& [k, v] : m)
        cb(k.c_str(), v.c_str(), user_data);
}


static std::optional<blsct::UnsignedInput> UnsignedInputFromC(const BlsctTxInData& tx_in)
{
    CAmount amount;
    if (!AmountFromUint64Checked(tx_in.amount, amount)) {
        return std::nullopt;
    }

    Scalar gamma;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(tx_in.gamma, SCALAR_SIZE, gamma);

    blsct::PrivateKey spending_key = blsct_scalar_to_priv_key(&tx_in.spending_key);

    TokenId token_id;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(tx_in.token_id, TOKEN_ID_SIZE, token_id);

    COutPoint out_point;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(tx_in.out_point, OUT_POINT_SIZE, out_point);

    blsct::UnsignedInput input;
    input.in = CTxIn(out_point, CScript(), tx_in.rbf ? MAX_BIP125_RBF_SEQUENCE : 0xffffffffU);
    input.value = Scalar(amount);
    input.gamma = gamma;
    input.sk = spending_key;
    input.is_staked_commitment = tx_in.staked_commitment;
    return input;
}

static std::optional<blsct::UnsignedOutput> UnsignedOutputFromC(const BlsctTxOutData& tx_out)
{
    CAmount amount;
    if (!AmountFromUint64Checked(tx_out.amount, amount)) {
        return std::nullopt;
    }

    CAmount min_stake;
    if (!AmountFromUint64Checked(tx_out.min_stake, min_stake)) {
        return std::nullopt;
    }

    blsct::SubAddress destination;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(tx_out.dest, SUB_ADDR_SIZE, destination);

    TokenId token_id;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(tx_out.token_id, TOKEN_ID_SIZE, token_id);

    Scalar blinding_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(tx_out.blinding_key, SCALAR_SIZE, blinding_key);

    blsct::CreateTransactionType out_type;
    if (tx_out.output_type == TxOutputType::Normal) {
        out_type = blsct::CreateTransactionType::NORMAL;
    } else if (tx_out.output_type == TxOutputType::StakedCommitment) {
        out_type = blsct::CreateTransactionType::STAKED_COMMITMENT;
    } else {
        return std::nullopt;
    }

    return blsct::CreateOutput(
        destination.GetKeys(),
        amount,
        std::string(tx_out.memo_c_str),
        token_id,
        blinding_key,
        out_type,
        min_stake);
}

static BlsctUint256Result MallocAndCopyUint256(const uint256& value)
{
    BlsctUint256Result r{};
    std::memcpy(r.value, value.begin(), UINT256_SIZE);
    r.result = BLSCT_SUCCESS;
    return r;
}

//---------------------

void free_obj(void* x)
{
    if (x != nullptr) free(x);
}


BlsctSizeTResult serialize_raw_obj(const uint8_t* ser_obj, size_t ser_obj_size, char* buf, size_t buf_size)
{
    if (ser_obj == nullptr) return typed_err<BlsctSizeTResult>(BLSCT_FAILURE);
    return {BLSCT_SUCCESS, WriteHexBuf(ser_obj, ser_obj_size, buf, buf_size)};
}

BLSCT_RESULT deserialize_raw_obj(const char* hex, uint8_t* buf, size_t buf_size, size_t* out_len)
{
    if (hex == nullptr) return BLSCT_FAILURE;
    size_t ser_obj_size = std::strlen(hex) / 2;
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec) || vec.size() != ser_obj_size) return BLSCT_FAILURE;
    if (out_len) *out_len = ser_obj_size;
    if (buf != nullptr && buf_size >= ser_obj_size)
        std::memcpy(buf, vec.data(), ser_obj_size);
    return BLSCT_SUCCESS;
}

// address
BlsctDoublePubKeyResult decode_address(
    const char* blsct_enc_addr)
{
    try {
        std::string enc_addr(blsct_enc_addr);
        auto& chain = get_chain();
        auto maybe_dpk = blsct::DecodeDoublePublicKey(chain, enc_addr);
        if (maybe_dpk) {
            auto dpk = maybe_dpk.value();
            if (dpk.IsValid()) {
                auto buf = dpk.GetVch();
                BlsctDoublePubKeyResult r{};
                std::memcpy(r.value, &buf[0], DOUBLE_PUBLIC_KEY_SIZE);
                r.result = BLSCT_SUCCESS;
                return r;
            }
        }
    } catch (...) {
    }

    return typed_err<BlsctDoublePubKeyResult>(BLSCT_EXCEPTION);
}

BLSCT_RESULT encode_address(
    const void* void_blsct_dpk,
    enum AddressEncoding encoding,
    char* buf,
    size_t buf_size,
    size_t* out_len)
{
    if (encoding != Bech32 && encoding != Bech32M) {
        return BLSCT_UNKNOWN_ENCODING;
    }
    try {
        UNVOID(BlsctDoublePubKey, blsct_dpk);

        auto blsct_dpk_u8 = U8C(blsct_dpk);
        std::vector<uint8_t> dpk_vec(blsct_dpk_u8, blsct_dpk_u8 + sizeof(BlsctDoublePubKey));
        auto dpk = blsct::DoublePublicKey(dpk_vec);

        auto bech32_encoding = encoding == Bech32 ?
                                   bech32_mod::Encoding::BECH32 :
                                   bech32_mod::Encoding::BECH32M;
        auto& chain = get_chain();
        auto enc_dpk_str = EncodeDoublePublicKey(chain, bech32_encoding, dpk);

        if (out_len != nullptr) *out_len = enc_dpk_str.size();
        WriteStrBuf(enc_dpk_str, buf, buf_size);
        return BLSCT_SUCCESS;

    } catch (...) {
    }

    return BLSCT_EXCEPTION;
}

// amount recovery
BLSCT_RESULT recover_amount(
    const BlsctAmountRecoveryReq* reqs,
    size_t n,
    BlsctAmountRecoveryResult* results)
{
    std::shared_lock<std::shared_mutex> lock(g_rpl_mutex);
    if (g_rpl == nullptr) return BLSCT_INIT_NOT_CALLED;
    if (reqs == nullptr || n == 0 || results == nullptr) return BLSCT_SUCCESS;
    try {
        std::vector<bulletproofs_plus::AmountRecoveryRequest<Mcl>> cpp_reqs;

        for (size_t i = 0; i < n; ++i) {
            const auto& ar_req = reqs[i];
            if (ar_req.range_proof == nullptr)
                return BLSCT_FAILURE;

            bulletproofs_plus::RangeProof<Mcl> range_proof;
            UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(ar_req.range_proof, ar_req.range_proof_size, range_proof);

            Mcl::Point nonce;
            UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(ar_req.nonce, POINT_SIZE, nonce);

            TokenId token_id;
            UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(ar_req.token_id, TOKEN_ID_SIZE, token_id);

            auto proof_w_seed = bulletproofs_plus::RangeProofWithSeed<Mcl>(range_proof, token_id);
            cpp_reqs.push_back(bulletproofs_plus::AmountRecoveryRequest<Mcl>::of(proof_w_seed, nonce, i));
        }

        auto recovery_results = g_rpl->RecoverAmounts(cpp_reqs);

        if (!recovery_results.is_completed) {
            return BLSCT_DID_NOT_RUN_TO_COMPLETION;
        }

        for (size_t i = 0; i < n; ++i) {
            results[i].is_succ = false;
        }

        for (size_t i = 0; i < recovery_results.amounts.size(); ++i) {
            auto& succ_res = recovery_results.amounts[i];
            auto& result = results[succ_res.id];

            result.is_succ = true;
            result.amount = succ_res.amount;

            size_t msg_len = std::min(succ_res.message.size(), (size_t)MAX_MEMO_LEN);
            std::memcpy(result.msg, succ_res.message.c_str(), msg_len);
            result.msg[msg_len] = '\0';

            SERIALIZE_AND_COPY(succ_res.gamma, result.gamma);
        }

        return BLSCT_SUCCESS;

    } catch (...) {
    }

    return BLSCT_EXCEPTION;
}

// ctx
BlsctCTxResult build_ctx(
    const BlsctTxInData* tx_ins,
    size_t tx_ins_len,
    const BlsctTxOutData* tx_outs,
    size_t tx_outs_len,
    char* buf,
    size_t buf_size,
    size_t* out_len)
{
    if (tx_ins == nullptr || tx_ins_len == 0 || tx_outs == nullptr || tx_outs_len == 0)
        return typed_err<BlsctCTxResult>(BLSCT_FAILURE);

    blsct::TxFactoryBase psbt;

    for (size_t i = 0; i < tx_ins_len; ++i) {
        // unserialize tx_in fields and add to TxFactoryBase
        const BlsctTxInData& tx_in = tx_ins[i];

        // check if the amount is within the range
        // amount is uint64_t and not serialized
        if (tx_in.amount > std::numeric_limits<int64_t>::max()) {
            BlsctCTxResult rv{};
            rv.result = BLSCT_IN_AMOUNT_ERROR;
            rv.in_amount_err_index = i;
            return rv;
        }

        Scalar gamma;
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(tx_in.gamma, SCALAR_SIZE, gamma);

        // unserialize spending_key
        blsct::PrivateKey spending_key =
            blsct_scalar_to_priv_key(&tx_in.spending_key);

        // unserialize token_id
        TokenId token_id;
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
            tx_in.token_id, TOKEN_ID_SIZE, token_id);

        // unserialize out_point
        COutPoint out_point;
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
            tx_in.out_point, OUT_POINT_SIZE, out_point);

        // add all to TxFactoryBase
        psbt.AddInput(
            tx_in.amount,
            gamma,
            spending_key,
            token_id,
            out_point,
            tx_in.staked_commitment,
            tx_in.rbf);
    }

    for (size_t i = 0; i < tx_outs_len; ++i) {
        // unserialize tx_out fields and add to TxFactoryBase
        const BlsctTxOutData& tx_out = tx_outs[i];

        // check if the amount is within the range
        // amount is uint64_t and not serialized
        if (tx_out.amount > std::numeric_limits<int64_t>::max()) {
            BlsctCTxResult rv{};
            rv.result = BLSCT_OUT_AMOUNT_ERROR;
            rv.out_amount_err_index = i;
            return rv;
        }

        // unserialize destination
        blsct::DoublePublicKey dest;
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
            tx_out.dest, DOUBLE_PUBLIC_KEY_SIZE, dest);

        // create memo std::string from memo c_str
        std::string memo_str(tx_out.memo_c_str);

        // unserialize token_id
        TokenId token_id;
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
            tx_out.token_id, TOKEN_ID_SIZE, token_id);

        // create out_type from blsct::TxOutputType
        blsct::CreateTransactionType out_type;
        if (tx_out.output_type == TxOutputType::Normal) {
            out_type = blsct::CreateTransactionType::NORMAL;
        } else if (tx_out.output_type == TxOutputType::StakedCommitment) {
            out_type = blsct::CreateTransactionType::STAKED_COMMITMENT;
        } else {
            return typed_err<BlsctCTxResult>(BLSCT_BAD_OUT_TYPE);
        }

        // unserialize blinding key
        Scalar blinding_key;
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
            tx_out.blinding_key, SCALAR_SIZE, blinding_key);

        // add all to TxFactoryBase
        psbt.AddOutput(
            dest,
            tx_out.amount,
            memo_str,
            token_id,
            out_type,
            tx_out.min_stake,
            tx_out.subtract_fee_from_amount,
            blinding_key);
    }

    // build ctx
    blsct::DoublePublicKey change_amt_dest;
    auto maybe_ctx = psbt.BuildTx(change_amt_dest);
    if (!maybe_ctx.has_value()) {
        return typed_err<BlsctCTxResult>(BLSCT_FAILURE);
    }

    CMutableTransaction ctx = std::move(maybe_ctx.value());
    size_t sz = SerializeCtxToHexBuf(ctx, buf, buf_size);
    if (out_len) *out_len = sz;
    BlsctCTxResult rv{};
    rv.result = BLSCT_SUCCESS;
    return rv;
}

static std::optional<CMutableTransaction> DeserializeCtx(const char* hex)
{
    if (!hex) return std::nullopt;
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(std::string(hex), vec)) return std::nullopt;
    try {
        CMutableTransaction tx;
        DataStream st;
        TransactionSerParams params{.allow_witness = true};
        ParamsStream ps{params, st};
        st.write(MakeByteSpan(vec));
        tx.Unserialize(ps);
        return tx;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

BlsctCTxIdHexResult get_ctx_id(const char* hex)
{
    auto tx = DeserializeCtx(hex);
    if (!tx) return typed_err<BlsctCTxIdHexResult>(BLSCT_FAILURE);
    std::string id_hex = tx->GetHash().GetHex();
    BlsctCTxIdHexResult r{};
    std::memcpy(r.value, id_hex.c_str(), id_hex.size() + 1);
    r.result = BLSCT_SUCCESS;
    return r;
}

bool are_ctx_ins_equal(const char* hex_a, const char* hex_b)
{
    if (!hex_a || !hex_b) return false;
    auto a = DeserializeCtx(hex_a);
    auto b = DeserializeCtx(hex_b);
    if (!a || !b) return false;
    return a->vin == b->vin;
}

BlsctSizeTResult get_ctx_ins_size(const char* hex)
{
    if (hex == nullptr) return typed_err<BlsctSizeTResult>(BLSCT_FAILURE);
    auto tx = DeserializeCtx(hex);
    if (!tx) return typed_err<BlsctSizeTResult>(BLSCT_FAILURE);
    return {BLSCT_SUCCESS, tx->vin.size()};
}

bool are_ctx_outs_equal(const char* hex_a, const char* hex_b)
{
    if (!hex_a || !hex_b) return false;
    auto a = DeserializeCtx(hex_a);
    auto b = DeserializeCtx(hex_b);
    if (!a || !b) return false;
    return a->vout == b->vout;
}

BlsctSizeTResult get_ctx_outs_size(const char* hex)
{
    if (hex == nullptr) return typed_err<BlsctSizeTResult>(BLSCT_FAILURE);
    auto tx = DeserializeCtx(hex);
    if (!tx) return typed_err<BlsctSizeTResult>(BLSCT_FAILURE);
    return {BLSCT_SUCCESS, tx->vout.size()};
}

BlsctCTxIdResult get_ctx_in_prev_out_hash_at(const char* hex, size_t i)
{
    auto tx = DeserializeCtx(hex);
    if (!tx || i >= tx->vin.size()) return typed_err<BlsctCTxIdResult>(BLSCT_FAILURE);
    return get_ctx_in_prev_out_hash(&tx->vin[i]);
}

BlsctScriptResult get_ctx_in_script_sig_at(const char* hex, size_t i)
{
    auto tx = DeserializeCtx(hex);
    if (!tx || i >= tx->vin.size()) return typed_err<BlsctScriptResult>(BLSCT_FAILURE);
    return get_ctx_in_script_sig(&tx->vin[i]);
}

BlsctUint32Result get_ctx_in_sequence_at(const char* hex, size_t i)
{
    auto tx = DeserializeCtx(hex);
    if (!tx || i >= tx->vin.size()) return typed_err<BlsctUint32Result>(BLSCT_FAILURE);
    return get_ctx_in_sequence(&tx->vin[i]);
}

BlsctScriptResult get_ctx_in_script_witness_at(const char* hex, size_t i)
{
    auto tx = DeserializeCtx(hex);
    if (!tx || i >= tx->vin.size()) return typed_err<BlsctScriptResult>(BLSCT_FAILURE);
    return get_ctx_in_script_witness(&tx->vin[i]);
}

BlsctUint64Result get_ctx_out_value_at(const char* hex, size_t i)
{
    auto tx = DeserializeCtx(hex);
    if (!tx || i >= tx->vout.size()) return typed_err<BlsctUint64Result>(BLSCT_FAILURE);
    return get_ctx_out_value(&tx->vout[i]);
}

BlsctScriptResult get_ctx_out_script_pub_key_at(const char* hex, size_t i)
{
    auto tx = DeserializeCtx(hex);
    if (!tx || i >= tx->vout.size()) return typed_err<BlsctScriptResult>(BLSCT_FAILURE);
    return get_ctx_out_script_pub_key(&tx->vout[i]);
}

BlsctTokenIdResult get_ctx_out_token_id_at(const char* hex, size_t i)
{
    auto tx = DeserializeCtx(hex);
    if (!tx || i >= tx->vout.size()) return typed_err<BlsctTokenIdResult>(BLSCT_FAILURE);
    return get_ctx_out_token_id(&tx->vout[i]);
}

BLSCT_RESULT get_ctx_out_vector_predicate_at(const char* hex, size_t i, uint8_t* buf, size_t buf_size, size_t* out_len)
{
    auto tx = DeserializeCtx(hex);
    if (!tx || i >= tx->vout.size()) return BLSCT_FAILURE;
    return get_ctx_out_vector_predicate(&tx->vout[i], buf, buf_size, out_len);
}

BlsctPointResult get_ctx_out_spending_key_at(const char* hex, size_t i)
{
    auto tx = DeserializeCtx(hex);
    if (!tx || i >= tx->vout.size()) return typed_err<BlsctPointResult>(BLSCT_FAILURE);
    return get_ctx_out_spending_key(&tx->vout[i]);
}

BlsctPointResult get_ctx_out_ephemeral_key_at(const char* hex, size_t i)
{
    auto tx = DeserializeCtx(hex);
    if (!tx || i >= tx->vout.size()) return typed_err<BlsctPointResult>(BLSCT_FAILURE);
    return get_ctx_out_ephemeral_key(&tx->vout[i]);
}

BlsctPointResult get_ctx_out_blinding_key_at(const char* hex, size_t i)
{
    auto tx = DeserializeCtx(hex);
    if (!tx || i >= tx->vout.size()) return typed_err<BlsctPointResult>(BLSCT_FAILURE);
    return get_ctx_out_blinding_key(&tx->vout[i]);
}

BLSCT_RESULT get_ctx_out_range_proof_at(const char* hex, size_t i, uint8_t* buf, size_t buf_size, size_t* out_len)
{
    auto tx = DeserializeCtx(hex);
    if (!tx || i >= tx->vout.size()) return BLSCT_FAILURE;
    return get_ctx_out_range_proof(&tx->vout[i], buf, buf_size, out_len);
}

BlsctUint16Result get_ctx_out_view_tag_at(const char* hex, size_t i)
{
    auto tx = DeserializeCtx(hex);
    if (!tx || i >= tx->vout.size()) return typed_err<BlsctUint16Result>(BLSCT_FAILURE);
    return get_ctx_out_view_tag(&tx->vout[i]);
}

// ctx id
BlsctCTxIdHexResult serialize_ctx_id(const BlsctCTxId* blsct_ctx_id)
{
    BlsctCTxIdHexResult r{};
    FillHexBuf((const uint8_t*)blsct_ctx_id, CTX_ID_SIZE, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctCTxIdResult deserialize_ctx_id(const char* hex)
{
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec) || vec.size() != CTX_ID_SIZE) {
        return typed_err<BlsctCTxIdResult>(BLSCT_BAD_SIZE);
    }
    BlsctCTxIdResult r{};
    std::memcpy(r.value, vec.data(), CTX_ID_SIZE);
    r.result = BLSCT_SUCCESS;
    return r;
}

BLSCT_RESULT aggregate_transactions(const char* const* tx_hexes, size_t tx_count, char* buf, size_t buf_size, size_t* out_len)
{
    if (tx_hexes == nullptr || tx_count == 0) return BLSCT_FAILURE;

    std::vector<CTransactionRef> txs;
    txs.reserve(tx_count);

    for (size_t i = 0; i < tx_count; ++i) {
        const std::string tx_hex = tx_hexes[i] ? tx_hexes[i] : "";
        std::vector<uint8_t> tx_bytes;
        if (!TryParseHexWrap(tx_hex, tx_bytes) || tx_bytes.empty()) {
            return BLSCT_DESER_FAILED;
        }

        CMutableTransaction mutable_tx;
        try {
            DataStream st{};
            TransactionSerParams params{.allow_witness = true};
            ParamsStream ps{params, st};
            st.write(MakeByteSpan(tx_bytes));
            mutable_tx.Unserialize(ps);
        } catch (const std::exception&) {
            return BLSCT_DESER_FAILED;
        }

        txs.push_back(MakeTransactionRef(std::move(mutable_tx)));
    }

    try {
        const auto aggregated_tx = blsct::AggregateTransactions(txs);

        DataStream st{};
        TransactionSerParams params{.allow_witness = true};
        ParamsStream ps{params, st};
        aggregated_tx->Serialize(ps);

        const auto hex = HexStr(MakeByteSpan(st));
        if (out_len != nullptr) *out_len = hex.size();
        WriteStrBuf(hex, buf, buf_size);
        return BLSCT_SUCCESS;
    } catch (const std::exception&) {
        return BLSCT_FAILURE;
    }
}

// ctx in
bool are_ctx_in_equal(const void* vp_a, const void* vp_b)
{
    if (vp_a == nullptr || vp_b == nullptr) return false;
    auto* a = static_cast<const CTxIn*>(vp_a);
    auto* b = static_cast<const CTxIn*>(vp_b);
    return *a == *b;
}

BlsctCTxIdResult get_ctx_in_prev_out_hash(const void* vp_ctx_in)
{
    if (vp_ctx_in == nullptr) return typed_err<BlsctCTxIdResult>(BLSCT_FAILURE);
    auto* ctx_in = static_cast<const CTxIn*>(vp_ctx_in);
    BlsctCTxIdResult r{};
    r.result = BLSCT_SUCCESS;
    std::memcpy(r.value, &ctx_in->prevout.hash, CTX_ID_SIZE);
    return r;
}

BlsctScriptResult get_ctx_in_script_sig(const void* vp_ctx_in)
{
    if (vp_ctx_in == nullptr) return typed_err<BlsctScriptResult>(BLSCT_FAILURE);
    auto* ctx_in = static_cast<const CTxIn*>(vp_ctx_in);
    if (ctx_in->scriptSig.size() > SCRIPT_SIZE)
        return typed_err<BlsctScriptResult>(BLSCT_BAD_SIZE);
    BlsctScriptResult r{};
    std::memcpy(r.value, ctx_in->scriptSig.data(), ctx_in->scriptSig.size());
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctUint32Result get_ctx_in_sequence(const void* vp_ctx_in)
{
    if (vp_ctx_in == nullptr) return typed_err<BlsctUint32Result>(BLSCT_FAILURE);
    auto* ctx_in = static_cast<const CTxIn*>(vp_ctx_in);
    return {BLSCT_SUCCESS, ctx_in->nSequence};
}

BlsctScriptResult get_ctx_in_script_witness(const void* vp_ctx_in)
{
    if (vp_ctx_in == nullptr) return typed_err<BlsctScriptResult>(BLSCT_FAILURE);
    auto* ctx_in = static_cast<const CTxIn*>(vp_ctx_in);
    const auto& stack = ctx_in->scriptWitness.stack;
    if (!stack.empty() && !stack[0].empty()) {
        if (stack[0].size() > SCRIPT_SIZE)
            return typed_err<BlsctScriptResult>(BLSCT_BAD_SIZE);
        BlsctScriptResult r{};
        std::memcpy(r.value, stack[0].data(), stack[0].size());
        r.result = BLSCT_SUCCESS;
        return r;
    }
    BlsctScriptResult r{};
    r.result = BLSCT_SUCCESS;
    return r;
}

// ctx out
bool are_ctx_out_equal(const void* vp_a, const void* vp_b)
{
    if (vp_a == nullptr || vp_b == nullptr) return false;
    auto* a = static_cast<const CTxOut*>(vp_a);
    auto* b = static_cast<const CTxOut*>(vp_b);
    return *a == *b;
}

BlsctUint64Result get_ctx_out_value(const void* vp_ctx_out)
{
    if (vp_ctx_out == nullptr) return typed_err<BlsctUint64Result>(BLSCT_FAILURE);
    auto* ctx_out = static_cast<const CTxOut*>(vp_ctx_out);
    return {BLSCT_SUCCESS, static_cast<uint64_t>(ctx_out->nValue)};
}

BlsctScriptResult get_ctx_out_script_pub_key(const void* vp_ctx_out)
{
    if (vp_ctx_out == nullptr) return typed_err<BlsctScriptResult>(BLSCT_FAILURE);
    auto* ctx_out = static_cast<const CTxOut*>(vp_ctx_out);
    if (ctx_out->scriptPubKey.size() > SCRIPT_SIZE)
        return typed_err<BlsctScriptResult>(BLSCT_BAD_SIZE);
    BlsctScriptResult r{};
    std::memcpy(r.value, ctx_out->scriptPubKey.data(), ctx_out->scriptPubKey.size());
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctPointResult get_ctx_out_spending_key(const void* vp_ctx_out)
{
    if (vp_ctx_out == nullptr) return typed_err<BlsctPointResult>(BLSCT_FAILURE);
    auto* ctx_out = static_cast<const CTxOut*>(vp_ctx_out);
    BlsctPointResult r{};
    r.result = BLSCT_SUCCESS;
    SERIALIZE_AND_COPY(ctx_out->blsctData.spendingKey, r.value);
    return r;
}

BlsctPointResult get_ctx_out_ephemeral_key(const void* vp_ctx_out)
{
    if (vp_ctx_out == nullptr) return typed_err<BlsctPointResult>(BLSCT_FAILURE);
    auto* ctx_out = static_cast<const CTxOut*>(vp_ctx_out);
    BlsctPointResult r{};
    r.result = BLSCT_SUCCESS;
    SERIALIZE_AND_COPY(ctx_out->blsctData.ephemeralKey, r.value);
    return r;
}

BlsctPointResult get_ctx_out_blinding_key(const void* vp_ctx_out)
{
    if (vp_ctx_out == nullptr) return typed_err<BlsctPointResult>(BLSCT_FAILURE);
    auto* ctx_out = static_cast<const CTxOut*>(vp_ctx_out);
    BlsctPointResult r{};
    r.result = BLSCT_SUCCESS;
    SERIALIZE_AND_COPY(ctx_out->blsctData.blindingKey, r.value);
    return r;
}

BLSCT_RESULT get_ctx_out_range_proof(const void* vp_ctx_out, uint8_t* buf, size_t buf_size, size_t* out_len)
{
    if (vp_ctx_out == nullptr) return BLSCT_FAILURE;
    auto* ctx_out = static_cast<const CTxOut*>(vp_ctx_out);
    size_t sz = SerializeObjToByteBuf(ctx_out->blsctData.rangeProof, buf, buf_size);
    if (out_len) *out_len = sz;
    return BLSCT_SUCCESS;
}

BlsctUint16Result get_ctx_out_view_tag(const void* vp_ctx_out)
{
    if (vp_ctx_out == nullptr) return typed_err<BlsctUint16Result>(BLSCT_FAILURE);
    auto* ctx_out = static_cast<const CTxOut*>(vp_ctx_out);
    return {BLSCT_SUCCESS, ctx_out->blsctData.viewTag};
}

BlsctTokenIdResult get_ctx_out_token_id(const void* vp_ctx_out)
{
    if (vp_ctx_out == nullptr) return typed_err<BlsctTokenIdResult>(BLSCT_FAILURE);
    auto* ctx_out = static_cast<const CTxOut*>(vp_ctx_out);
    BlsctTokenIdResult r{};
    r.result = BLSCT_SUCCESS;
    std::memcpy(r.value, &ctx_out->tokenId, TOKEN_ID_SIZE);
    return r;
}

BLSCT_RESULT get_ctx_out_vector_predicate(const void* vp_ctx_out, uint8_t* buf, size_t buf_size, size_t* out_len)
{
    if (vp_ctx_out == nullptr) return BLSCT_FAILURE;
    auto* ctx_out = static_cast<const CTxOut*>(vp_ctx_out);
    auto& pred = ctx_out->predicate;
    if (out_len) *out_len = pred.size();
    if (buf != nullptr && buf_size >= pred.size())
        std::memcpy(buf, pred.data(), pred.size());
    return BLSCT_SUCCESS;
}

// delegators of blsct/wallet/helpers
BlsctUint64Result calc_view_tag(
    const BlsctPubKey* blsct_blinding_pub_key,
    const BlsctScalar* blsct_view_key)
{
    if (blsct_blinding_pub_key == nullptr || blsct_view_key == nullptr)
        return typed_err<BlsctUint64Result>(BLSCT_FAILURE);

    blsct::PublicKey blinding_pub_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_blinding_pub_key, PUBLIC_KEY_SIZE, blinding_pub_key);

    Scalar view_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_view_key, SCALAR_SIZE, view_key);

    return {BLSCT_SUCCESS, blsct::CalculateViewTag(
                               blinding_pub_key.GetG1Point(),
                               view_key)};
}

BlsctPointResult calc_nonce(
    const BlsctPubKey* blsct_blinding_pub_key,
    const BlsctScalar* blsct_view_key)
{
    if (blsct_blinding_pub_key == nullptr || blsct_view_key == nullptr)
        return typed_err<BlsctPointResult>(BLSCT_FAILURE);

    blsct::PublicKey blinding_pub_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_blinding_pub_key, PUBLIC_KEY_SIZE, blinding_pub_key);

    Scalar view_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_view_key, SCALAR_SIZE, view_key);

    auto nonce = blsct::CalculateNonce(
        blinding_pub_key.GetG1Point(),
        view_key);
    BlsctPointResult r{};
    SERIALIZE_AND_COPY(nonce, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

// double public key
BlsctDoublePubKeyResult gen_double_pub_key(
    const BlsctPubKey* blsct_pk1,
    const BlsctPubKey* blsct_pk2)
{
    auto blsct_pk1_u8 = U8C(blsct_pk1);
    auto blsct_pk2_u8 = U8C(blsct_pk2);

    blsct::PublicKey pk1, pk2;
    std::vector<uint8_t> blsct_pk1_vec{
        blsct_pk1_u8,
        blsct_pk1_u8 + blsct::PublicKey::SIZE};
    std::vector<uint8_t> blsct_pk2_vec{
        blsct_pk2_u8,
        blsct_pk2_u8 + blsct::PublicKey::SIZE};
    pk1.SetVch(blsct_pk1_vec);
    pk2.SetVch(blsct_pk2_vec);

    blsct::DoublePublicKey dpk(pk1, pk2);
    BlsctDoublePubKeyResult r{};
    SERIALIZE_AND_COPY(dpk, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctSubAddrResult dpk_to_sub_addr(
    const BlsctDoublePubKey* blsct_dpk)
{
    // unserialize double public key
    blsct::DoublePublicKey dpk;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
        blsct_dpk, DOUBLE_PUBLIC_KEY_SIZE, dpk);

    // create sub address from dpk
    blsct::SubAddress sub_addr(dpk);

    BlsctSubAddrResult r{};
    SERIALIZE_AND_COPY_WITH_STREAM(sub_addr, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctDoublePubKeyResult sub_addr_to_dpk(
    const BlsctSubAddr* blsct_sub_addr)
{
    // unserialize sub address
    blsct::SubAddress sub_addr;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
        blsct_sub_addr, SUB_ADDR_SIZE, sub_addr);

    blsct::DoublePublicKey dpk = sub_addr.GetKeys();
    BlsctDoublePubKeyResult r{};
    SERIALIZE_AND_COPY_WITH_STREAM(dpk, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctDoublePubKeyResult gen_dpk_with_keys_acct_addr(
    const BlsctScalar* blsct_view_key,
    const BlsctPubKey* blsct_spending_pub_key,
    const int64_t account,
    const uint64_t address)
{
    Scalar view_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_view_key, SCALAR_SIZE, view_key);

    blsct::PublicKey spending_pub_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_spending_pub_key, PUBLIC_KEY_SIZE, spending_pub_key);

    blsct::SubAddressIdentifier sub_addr_id{account, address};
    blsct::SubAddress sub_addr(view_key, spending_pub_key, sub_addr_id);

    auto dpk = std::get<blsct::DoublePublicKey>(sub_addr.GetDestination());
    BlsctDoublePubKeyResult r{};
    SERIALIZE_AND_COPY_WITH_STREAM(dpk, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctDoublePubKeyHexResult serialize_dpk(const BlsctDoublePubKey* blsct_dpk)
{
    BlsctDoublePubKeyHexResult r{};
    FillHexBuf((const uint8_t*)blsct_dpk, DOUBLE_PUBLIC_KEY_SIZE, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctDoublePubKeyResult deserialize_dpk(const char* hex)
{
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec) || vec.size() != DOUBLE_PUBLIC_KEY_SIZE) {
        return typed_err<BlsctDoublePubKeyResult>(BLSCT_BAD_SIZE);
    }
    BlsctDoublePubKeyResult r{};
    std::memcpy(r.value, vec.data(), DOUBLE_PUBLIC_KEY_SIZE);
    r.result = BLSCT_SUCCESS;
    return r;
}

// key id
BlsctKeyIdResult calc_key_id(
    const BlsctPubKey* blsct_blinding_pub_key,
    const BlsctPubKey* blsct_spending_pub_key,
    const BlsctScalar* blsct_view_key)
{
    blsct::PublicKey blinding_pub_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_blinding_pub_key, PUBLIC_KEY_SIZE, blinding_pub_key);

    blsct::PublicKey spending_pub_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_spending_pub_key, PUBLIC_KEY_SIZE, spending_pub_key);

    Scalar view_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_view_key, SCALAR_SIZE, view_key);

    auto key_id = blsct::CalculateHashId(
        blinding_pub_key.GetG1Point(),
        spending_pub_key.GetG1Point(),
        view_key);
    BlsctKeyIdResult r{};
    SERIALIZE_AND_COPY_WITH_STREAM(key_id, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctKeyIdHexResult serialize_key_id(
    const BlsctKeyId* blsct_key_id)
{
    BlsctKeyIdHexResult r{};
    FillHexBuf((const uint8_t*)blsct_key_id, KEY_ID_SIZE, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctKeyIdResult deserialize_key_id(const char* hex)
{
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec) || vec.size() != KEY_ID_SIZE) {
        return typed_err<BlsctKeyIdResult>(BLSCT_BAD_SIZE);
    }
    BlsctKeyIdResult r{};
    std::memcpy(r.value, vec.data(), KEY_ID_SIZE);
    r.result = BLSCT_SUCCESS;
    return r;
}

// out point
BlsctOutPointResult gen_out_point(
    const char* ctx_id_c_str)
{
    if (ctx_id_c_str == nullptr || std::strlen(ctx_id_c_str) != CTX_ID_STR_LEN)
        return typed_err<BlsctOutPointResult>(BLSCT_FAILURE);

    std::string ctx_id_str(ctx_id_c_str, CTX_ID_STR_LEN);

    auto ctx_id = TxidFromString(ctx_id_str);
    COutPoint out_point{ctx_id};

    BlsctOutPointResult r{};
    SERIALIZE_AND_COPY_WITH_STREAM(out_point, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctOutPointHexResult serialize_out_point(const BlsctOutPoint* blsct_out_point)
{
    BlsctOutPointHexResult r{};
    FillHexBuf((const uint8_t*)blsct_out_point, OUT_POINT_SIZE, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctOutPointResult deserialize_out_point(const char* hex)
{
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec) || vec.size() != OUT_POINT_SIZE) {
        return typed_err<BlsctOutPointResult>(BLSCT_BAD_SIZE);
    }
    BlsctOutPointResult r{};
    std::memcpy(r.value, vec.data(), OUT_POINT_SIZE);
    r.result = BLSCT_SUCCESS;
    return r;
}

// point
BlsctPointResult gen_base_point()
{
    BlsctPointResult r{};
    auto x = Point::GetBasePoint();
    SERIALIZE_AND_COPY(x, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctPointResult gen_random_point()
{
    BlsctPointResult r{};
    auto x = Point::Rand();
    SERIALIZE_AND_COPY(x, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctPointHexResult serialize_point(const BlsctPoint* blsct_point)
{
    Point point;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_point, POINT_SIZE, point);
    auto ser_point = point.GetVch();
    BlsctPointHexResult r{};
    FillHexBuf(ser_point.data(), ser_point.size(), r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctPointResult deserialize_point(const char* hex)
{
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec)) {
        return typed_err<BlsctPointResult>(BLSCT_FAILURE);
    }
    Point point;
    if (!point.SetVch(vec)) {
        return typed_err<BlsctPointResult>(BLSCT_DESER_FAILED);
    }

    BlsctPointResult r{};
    SERIALIZE_AND_COPY(point, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

int are_point_equal(const BlsctPoint* blsct_a, const BlsctPoint* blsct_b)
{
    if (blsct_a == nullptr || blsct_b == nullptr) {
        return 0;
    }
    Point a, b;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_a, POINT_SIZE, a);
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_b, POINT_SIZE, b);
    return a == b ? 1 : 0;
}

BlsctPointResult scalar_muliply_point(
    const BlsctPoint* blsct_point,
    const BlsctScalar* blsct_scalar)
{
    Point p;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_point, POINT_SIZE, p);

    Scalar s;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_scalar, SCALAR_SIZE, s);

    Point sp = p * s;

    BlsctPointResult r{};
    SERIALIZE_AND_COPY(sp, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctSizeTResult point_to_str(const BlsctPoint* blsct_point, char* buf, size_t buf_size)
{
    if (blsct_point == nullptr) return typed_err<BlsctSizeTResult>(BLSCT_FAILURE);
    Point point;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_point, POINT_SIZE, point);
    return {BLSCT_SUCCESS, WriteStrBuf(point.GetString(), buf, buf_size)};
}

BlsctPointResult point_from_scalar(const BlsctScalar* blsct_scalar)
{
    Scalar scalar;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_scalar, SCALAR_SIZE, scalar);

    Point g = Point::GetBasePoint();
    Point point = g * scalar;

    BlsctPointResult r{};
    SERIALIZE_AND_COPY(point, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

bool is_valid_point(
    const BlsctPoint* blsct_point)
{
    if (blsct_point == nullptr) return false;
    Point point;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_point, POINT_SIZE, point);

    return point.IsValid();
}

// public key
BlsctPubKeyResult gen_random_public_key()
{
    auto vec = Point::Rand().GetVch();
    blsct::PublicKey pub_key(vec);

    BlsctPubKeyResult r{};
    SERIALIZE_AND_COPY(pub_key, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctPointResult get_public_key_point(const BlsctPubKey* blsct_pub_key)
{
    blsct::PublicKey pub_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_pub_key, PUBLIC_KEY_SIZE, pub_key);
    auto point = pub_key.GetG1Point();

    BlsctPointResult r{};
    r.result = BLSCT_SUCCESS;
    SERIALIZE_AND_COPY(point, r.value);
    return r;
}

BlsctPubKeyResult point_to_public_key(const BlsctPoint* blsct_point)
{
    Point point;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_point, POINT_SIZE, point);
    blsct::PublicKey pub_key(point);

    BlsctPubKeyResult r{};
    SERIALIZE_AND_COPY(pub_key, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctPointHexResult serialize_public_key(const BlsctPoint* blsct_pubkey)
{
    blsct::PublicKey pubkey;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_pubkey, PUBLIC_KEY_SIZE, pubkey);
    auto ser_pubkey = pubkey.GetVch();
    BlsctPointHexResult r{};
    FillHexBuf(ser_pubkey.data(), ser_pubkey.size(), r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctPubKeyResult deserialize_public_key(const char* hex)
{
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec)) {
        return typed_err<BlsctPubKeyResult>(BLSCT_FAILURE);
    }
    blsct::PublicKey pubkey;
    if (!pubkey.SetVch(vec)) {
        return typed_err<BlsctPubKeyResult>(BLSCT_DESER_FAILED);
    }

    BlsctPubKeyResult r{};
    SERIALIZE_AND_COPY(pubkey, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

// range proof
BLSCT_RESULT build_range_proof(
    const uint64_t* amounts,
    size_t amounts_len,
    const BlsctPoint* blsct_nonce,
    const char* blsct_msg,
    const BlsctTokenId* blsct_token_id,
    uint8_t* buf,
    size_t buf_size,
    size_t* out_len)
{
    std::shared_lock<std::shared_mutex> lock(g_rpl_mutex);
    if (g_rpl == nullptr) return BLSCT_INIT_NOT_CALLED;
    if (amounts == nullptr || amounts_len == 0) return BLSCT_FAILURE;
    try {
        Scalars vs;
        for (size_t i = 0; i < amounts_len; ++i) {
            if (amounts[i] > INT64_MAX) {
                return BLSCT_VALUE_OUTSIDE_THE_RANGE;
            }
            Mcl::Scalar x(static_cast<int64_t>(amounts[i]));
            vs.Add(x);
        }

        // blsct_nonce to nonce
        Mcl::Point nonce = Mcl::Point::GetBasePoint();
        auto blsct_nonce_u8 = U8C(blsct_nonce);
        std::vector<uint8_t> ser_point(
            blsct_nonce_u8, blsct_nonce_u8 + POINT_SIZE);
        nonce.SetVch(ser_point);

        // blsct_message to message
        std::string msg(blsct_msg);
        std::vector<uint8_t> msg_vec(msg.begin(), msg.end());

        // blsct_token_id to token_id
        TokenId token_id;
        auto blsct_token_id_u8 = U8C(blsct_token_id);
        UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_token_id_u8, TOKEN_ID_SIZE, token_id);

        auto range_proof = g_rpl->Prove(vs, nonce, msg_vec, token_id);
        size_t sz = SerializeObjToByteBuf(range_proof, buf, buf_size);
        if (out_len) *out_len = sz;
        return BLSCT_SUCCESS;

    } catch (...) {
    }

    return BLSCT_EXCEPTION;
}

BlsctBoolResult verify_range_proofs(
    const BlsctRangeProof* const* proofs,
    const size_t* proof_sizes,
    size_t proof_count)
{
    std::shared_lock<std::shared_mutex> lock(g_rpl_mutex);
    if (g_rpl == nullptr) return typed_err<BlsctBoolResult>(BLSCT_INIT_NOT_CALLED);
    if (proofs == nullptr || proof_sizes == nullptr || proof_count == 0) return typed_err<BlsctBoolResult>(BLSCT_FAILURE);
    try {
        std::vector<bulletproofs_plus::RangeProofWithSeed<Mcl>> range_proof_w_seeds;

        for (size_t i = 0; i < proof_count; ++i) {
            bulletproofs_plus::RangeProof<Mcl> rp;
            DataStream st{};
            for (size_t j = 0; j < proof_sizes[i]; ++j) {
                st << proofs[i][j];
            }
            rp.Unserialize(st);
            range_proof_w_seeds.push_back(bulletproofs_plus::RangeProofWithSeed<Mcl>(rp));
        }
        bool is_valid = g_rpl->Verify(range_proof_w_seeds);
        return succ_bool(is_valid);

    } catch (...) {
    }

    return typed_err<BlsctBoolResult>(BLSCT_EXCEPTION);
}

#define DEFINE_RANGE_PROOF_POINT_GETTER(field)                                                                        \
    BlsctPointResult get_range_proof_##field(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size) \
    {                                                                                                                 \
        bulletproofs_plus::RangeProof<Mcl> range_proof;                                                               \
        UNSERIALIZE_AND_COPY_WITH_STREAM(blsct_range_proof, range_proof_size, range_proof);                           \
        BlsctPointResult r{};                                                                                         \
        SERIALIZE_AND_COPY(range_proof.field, r.value);                                                               \
        r.result = BLSCT_SUCCESS;                                                                                     \
        return r;                                                                                                     \
    }

DEFINE_RANGE_PROOF_POINT_GETTER(A)
DEFINE_RANGE_PROOF_POINT_GETTER(A_wip)
DEFINE_RANGE_PROOF_POINT_GETTER(B)

#undef DEFINE_RANGE_PROOF_POINT_GETTER

#define DEFINE_RANGE_PROOF_SCALAR_GETTER(field)                                                                        \
    BlsctScalarResult get_range_proof_##field(const BlsctRangeProof* blsct_range_proof, const size_t range_proof_size) \
    {                                                                                                                  \
        bulletproofs_plus::RangeProof<Mcl> range_proof;                                                                \
        UNSERIALIZE_AND_COPY_WITH_STREAM(blsct_range_proof, range_proof_size, range_proof);                            \
        BlsctScalarResult r{};                                                                                         \
        SERIALIZE_AND_COPY(range_proof.field, r.value);                                                                \
        r.result = BLSCT_SUCCESS;                                                                                      \
        return r;                                                                                                      \
    }

DEFINE_RANGE_PROOF_SCALAR_GETTER(r_prime)
DEFINE_RANGE_PROOF_SCALAR_GETTER(s_prime)
DEFINE_RANGE_PROOF_SCALAR_GETTER(delta_prime)
DEFINE_RANGE_PROOF_SCALAR_GETTER(alpha_hat)
DEFINE_RANGE_PROOF_SCALAR_GETTER(tau_x)

#undef DEFINE_RANGE_PROOF_SCALAR_GETTER

BlsctSizeTResult serialize_range_proof(
    const BlsctRangeProof* blsct_range_proof,
    size_t range_proof_size,
    char* buf,
    size_t buf_size)
{
    if (blsct_range_proof == nullptr) return typed_err<BlsctSizeTResult>(BLSCT_FAILURE);
    return {BLSCT_SUCCESS, WriteHexBuf(reinterpret_cast<const uint8_t*>(blsct_range_proof), range_proof_size, buf, buf_size)};
}

BLSCT_RESULT deserialize_range_proof(
    const char* hex,
    const size_t range_proof_size,
    uint8_t* buf,
    size_t buf_size,
    size_t* out_len)
{
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec) || vec.size() != range_proof_size) {
        return BLSCT_BAD_SIZE;
    }
    if (out_len) *out_len = range_proof_size;
    if (buf != nullptr && buf_size >= range_proof_size)
        std::memcpy(buf, vec.data(), range_proof_size);
    return BLSCT_SUCCESS;
}


// scalar
BlsctScalarResult gen_random_scalar()
{
    BlsctScalarResult r{};
    auto x = Scalar::Rand(true);
    SERIALIZE_AND_COPY(x, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctScalarResult gen_scalar(
    const uint64_t n)
{
    BlsctScalarResult r{};
    Scalar scalar(n);
    SERIALIZE_AND_COPY(scalar, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctUint64Result scalar_to_uint64(const BlsctScalar* blsct_scalar)
{
    if (blsct_scalar == nullptr) return typed_err<BlsctUint64Result>(BLSCT_FAILURE);
    Scalar scalar;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_scalar, SCALAR_SIZE, scalar);
    return {BLSCT_SUCCESS, scalar.GetUint64()};
}

BlsctScalarHexResult serialize_scalar(const BlsctScalar* blsct_scalar)
{
    BlsctScalarHexResult r{};
    FillHexBuf((const uint8_t*)blsct_scalar, SCALAR_SIZE, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctScalarResult deserialize_scalar(const char* hex)
{
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec)) {
        return typed_err<BlsctScalarResult>(BLSCT_FAILURE);
    }
    Scalar scalar;
    scalar.SetVch(vec);

    BlsctScalarResult r{};
    SERIALIZE_AND_COPY(scalar, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

int are_scalar_equal(const BlsctScalar* blsct_a, const BlsctScalar* blsct_b)
{
    if (blsct_a == nullptr || blsct_b == nullptr) {
        return 0;
    }
    Scalar a, b;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_a, SCALAR_SIZE, a);
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_b, SCALAR_SIZE, b);
    return a == b ? 1 : 0;
}

BlsctSizeTResult scalar_to_str(const BlsctScalar* blsct_scalar, char* buf, size_t buf_size)
{
    if (blsct_scalar == nullptr) return typed_err<BlsctSizeTResult>(BLSCT_FAILURE);
    Scalar scalar;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_scalar, SCALAR_SIZE, scalar);
    return {BLSCT_SUCCESS, WriteStrBuf(scalar.GetString(10), buf, buf_size)};
}

BlsctPubKeyResult scalar_to_pub_key(
    const BlsctScalar* blsct_scalar)
{
    Scalar scalar;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
        blsct_scalar, SCALAR_SIZE, scalar);
    auto priv_key = blsct::PrivateKey(scalar);
    auto pub_key = priv_key.GetPublicKey();

    BlsctPubKeyResult r{};
    SERIALIZE_AND_COPY(pub_key, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

// script
BlsctScriptHexResult serialize_script(const BlsctScript* blsct_script)
{
    BlsctScriptHexResult r{};
    FillHexBuf((const uint8_t*)blsct_script, SCRIPT_SIZE, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctScriptResult deserialize_script(const char* hex)
{
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec) || vec.size() != SCRIPT_SIZE) {
        return typed_err<BlsctScriptResult>(BLSCT_BAD_SIZE);
    }
    BlsctScriptResult r{};
    std::memcpy(r.value, vec.data(), SCRIPT_SIZE);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctSignatureHexResult serialize_signature(const BlsctSignature* blsct_signature)
{
    BlsctSignatureHexResult r{};
    FillHexBuf((const uint8_t*)blsct_signature, SIGNATURE_SIZE, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctSignatureResult deserialize_signature(const char* hex)
{
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec) || vec.size() != SIGNATURE_SIZE) {
        return typed_err<BlsctSignatureResult>(BLSCT_BAD_SIZE);
    }
    BlsctSignatureResult r{};
    std::memcpy(r.value, vec.data(), SIGNATURE_SIZE);
    r.result = BLSCT_SUCCESS;
    return r;
}

// signature
BlsctSignatureResult sign_message(
    const BlsctScalar* blsct_priv_key,
    const char* blsct_msg)
{
    Scalar scalar_priv_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(
        blsct_priv_key, SCALAR_SIZE, scalar_priv_key);
    auto priv_key = blsct::PrivateKey(scalar_priv_key);

    std::string msg_str(blsct_msg);
    blsct::Message msg(msg_str.begin(), msg_str.end());
    blsct::Signature sig = priv_key.Sign(msg);

    BlsctSignatureResult r{};
    SERIALIZE_AND_COPY(sig, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

bool verify_msg_sig(
    const BlsctPubKey* blsct_pub_key,
    const char* blsct_msg,
    const BlsctSignature* blsct_signature)
{
    if (blsct_pub_key == nullptr || blsct_msg == nullptr || blsct_signature == nullptr) return false;
    blsct::PublicKey pub_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_pub_key, PUBLIC_KEY_SIZE, pub_key);

    std::string msg_str(blsct_msg);
    blsct::Message msg(msg_str.begin(), msg_str.end());

    blsct::Signature signature;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_signature, SIGNATURE_SIZE, signature);

    return pub_key.Verify(msg, signature);
}

// sub addr
BlsctSubAddrResult derive_sub_address(
    const BlsctScalar* blsct_view_key,
    const BlsctPubKey* blsct_spending_pub_key,
    const BlsctSubAddrId* blsct_sub_addr_id)
{
    Scalar view_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_view_key, SCALAR_SIZE, view_key);

    blsct::PublicKey spending_pub_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_spending_pub_key, PUBLIC_KEY_SIZE, spending_pub_key);

    blsct::SubAddressIdentifier sub_addr_id;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_sub_addr_id, SUB_ADDR_ID_SIZE, sub_addr_id);

    auto sub_addr = blsct::DeriveSubAddress(view_key, spending_pub_key, sub_addr_id);
    BlsctSubAddrResult r{};
    SERIALIZE_AND_COPY_WITH_STREAM(sub_addr, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctSubAddrHexResult serialize_sub_addr(const BlsctSubAddr* blsct_sub_addr)
{
    BlsctSubAddrHexResult r{};
    FillHexBuf((const uint8_t*)blsct_sub_addr, SUB_ADDR_SIZE, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctSubAddrResult deserialize_sub_addr(const char* hex)
{
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec) || vec.size() != SUB_ADDR_SIZE) {
        return typed_err<BlsctSubAddrResult>(BLSCT_BAD_SIZE);
    }
    BlsctSubAddrResult r{};
    std::memcpy(r.value, vec.data(), SUB_ADDR_SIZE);
    r.result = BLSCT_SUCCESS;
    return r;
}

// sub addr id
BlsctSubAddrIdResult gen_sub_addr_id(
    const int64_t account,
    const uint64_t address)
{
    blsct::SubAddressIdentifier sub_addr_id;
    sub_addr_id.account = account;
    sub_addr_id.address = address;

    BlsctSubAddrIdResult r{};
    SERIALIZE_AND_COPY_WITH_STREAM(sub_addr_id, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctSubAddrIdHexResult serialize_sub_addr_id(const BlsctSubAddrId* blsct_sub_addr_id)
{
    BlsctSubAddrIdHexResult r{};
    FillHexBuf((const uint8_t*)blsct_sub_addr_id, SUB_ADDR_ID_SIZE, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctSubAddrIdResult deserialize_sub_addr_id(const char* hex)
{
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec) || vec.size() != SUB_ADDR_ID_SIZE) {
        return typed_err<BlsctSubAddrIdResult>(BLSCT_BAD_SIZE);
    }
    BlsctSubAddrIdResult r{};
    std::memcpy(r.value, vec.data(), SUB_ADDR_ID_SIZE);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctInt64Result get_sub_addr_id_account(
    const BlsctSubAddrId* blsct_sub_addr_id)
{
    if (blsct_sub_addr_id == nullptr) return typed_err<BlsctInt64Result>(BLSCT_FAILURE);
    blsct::SubAddressIdentifier sub_addr_id;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_sub_addr_id, SUB_ADDR_ID_SIZE, sub_addr_id);
    return {BLSCT_SUCCESS, sub_addr_id.account};
}

BlsctUint64Result get_sub_addr_id_address(
    const BlsctSubAddrId* blsct_sub_addr_id)
{
    if (blsct_sub_addr_id == nullptr) return typed_err<BlsctUint64Result>(BLSCT_FAILURE);
    blsct::SubAddressIdentifier sub_addr_id;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_sub_addr_id, SUB_ADDR_ID_SIZE, sub_addr_id);
    return {BLSCT_SUCCESS, sub_addr_id.address};
}

// token id
BlsctTokenIdResult gen_token_id_with_token_and_subid(
    const uint64_t token,
    const uint64_t subid)
{
    uint256 token_uint256;
    auto data = token_uint256.data();
    uint64_t n = token;
    for (size_t i = 0; i < 8; i++) {
        data[i] = n & 0xFF;
        n >>= 8; // Shift the value right by 8 bits to process the next byte
    }
    TokenId token_id(token_uint256, subid);
    BlsctTokenIdResult r{};
    SERIALIZE_AND_COPY_WITH_STREAM(token_id, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctTokenIdResult gen_token_id(
    const uint64_t token)
{
    return gen_token_id_with_token_and_subid(
        token,
        UINT64_MAX);
}

BlsctTokenIdResult gen_default_token_id()
{
    TokenId token_id;
    BlsctTokenIdResult r{};
    SERIALIZE_AND_COPY_WITH_STREAM(token_id, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctUint64Result get_token_id_token(const BlsctTokenId* blsct_token_id)
{
    if (blsct_token_id == nullptr) return typed_err<BlsctUint64Result>(BLSCT_FAILURE);
    TokenId token_id;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_token_id, TOKEN_ID_SIZE, token_id);
    return {BLSCT_SUCCESS, token_id.token.GetUint64(0)};
}

BlsctUint64Result get_token_id_subid(const BlsctTokenId* blsct_token_id)
{
    if (blsct_token_id == nullptr) return typed_err<BlsctUint64Result>(BLSCT_FAILURE);
    TokenId token_id;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_token_id, TOKEN_ID_SIZE, token_id);
    return {BLSCT_SUCCESS, token_id.subid};
}

BlsctTokenIdHexResult serialize_token_id(const BlsctTokenId* blsct_token_id)
{
    BlsctTokenIdHexResult r{};
    FillHexBuf((const uint8_t*)blsct_token_id, TOKEN_ID_SIZE, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctTokenIdResult deserialize_token_id(const char* hex)
{
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec) || vec.size() != TOKEN_ID_SIZE) {
        return typed_err<BlsctTokenIdResult>(BLSCT_BAD_SIZE);
    }
    BlsctTokenIdResult r{};
    std::memcpy(r.value, vec.data(), TOKEN_ID_SIZE);
    r.result = BLSCT_SUCCESS;
    return r;
}

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
    size_t* out_len)
{
    if (blsct_public_key == nullptr) return BLSCT_FAILURE;

    CAmount supply;
    if (!AmountFromUint64Checked(total_supply, supply)) return BLSCT_VALUE_OUTSIDE_THE_RANGE;

    blsct::PublicKey public_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_public_key, PUBLIC_KEY_SIZE, public_key);

    blsct::TokenInfo token_info{TokenTypeFromC(type), public_key, StringMapFromArrays(metadata_keys, metadata_values, metadata_count), supply};
    size_t sz = SerializeObjToHexBuf(token_info, buf, buf_size);
    if (out_len) *out_len = sz;
    return BLSCT_SUCCESS;
}

BlsctTokenTypeResult get_token_info_type(const char* hex)
{
    if (hex == nullptr) return typed_err<BlsctTokenTypeResult>(BLSCT_FAILURE);
    auto info = DeserializeObj<blsct::TokenInfo>(hex);
    if (!info.has_value()) return typed_err<BlsctTokenTypeResult>(BLSCT_FAILURE);
    return {BLSCT_SUCCESS, TokenTypeToC(info->type)};
}

BlsctPubKeyResult get_token_info_public_key(const char* hex)
{
    auto info = DeserializeObj<blsct::TokenInfo>(hex);
    if (!info.has_value()) return typed_err<BlsctPubKeyResult>(BLSCT_FAILURE);
    BlsctPubKeyResult r{};
    SERIALIZE_AND_COPY(info->publicKey, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctUint64Result get_token_info_total_supply(const char* hex)
{
    auto info = DeserializeObj<blsct::TokenInfo>(hex);
    if (!info.has_value()) return typed_err<BlsctUint64Result>(BLSCT_FAILURE);
    return {BLSCT_SUCCESS, static_cast<uint64_t>(info->nTotalSupply)};
}

void get_token_info_metadata(const char* hex, BlsctStringMapCallback cb, void* user_data)
{
    auto info = DeserializeObj<blsct::TokenInfo>(hex);
    if (!info.has_value()) return;
    InvokeCallbackForMap(info->mapMetadata, cb, user_data);
}

// collection token hash and token key derivation
BlsctUint256Result calc_collection_token_hash(
    const char* const* metadata_keys,
    const char* const* metadata_values,
    size_t metadata_count,
    const uint64_t total_supply)
{
    CAmount supply;
    if (!AmountFromUint64Checked(total_supply, supply)) {
        return typed_err<BlsctUint256Result>(BLSCT_VALUE_OUTSIDE_THE_RANGE);
    }

    const uint256 hash = (HashWriter{} << StringMapFromArrays(metadata_keys, metadata_values, metadata_count) << supply).GetHash();
    return MallocAndCopyUint256(hash);
}

BlsctScalarResult derive_collection_token_key(
    const BlsctScalar* blsct_master_token_key,
    const BlsctUint256* blsct_collection_token_hash)
{
    if (blsct_master_token_key == nullptr) {
        return typed_err<BlsctScalarResult>(BLSCT_FAILURE);
    }
    if (blsct_collection_token_hash == nullptr) {
        return typed_err<BlsctScalarResult>(BLSCT_FAILURE);
    }

    Scalar master_token_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_master_token_key, SCALAR_SIZE, master_token_key);

    uint256 collection_hash;
    std::memcpy(collection_hash.begin(), blsct_collection_token_hash, UINT256_SIZE);

    Scalar token_key = BLS12_381_KeyGen::derive_child_SK_hash(master_token_key, collection_hash);
    BlsctScalarResult r{};
    SERIALIZE_AND_COPY(token_key, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctPubKeyResult derive_collection_token_public_key(
    const BlsctScalar* blsct_master_token_key,
    const BlsctUint256* blsct_collection_token_hash)
{
    auto token_key_rv = derive_collection_token_key(blsct_master_token_key, blsct_collection_token_hash);
    if (token_key_rv.result != BLSCT_SUCCESS) {
        return typed_err<BlsctPubKeyResult>(BLSCT_FAILURE);
    }

    return scalar_to_pub_key(&token_key_rv.value);
}

// tx_in
BlsctTxInResult build_tx_in(
    const uint64_t amount,
    const BlsctScalar* gamma,
    const BlsctScalar* spending_key,
    const BlsctTokenId* token_id,
    const BlsctOutPoint* out_point,
    const bool staked_commitment,
    const bool rbf)
{
    BlsctTxInResult r{};
    r.result = BLSCT_SUCCESS;
    r.value.amount = amount;
    BLSCT_COPY(gamma, r.value.gamma);
    BLSCT_COPY(spending_key, r.value.spending_key);
    BLSCT_COPY(token_id, r.value.token_id);
    BLSCT_COPY(out_point, r.value.out_point);
    r.value.staked_commitment = staked_commitment;
    r.value.rbf = rbf;
    return r;
}

BlsctUint64Result get_tx_in_amount(const BlsctTxInData* tx_in)
{
    if (tx_in == nullptr) return typed_err<BlsctUint64Result>(BLSCT_FAILURE);
    return {BLSCT_SUCCESS, tx_in->amount};
}

BlsctScalarResult get_tx_in_gamma(const BlsctTxInData* tx_in)
{
    if (tx_in == nullptr) return typed_err<BlsctScalarResult>(BLSCT_FAILURE);
    BlsctScalarResult r{};
    r.result = BLSCT_SUCCESS;
    BLSCT_COPY(tx_in->gamma, r.value);
    return r;
}

BlsctScalarResult get_tx_in_spending_key(const BlsctTxInData* tx_in)
{
    if (tx_in == nullptr) return typed_err<BlsctScalarResult>(BLSCT_FAILURE);
    BlsctScalarResult r{};
    r.result = BLSCT_SUCCESS;
    BLSCT_COPY(tx_in->spending_key, r.value);
    return r;
}

BlsctTokenIdResult get_tx_in_token_id(const BlsctTxInData* tx_in)
{
    if (tx_in == nullptr) return typed_err<BlsctTokenIdResult>(BLSCT_FAILURE);
    BlsctTokenIdResult r{};
    r.result = BLSCT_SUCCESS;
    BLSCT_COPY(tx_in->token_id, r.value);
    return r;
}

BlsctOutPointResult get_tx_in_out_point(const BlsctTxInData* tx_in)
{
    if (tx_in == nullptr) return typed_err<BlsctOutPointResult>(BLSCT_FAILURE);
    BlsctOutPointResult r{};
    r.result = BLSCT_SUCCESS;
    BLSCT_COPY(tx_in->out_point, r.value);
    return r;
}

BlsctBoolResult get_tx_in_staked_commitment(const BlsctTxInData* tx_in)
{
    if (tx_in == nullptr) return typed_err<BlsctBoolResult>(BLSCT_FAILURE);
    return {BLSCT_SUCCESS, tx_in->staked_commitment};
}

BlsctBoolResult get_tx_in_rbf(const BlsctTxInData* tx_in)
{
    if (tx_in == nullptr) return typed_err<BlsctBoolResult>(BLSCT_FAILURE);
    return {BLSCT_SUCCESS, tx_in->rbf};
}

// tx out
BlsctTxOutResult build_tx_out(
    const BlsctSubAddr* blsct_dest,
    const uint64_t amount,
    const char* memo_c_str,
    const BlsctTokenId* blsct_token_id,
    const TxOutputType output_type,
    const uint64_t min_stake,
    const bool subtract_fee_from_amount,
    const BlsctScalar* blsct_blinding_key)
{
    if (blsct_dest == nullptr || memo_c_str == nullptr || blsct_token_id == nullptr || blsct_blinding_key == nullptr)
        return typed_err<BlsctTxOutResult>(BLSCT_FAILURE);
    size_t memo_c_str_len = std::strlen(memo_c_str);
    if (memo_c_str_len > MAX_MEMO_LEN) {
        return typed_err<BlsctTxOutResult>(BLSCT_MEMO_TOO_LONG);
    }

    BlsctTxOutResult r{};
    r.result = BLSCT_SUCCESS;
    BLSCT_COPY(blsct_dest, r.value.dest);
    r.value.amount = amount;
    std::memcpy(r.value.memo_c_str, memo_c_str, memo_c_str_len);
    r.value.memo_c_str[memo_c_str_len] = '\0';
    BLSCT_COPY(blsct_token_id, r.value.token_id);
    r.value.output_type = output_type;
    r.value.min_stake = min_stake;
    r.value.subtract_fee_from_amount = subtract_fee_from_amount;
    BLSCT_COPY(blsct_blinding_key, r.value.blinding_key);
    return r;
}

BlsctSubAddrResult get_tx_out_destination(const BlsctTxOutData* tx_out)
{
    if (tx_out == nullptr) return typed_err<BlsctSubAddrResult>(BLSCT_FAILURE);
    BlsctSubAddrResult r{};
    r.result = BLSCT_SUCCESS;
    BLSCT_COPY(tx_out->dest, r.value);
    return r;
}

BlsctUint64Result get_tx_out_amount(const BlsctTxOutData* tx_out)
{
    if (tx_out == nullptr) return typed_err<BlsctUint64Result>(BLSCT_FAILURE);
    return {BLSCT_SUCCESS, tx_out->amount};
}

BlsctStrResult get_tx_out_memo(const BlsctTxOutData* tx_out)
{
    if (tx_out == nullptr) return typed_err<BlsctStrResult>(BLSCT_FAILURE);
    return {BLSCT_SUCCESS, tx_out->memo_c_str};
}

BlsctTokenIdResult get_tx_out_token_id(const BlsctTxOutData* tx_out)
{
    if (tx_out == nullptr) return typed_err<BlsctTokenIdResult>(BLSCT_FAILURE);
    BlsctTokenIdResult r{};
    r.result = BLSCT_SUCCESS;
    BLSCT_COPY(tx_out->token_id, r.value);
    return r;
}

BlsctTxOutputTypeResult get_tx_out_output_type(const BlsctTxOutData* tx_out)
{
    if (tx_out == nullptr) return typed_err<BlsctTxOutputTypeResult>(BLSCT_FAILURE);
    return {BLSCT_SUCCESS, tx_out->output_type};
}

BlsctUint64Result get_tx_out_min_stake(const BlsctTxOutData* tx_out)
{
    if (tx_out == nullptr) return typed_err<BlsctUint64Result>(BLSCT_FAILURE);
    return {BLSCT_SUCCESS, tx_out->min_stake};
}

BlsctBoolResult get_tx_out_subtract_fee_from_amount(const BlsctTxOutData* tx_out)
{
    if (tx_out == nullptr) return typed_err<BlsctBoolResult>(BLSCT_FAILURE);
    return {BLSCT_SUCCESS, tx_out->subtract_fee_from_amount};
}

BlsctScalarResult get_tx_out_blinding_key(const BlsctTxOutData* tx_out)
{
    if (tx_out == nullptr) return typed_err<BlsctScalarResult>(BLSCT_FAILURE);
    BlsctScalarResult r{};
    r.result = BLSCT_SUCCESS;
    BLSCT_COPY(tx_out->blinding_key, r.value);
    return r;
}

// unsigned input/output/transaction helpers
BLSCT_RESULT build_unsigned_input(const BlsctTxInData* tx_in, char* buf, size_t buf_size, size_t* out_len)
{
    if (tx_in == nullptr) return BLSCT_FAILURE;
    auto input = UnsignedInputFromC(*tx_in);
    if (!input.has_value()) return BLSCT_VALUE_OUTSIDE_THE_RANGE;
    size_t sz = SerializeObjToHexBuf(input.value(), buf, buf_size);
    if (out_len) *out_len = sz;
    return BLSCT_SUCCESS;
}

BLSCT_RESULT build_unsigned_output(const BlsctTxOutData* tx_out, char* buf, size_t buf_size, size_t* out_len)
{
    if (tx_out == nullptr) return BLSCT_FAILURE;
    auto output = UnsignedOutputFromC(*tx_out);
    if (!output.has_value()) return BLSCT_BAD_OUT_TYPE;
    size_t sz = SerializeObjToHexBuf(output.value(), buf, buf_size);
    if (out_len) *out_len = sz;
    return BLSCT_SUCCESS;
}

BLSCT_RESULT build_unsigned_create_token_output(
    const BlsctScalar* blsct_token_key,
    const char* token_info_hex,
    char* buf,
    size_t buf_size,
    size_t* out_len)
{
    if (blsct_token_key == nullptr) return BLSCT_FAILURE;
    if (token_info_hex == nullptr) return BLSCT_FAILURE;
    auto token_info = DeserializeObj<blsct::TokenInfo>(token_info_hex);
    if (!token_info.has_value()) return BLSCT_DESER_FAILED;
    Scalar token_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_token_key, SCALAR_SIZE, token_key);
    blsct::UnsignedOutput unsigned_output(blsct::CreateOutput(token_key, *token_info));
    size_t sz = SerializeObjToHexBuf(unsigned_output, buf, buf_size);
    if (out_len) *out_len = sz;
    return BLSCT_SUCCESS;
}

BLSCT_RESULT build_unsigned_mint_token_output(
    const BlsctSubAddr* blsct_dest,
    const uint64_t amount,
    const BlsctScalar* blsct_blinding_key,
    const BlsctScalar* blsct_token_key,
    const BlsctPubKey* blsct_token_public_key,
    char* buf,
    size_t buf_size,
    size_t* out_len)
{
    if (blsct_dest == nullptr) return BLSCT_FAILURE;
    if (blsct_blinding_key == nullptr) return BLSCT_FAILURE;
    if (blsct_token_key == nullptr) return BLSCT_FAILURE;
    if (blsct_token_public_key == nullptr) return BLSCT_FAILURE;

    CAmount mint_amount;
    if (!AmountFromUint64Checked(amount, mint_amount)) return BLSCT_VALUE_OUTSIDE_THE_RANGE;

    blsct::SubAddress destination;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_dest, SUB_ADDR_SIZE, destination);

    Scalar blinding_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_blinding_key, SCALAR_SIZE, blinding_key);

    Scalar token_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_token_key, SCALAR_SIZE, token_key);

    blsct::PublicKey token_public_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_token_public_key, PUBLIC_KEY_SIZE, token_public_key);

    blsct::UnsignedOutput unsigned_output(
        blsct::CreateOutput(destination.GetKeys(), mint_amount, blinding_key, token_key, token_public_key));
    size_t sz = SerializeObjToHexBuf(unsigned_output, buf, buf_size);
    if (out_len) *out_len = sz;
    return BLSCT_SUCCESS;
}

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
    size_t* out_len)
{
    if (blsct_dest == nullptr) return BLSCT_FAILURE;
    if (blsct_blinding_key == nullptr) return BLSCT_FAILURE;
    if (blsct_token_key == nullptr) return BLSCT_FAILURE;
    if (blsct_token_public_key == nullptr) return BLSCT_FAILURE;

    blsct::SubAddress destination;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_dest, SUB_ADDR_SIZE, destination);

    Scalar blinding_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_blinding_key, SCALAR_SIZE, blinding_key);

    Scalar token_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_token_key, SCALAR_SIZE, token_key);

    blsct::PublicKey token_public_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_token_public_key, PUBLIC_KEY_SIZE, token_public_key);

    blsct::UnsignedOutput unsigned_output(
        blsct::CreateOutput(destination.GetKeys(), blinding_key, token_key, token_public_key, nft_id, StringMapFromArrays(metadata_keys, metadata_values, metadata_count)));
    size_t sz = SerializeObjToHexBuf(unsigned_output, buf, buf_size);
    if (out_len) *out_len = sz;
    return BLSCT_SUCCESS;
}

BLSCT_RESULT sign_unsigned_transaction(
    const char* const* input_hexes, size_t n_inputs,
    const char* const* output_hexes, size_t n_outputs,
    uint64_t fee,
    char* buf, size_t buf_size, size_t* out_len)
{
    try {
        blsct::UnsignedTransaction utx;

        CAmount tx_fee;
        if (!AmountFromUint64Checked(fee, tx_fee)) return BLSCT_FAILURE;
        utx.SetFee(tx_fee);

        for (size_t i = 0; i < n_inputs; ++i) {
            if (input_hexes == nullptr || input_hexes[i] == nullptr) return BLSCT_FAILURE;
            auto input = DeserializeObj<blsct::UnsignedInput>(input_hexes[i]);
            if (!input.has_value()) return BLSCT_DESER_FAILED;
            utx.AddInput(*input);
        }

        for (size_t i = 0; i < n_outputs; ++i) {
            if (output_hexes == nullptr || output_hexes[i] == nullptr) return BLSCT_FAILURE;
            auto output = DeserializeObj<blsct::UnsignedOutput>(output_hexes[i]);
            if (!output.has_value()) return BLSCT_DESER_FAILED;
            utx.AddOutput(*output);
        }

        auto signed_tx = utx.Sign();
        if (!signed_tx.has_value()) return BLSCT_FAILURE;

        DataStream st{};
        TransactionSerParams params{.allow_witness = true};
        ParamsStream ps{params, st};

        CMutableTransaction mutable_tx(signed_tx.value());
        mutable_tx.Serialize(ps);

        const auto hex = HexStr(st);
        if (out_len != nullptr) *out_len = hex.size();
        WriteStrBuf(hex, buf, buf_size);
        return BLSCT_SUCCESS;
    } catch (const std::exception&) {
        return BLSCT_EXCEPTION;
    }
}

// vector predicate
int are_vector_predicate_equal(
    const BlsctVectorPredicate* a,
    const size_t a_size,
    const BlsctVectorPredicate* b,
    const size_t b_size)
{
    if (a_size != b_size) {
        return 0;
    }
    for (size_t i = 0; i < a_size; ++i) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

BlsctSizeTResult serialize_vector_predicate(
    const BlsctVectorPredicate* blsct_vector_predicate,
    size_t obj_size,
    char* buf,
    size_t buf_size)
{
    if (blsct_vector_predicate == nullptr) return typed_err<BlsctSizeTResult>(BLSCT_FAILURE);
    return {BLSCT_SUCCESS, WriteHexBuf(reinterpret_cast<const uint8_t*>(blsct_vector_predicate), obj_size, buf, buf_size)};
}

BLSCT_RESULT deserialize_vector_predicate(
    const char* hex,
    uint8_t* buf,
    size_t buf_size,
    size_t* out_len)
{
    std::vector<uint8_t> vec;
    if (!TryParseHexWrap(hex, vec)) return BLSCT_FAILURE;
    if (out_len) *out_len = vec.size();
    if (buf != nullptr && buf_size >= vec.size())
        std::memcpy(buf, vec.data(), vec.size());
    return BLSCT_SUCCESS;
}

BlsctPredicateTypeResult get_vector_predicate_type(
    const BlsctVectorPredicate* blsct_vector_predicate,
    size_t obj_size)
{
    if (blsct_vector_predicate == nullptr) return typed_err<BlsctPredicateTypeResult>(BLSCT_FAILURE);
    auto predicate = ParseOpaquePredicate(blsct_vector_predicate, obj_size);
    if (!predicate.has_value()) return typed_err<BlsctPredicateTypeResult>(BLSCT_FAILURE);
    return {BLSCT_SUCCESS, PredicateTypeToC(predicate.value())};
}

BLSCT_RESULT build_create_token_predicate(
    const char* token_info_hex,
    uint8_t* buf,
    size_t buf_size,
    size_t* out_len)
{
    if (token_info_hex == nullptr) return BLSCT_FAILURE;
    auto token_info = DeserializeObj<blsct::TokenInfo>(token_info_hex);
    if (!token_info.has_value()) return BLSCT_DESER_FAILED;
    auto predicate = blsct::CreateTokenPredicate(*token_info).GetVch();
    if (out_len) *out_len = predicate.size();
    if (buf != nullptr && buf_size >= predicate.size())
        std::memcpy(buf, predicate.data(), predicate.size());
    return BLSCT_SUCCESS;
}

BLSCT_RESULT build_mint_token_predicate(
    const BlsctPubKey* blsct_token_public_key,
    const uint64_t amount,
    uint8_t* buf,
    size_t buf_size,
    size_t* out_len)
{
    if (blsct_token_public_key == nullptr) return BLSCT_FAILURE;

    CAmount mint_amount;
    if (!AmountFromUint64Checked(amount, mint_amount)) return BLSCT_VALUE_OUTSIDE_THE_RANGE;

    blsct::PublicKey token_public_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_token_public_key, PUBLIC_KEY_SIZE, token_public_key);
    auto predicate = blsct::MintTokenPredicate(token_public_key, mint_amount).GetVch();
    if (out_len) *out_len = predicate.size();
    if (buf != nullptr && buf_size >= predicate.size())
        std::memcpy(buf, predicate.data(), predicate.size());
    return BLSCT_SUCCESS;
}

BLSCT_RESULT build_mint_nft_predicate(
    const BlsctPubKey* blsct_token_public_key,
    const uint64_t nft_id,
    const char* const* metadata_keys,
    const char* const* metadata_values,
    size_t metadata_count,
    uint8_t* buf,
    size_t buf_size,
    size_t* out_len)
{
    if (blsct_token_public_key == nullptr) return BLSCT_FAILURE;

    blsct::PublicKey token_public_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_token_public_key, PUBLIC_KEY_SIZE, token_public_key);
    auto predicate = blsct::MintNftPredicate(token_public_key, nft_id, StringMapFromArrays(metadata_keys, metadata_values, metadata_count)).GetVch();
    if (out_len) *out_len = predicate.size();
    if (buf != nullptr && buf_size >= predicate.size())
        std::memcpy(buf, predicate.data(), predicate.size());
    return BLSCT_SUCCESS;
}

BLSCT_RESULT get_create_token_predicate_token_info(
    const BlsctVectorPredicate* blsct_vector_predicate,
    size_t obj_size,
    char* buf,
    size_t buf_size,
    size_t* out_len)
{
    auto predicate = ParseOpaquePredicate(blsct_vector_predicate, obj_size);
    if (!predicate.has_value() || !predicate->IsCreateTokenPredicate()) return BLSCT_FAILURE;
    auto token_info = predicate->GetTokenInfo();
    size_t sz = SerializeObjToHexBuf(token_info, buf, buf_size);
    if (out_len) *out_len = sz;
    return BLSCT_SUCCESS;
}

BlsctPubKeyResult get_mint_token_predicate_public_key(
    const BlsctVectorPredicate* blsct_vector_predicate,
    size_t obj_size)
{
    auto predicate = ParseOpaquePredicate(blsct_vector_predicate, obj_size);
    if (!predicate.has_value() || !predicate->IsMintTokenPredicate()) {
        return typed_err<BlsctPubKeyResult>(BLSCT_FAILURE);
    }

    BlsctPubKeyResult r{};
    SERIALIZE_AND_COPY(predicate->GetPublicKey(), r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctUint64Result get_mint_token_predicate_amount(
    const BlsctVectorPredicate* blsct_vector_predicate,
    size_t obj_size)
{
    auto predicate = ParseOpaquePredicate(blsct_vector_predicate, obj_size);
    if (!predicate.has_value() || !predicate->IsMintTokenPredicate())
        return typed_err<BlsctUint64Result>(BLSCT_FAILURE);
    return {BLSCT_SUCCESS, static_cast<uint64_t>(predicate->GetAmount())};
}

BlsctPubKeyResult get_mint_nft_predicate_public_key(
    const BlsctVectorPredicate* blsct_vector_predicate,
    size_t obj_size)
{
    auto predicate = ParseOpaquePredicate(blsct_vector_predicate, obj_size);
    if (!predicate.has_value() || !predicate->IsMintNftPredicate()) {
        return typed_err<BlsctPubKeyResult>(BLSCT_FAILURE);
    }

    BlsctPubKeyResult r{};
    SERIALIZE_AND_COPY(predicate->GetPublicKey(), r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctUint64Result get_mint_nft_predicate_nft_id(
    const BlsctVectorPredicate* blsct_vector_predicate,
    size_t obj_size)
{
    auto predicate = ParseOpaquePredicate(blsct_vector_predicate, obj_size);
    if (!predicate.has_value() || !predicate->IsMintNftPredicate())
        return typed_err<BlsctUint64Result>(BLSCT_FAILURE);
    return {BLSCT_SUCCESS, predicate->GetNftId()};
}

void get_mint_nft_predicate_metadata(
    const BlsctVectorPredicate* blsct_vector_predicate,
    size_t obj_size,
    BlsctStringMapCallback cb,
    void* user_data)
{
    auto predicate = ParseOpaquePredicate(blsct_vector_predicate, obj_size);
    if (!predicate.has_value() || !predicate->IsMintNftPredicate()) return;
    InvokeCallbackForMap(predicate->GetNftMetaData(), cb, user_data);
}

// key derivation functions

BlsctScalarResult from_seed_to_child_key(
    const BlsctScalar* blsct_seed)
{
    if (blsct_seed == nullptr)
        return typed_err<BlsctScalarResult>(BLSCT_FAILURE);

    Scalar seed;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_seed, SCALAR_SIZE, seed);

    auto child_key = blsct::FromSeedToChildKey(seed);
    BlsctScalarResult r{};
    SERIALIZE_AND_COPY(child_key, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctScalarResult from_child_key_to_blinding_key(
    const BlsctScalar* blsct_child_key)
{
    if (blsct_child_key == nullptr)
        return typed_err<BlsctScalarResult>(BLSCT_FAILURE);

    Scalar child_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_child_key, SCALAR_SIZE, child_key);

    Scalar blinding_key = blsct::FromChildToBlindingKey(child_key);
    BlsctScalarResult r{};
    SERIALIZE_AND_COPY(blinding_key, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctScalarResult from_child_key_to_token_key(
    const BlsctScalar* blsct_child_key)
{
    if (blsct_child_key == nullptr)
        return typed_err<BlsctScalarResult>(BLSCT_FAILURE);

    Scalar child_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_child_key, SCALAR_SIZE, child_key);

    auto token_key = blsct::FromChildToTokenKey(child_key);
    BlsctScalarResult r{};
    SERIALIZE_AND_COPY(token_key, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctScalarResult from_child_key_to_tx_key(
    const BlsctScalar* blsct_child_key)
{
    if (blsct_child_key == nullptr)
        return typed_err<BlsctScalarResult>(BLSCT_FAILURE);

    Scalar child_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_child_key, SCALAR_SIZE, child_key);

    auto tx_key = blsct::FromChildToTransactionKey(child_key);
    BlsctScalarResult r{};
    SERIALIZE_AND_COPY(tx_key, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctScalarResult from_tx_key_to_view_key(
    const BlsctScalar* blsct_tx_key)
{
    if (blsct_tx_key == nullptr)
        return typed_err<BlsctScalarResult>(BLSCT_FAILURE);

    Scalar tx_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_tx_key, SCALAR_SIZE, tx_key);

    auto view_key = blsct::FromTransactionToViewKey(tx_key);
    BlsctScalarResult r{};
    SERIALIZE_AND_COPY(view_key, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctScalarResult from_tx_key_to_spending_key(
    const BlsctScalar* blsct_tx_key)
{
    if (blsct_tx_key == nullptr)
        return typed_err<BlsctScalarResult>(BLSCT_FAILURE);

    Scalar tx_key;
    UNSERIALIZE_FROM_BYTE_ARRAY_WITH_STREAM(blsct_tx_key, SCALAR_SIZE, tx_key);

    auto spending_key = blsct::FromTransactionToSpendKey(tx_key);
    BlsctScalarResult r{};
    SERIALIZE_AND_COPY(spending_key, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

BlsctScalarResult calc_priv_spending_key(
    const BlsctPubKey* blsct_blinding_pub_key,
    const BlsctScalar* blsct_view_key,
    const BlsctScalar* blsct_spending_key,
    const int64_t account,
    const uint64_t address)
{
    if (blsct_blinding_pub_key == nullptr || blsct_view_key == nullptr || blsct_spending_key == nullptr)
        return typed_err<BlsctScalarResult>(BLSCT_FAILURE);

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
        address);
    BlsctScalarResult r{};
    SERIALIZE_AND_COPY(priv_spending_key, r.value);
    r.result = BLSCT_SUCCESS;
    return r;
}

// Misc helper functions

size_t buf_to_hex(const uint8_t* buf, size_t size, char* out, size_t out_size)
{
    return WriteHexBuf(buf, size, out, out_size);
}
