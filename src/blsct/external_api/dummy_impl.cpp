// Copyright (c) 2024 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Dummy implementations of functions required for runtime linking
// but not actually used by any of the BLSCT external API functions

#include <uint256.h>
#include <util/fs.h>
#include <blsct/double_public_key.h>

#include <chrono>
#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

#define NOT_IMPL { throw std::runtime_error("Not implemented"); }

struct bilingual_str {};
struct CBaseChainParams;
struct CExtPubKey;
struct CFeeRate;
struct CChainParams;
struct ChainType {};
struct CMutableTransaction {};
struct CNoDestination {};
struct Coin;
struct COutPoint;
struct CRPCCommand {};
struct CScript {};
struct CScriptID {};
struct CTransaction;
struct CTxOut;
struct CTxUndo;
struct Descriptor;
struct ExtPubKeyMap {};
struct FeeEstimateMode;
struct FeeReason {};
struct FillableSigningProvider;
struct FlatSigningProvider;
struct Handler {};
struct OutputType {};
struct Params {};
struct PartiallySignedTransaction;
struct PKHash;
struct PrecomputedTransactionData {};
struct PubKeyDestination {};
struct SigningProvider;
struct SigningRequest;
struct SigningResult {};
struct SignatureData;
struct TransactionError {};
struct TxoutType {};
struct TxVerbosity {};
struct UniValue {};
struct WitnessV1Taproot {};
struct WitnessUnknown {};

typedef int64_t CAmount;

namespace blsct {
    struct TokenEntry;
} // namescape blsct

const size_t AES256_KEYSIZE = 0;
const size_t AES_BLOCKSIZE = 0;
const size_t OUTPUT_SIZE = 0;

///

std::string WriteHDKeypath(const std::vector<uint32_t>& keypath, bool apostrophe) NOT_IMPL

struct WitnessV0ScriptHash {
    explicit WitnessV0ScriptHash(const CScript& script);
};
WitnessV0ScriptHash::WitnessV0ScriptHash(const CScript& script) NOT_IMPL

struct WitnessV0KeyHash {
    WitnessV0KeyHash();
    explicit WitnessV0KeyHash(const CPubKey& pubkey);
};
WitnessV0KeyHash::WitnessV0KeyHash() {}
WitnessV0KeyHash::WitnessV0KeyHash(const CPubKey& pubkey) {}

UniValue ValueFromAmount(const CAmount amount) NOT_IMPL

void UpdatePSBTOutput(const SigningProvider& provider, PartiallySignedTransaction& psbt, int index) NOT_IMPL

void TxToUniv(const CTransaction& tx, const uint256& block_hash, UniValue& entry, bool include_hex, const CTxUndo* txundo, TxVerbosity verbosity, bool extendedRangeProof) NOT_IMPL

bool TryCreateDirectories(const fs::path& p) NOT_IMPL

bilingual_str TransactionErrorString(const TransactionError err) NOT_IMPL

CKeyID ToKeyID(const PKHash& key_hash) NOT_IMPL
CKeyID ToKeyID(const WitnessV0KeyHash& key_hash) NOT_IMPL

std::string StringForFeeReason(FeeReason reason) NOT_IMPL

std::string StrFormatInternalBug(std::string_view msg, std::string_view file, int line, std::string_view func) NOT_IMPL

TxoutType Solver(const CScript& scriptPubKey, std::vector<std::vector<unsigned char>>& vSolutionsRet) NOT_IMPL

uint64_t SipHashUint256(uint64_t k0, uint64_t k1, const uint256& val) NOT_IMPL

uint64_t SipHashUint256Extra(uint64_t k0, uint64_t k1, const uint256& val, uint32_t extra) NOT_IMPL

std::string SigningResultString(const SigningResult res) NOT_IMPL

void SignTransactionResultToJSON(CMutableTransaction& mtx, bool complete, const std::map<COutPoint, Coin>& coins, const std::map<int, bilingual_str>& input_errors, UniValue& result) NOT_IMPL

bool SignPSBTInput(const SigningProvider& provider, PartiallySignedTransaction& psbt, int index, const PrecomputedTransactionData* txdata, int sighash,  SignatureData* out_sigdata, bool finalize) NOT_IMPL

namespace util {
    template <typename T>
    struct Result {};
} // namespace util
util::Result<int> SighashFromStr(const std::string& sighash) NOT_IMPL

struct ScriptHash {
    explicit ScriptHash(const CScript& script);
    explicit ScriptHash(const CScriptID& script);
};
ScriptHash::ScriptHash(const CScript& script) NOT_IMPL
ScriptHash::ScriptHash(const CScriptID& script) NOT_IMPL

CScriptID ToScriptID(const ScriptHash& script_hash) NOT_IMPL

struct SaltedTxidHasher {
    SaltedTxidHasher();
};
SaltedTxidHasher::SaltedTxidHasher() NOT_IMPL

struct SaltedSipHasher {
    SaltedSipHasher();
    size_t operator()(const Span<const unsigned char>& script) const;
};
SaltedSipHasher::SaltedSipHasher() NOT_IMPL
size_t SaltedSipHasher::operator()(const Span<const unsigned char>& script) const NOT_IMPL

struct SaltedOutpointHasher {
    SaltedOutpointHasher(bool deterministic = false);
};
SaltedOutpointHasher::SaltedOutpointHasher(bool deterministic) NOT_IMPL

bool RenameOver(fs::path src, fs::path dest) NOT_IMPL

void RemoveUnnecessaryTransactions(PartiallySignedTransaction& psbtx, const int& sighash_type) NOT_IMPL

PrecomputedTransactionData PrecomputePSBTData(const PartiallySignedTransaction& psbt) NOT_IMPL

void ParsePrevouts(const UniValue& prevTxsUnival, FillableSigningProvider* keystore, std::map<COutPoint, Coin>& coins) NOT_IMPL

bool ParseHDKeypath(const std::string& keypath_str, std::vector<uint32_t>& keypath) NOT_IMPL

std::unique_ptr<Descriptor> Parse(const std::string& descriptor, FlatSigningProvider& out, std::string& error, bool require_checksum) NOT_IMPL

struct PSBTInput {
    void FillSignatureData(SignatureData& sigdata) const;
};
void PSBTInput::FillSignatureData(SignatureData& sigdata) const NOT_IMPL

bool PSBTInputSigned(const PSBTInput& input) NOT_IMPL

struct PKHash {
    explicit PKHash(const CPubKey& pubkey);
    explicit PKHash(const CKeyID& pubkey_id);
};
PKHash::PKHash(const CPubKey& pubkey) {}
PKHash::PKHash(const CKeyID& pubkey_id) {}

using CTxDestination = std::variant<CNoDestination, PubKeyDestination, PKHash, ScriptHash, WitnessV0ScriptHash, WitnessV0KeyHash, WitnessV1Taproot, WitnessUnknown, blsct::DoublePublicKey>;

struct NonFatalCheckError {
    NonFatalCheckError(std::string_view msg, std::string_view file, int line, std::string_view func);
};
NonFatalCheckError::NonFatalCheckError(std::string_view msg, std::string_view file, int line, std::string_view func) NOT_IMPL

bool MessageSign(const CKey& privkey, const std::string& message, std::string& signature) NOT_IMPL

bool IsValidDestination(const CTxDestination& dest) NOT_IMPL

bool IsDust(const CTxOut& txout, const CFeeRate& dustRelayFeeIn) NOT_IMPL

std::string InvalidEstimateModeErrorMessage() NOT_IMPL

std::unique_ptr<Descriptor> InferDescriptor(const CScript& script, const SigningProvider& provider) NOT_IMPL

int64_t GetVirtualTransactionSize(int64_t nWeight, int64_t nSigOpCost, unsigned int bytes_per_sigop) NOT_IMPL

int64_t GetVirtualTransactionSize(const CTransaction& tx, int64_t nSigOpCost, unsigned int bytes_per_sigop) NOT_IMPL

std::string GetTxnOutputType(TxoutType t) NOT_IMPL

void GetStrongRandBytes(Span<unsigned char> bytes) noexcept {}

CScript GetScriptForRawPubKey(const CPubKey& pubKey) NOT_IMPL

CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys) NOT_IMPL

CScript GetScriptForDestination(const CTxDestination& dest) NOT_IMPL

CAmount GetDustThreshold(const CTxOut& txout, const CFeeRate& dustRelayFeeIn) NOT_IMPL

CKey GenerateRandomKey(bool compressed) noexcept { return CKey(); }

std::string FormatHDKeypath(const std::vector<uint32_t>& path, bool apostrophe) NOT_IMPL

bool FinalizePSBT(PartiallySignedTransaction& psbtx) NOT_IMPL

bool FinalizeAndExtractPSBT(PartiallySignedTransaction& psbtx, CMutableTransaction& result) NOT_IMPL

std::string FeeModes(const std::string& delimiter) NOT_IMPL

bool FeeModeFromString(const std::string& mode_string, FeeEstimateMode& fee_estimate_mode) NOT_IMPL

struct FastRandomContext {
    void RandomSeed();
    explicit FastRandomContext(bool fDeterministic = false) noexcept;
};
void FastRandomContext::RandomSeed() NOT_IMPL
FastRandomContext::FastRandomContext(bool fDeterministic) noexcept {}

bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet) NOT_IMPL

std::string EncodeHexTx(const CTransaction& tx) NOT_IMPL

uint256 DescriptorID(const Descriptor& desc) NOT_IMPL

bool DecodeHexTx(CMutableTransaction& tx, const std::string& hex_tx, bool try_no_witness, bool try_witness) NOT_IMPL

bool DecodeBase64PSBT(PartiallySignedTransaction& psbt, const std::string& base64_tx, std::string& error) NOT_IMPL

CMutableTransaction ConstructTransaction(const UniValue& inputs_in, const UniValue& outputs_in, const UniValue& locktime, std::optional<bool> rbf) NOT_IMPL

struct arith_uint256 {
    arith_uint256& SetCompact(uint32_t nCompact, bool* pfNegative, bool* pfOverflow);
    uint32_t GetCompact(bool fNegative) const;
};
arith_uint256& arith_uint256::SetCompact(uint32_t nCompact, bool* pfNegative, bool* pfOverflow) NOT_IMPL
uint32_t arith_uint256::GetCompact(bool fNegative) const NOT_IMPL

arith_uint256 UintToArith256(const uint256 &a) NOT_IMPL

void assertion_fail(std::string_view file, int line, std::string_view func, std::string_view assertion) NOT_IMPL

namespace fsbridge {
fs::path AbsPathJoin(const fs::path& base, const fs::path& path) NOT_IMPL
std::string get_filesystem_error_message(const fs::filesystem_error& e) NOT_IMPL
} // namespace fsbridge

namespace boost {
namespace signals2 {
struct connection {};
} // namespace signals2
} // namespace boost

namespace interfaces {
std::unique_ptr<Handler> MakeSignalHandler(boost::signals2::connection connection) NOT_IMPL
std::unique_ptr<Handler> MakeCleanupHandler(std::function<void()> cleanup) NOT_IMPL
} // namespace interfaces

template<unsigned int BITS>
struct base_uint {
    int CompareTo(const base_uint<BITS>& other) const;
    base_uint<BITS>& operator*=(unsigned int);
    base_uint<BITS>& operator/=(const base_uint<BITS>&);;
};
template<> int base_uint<256>::CompareTo(base_uint<256> const&) const NOT_IMPL
template<> base_uint<256>& base_uint<256>::operator*=(unsigned int) NOT_IMPL
template<> base_uint<256>& base_uint<256>::operator/=(base_uint<256> const&) NOT_IMPL

struct PartiallySignedTransaction {
    PartiallySignedTransaction(const CMutableTransaction& tx);
    uint32_t GetVersion() const;
};
PartiallySignedTransaction::PartiallySignedTransaction(const CMutableTransaction& tx) {}
uint32_t PartiallySignedTransaction::GetVersion() const NOT_IMPL

struct ExternalSigner {
    UniValue DisplayAddress(const std::string& descriptor) const;
    static bool Enumerate(const std::string& command, std::vector<ExternalSigner>& signers, const std::string chain);
    UniValue GetDescriptors(const int account);
    bool SignTransaction(PartiallySignedTransaction& psbt, std::string& error);
};
UniValue ExternalSigner::DisplayAddress(const std::string& descriptor) const NOT_IMPL
bool ExternalSigner::Enumerate(const std::string& command, std::vector<ExternalSigner>& signers, const std::string chain) NOT_IMPL
UniValue ExternalSigner::GetDescriptors(const int account) NOT_IMPL
bool ExternalSigner::SignTransaction(PartiallySignedTransaction& psbt, std::string& error) NOT_IMPL

struct DescriptorCache {
    void CacheDerivedExtPubKey(uint32_t key_exp_pos, uint32_t der_index, const CExtPubKey& xpub);
    void CacheLastHardenedExtPubKey(uint32_t key_exp_pos, const CExtPubKey& xpub);
    void CacheParentExtPubKey(uint32_t key_exp_pos, const CExtPubKey& xpub);
    bool GetCachedParentExtPubKey(uint32_t key_exp_pos, CExtPubKey& xpub) const;
    std::unordered_map<uint32_t, ExtPubKeyMap> GetCachedDerivedExtPubKeys() const;
    ExtPubKeyMap GetCachedLastHardenedExtPubKeys() const;
    ExtPubKeyMap GetCachedParentExtPubKeys() const;
    DescriptorCache MergeAndDiff(const DescriptorCache& other);
};
void DescriptorCache::CacheDerivedExtPubKey(uint32_t key_exp_pos, uint32_t der_index, const CExtPubKey& xpub) NOT_IMPL
void DescriptorCache::CacheLastHardenedExtPubKey(uint32_t key_exp_pos, const CExtPubKey& xpub) NOT_IMPL
void DescriptorCache::CacheParentExtPubKey(uint32_t key_exp_pos, const CExtPubKey& xpub) NOT_IMPL
bool DescriptorCache::GetCachedParentExtPubKey(uint32_t key_exp_pos, CExtPubKey& xpub) const NOT_IMPL
std::unordered_map<uint32_t, ExtPubKeyMap> DescriptorCache::GetCachedDerivedExtPubKeys() const NOT_IMPL
ExtPubKeyMap DescriptorCache::GetCachedLastHardenedExtPubKeys() const NOT_IMPL
ExtPubKeyMap DescriptorCache::GetCachedParentExtPubKeys() const NOT_IMPL
DescriptorCache DescriptorCache::MergeAndDiff(const DescriptorCache& other) NOT_IMPL

struct ChaCha20 {
    ~ChaCha20();
    void Keystream(Span<std::byte> out) noexcept;
};
ChaCha20::~ChaCha20() {}
void ChaCha20::Keystream(Span<std::byte> out) noexcept {}

struct CScheduler {
    typedef std::function<void()> Function;
    void scheduleEvery(Function f, std::chrono::milliseconds delta);
    void MockForward(std::chrono::seconds delta_seconds);
};
void CScheduler::scheduleEvery(CScheduler::Function f, std::chrono::milliseconds delta) NOT_IMPL
void CScheduler::MockForward(std::chrono::seconds delta_seconds) NOT_IMPL

struct CSHA512 {
    CSHA512();
    CSHA512& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
    CSHA512& Reset();
};
CSHA512::CSHA512() NOT_IMPL
CSHA512& CSHA512::Write(const unsigned char* data, size_t len) NOT_IMPL
void CSHA512::Finalize(unsigned char hash[OUTPUT_SIZE]) NOT_IMPL
CSHA512& CSHA512::Reset() NOT_IMPL

struct CSHA1 {
    CSHA1();
    CSHA1& Write(const unsigned char* data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
};
CSHA1::CSHA1() NOT_IMPL
CSHA1& CSHA1::Write(const unsigned char* data, size_t len) NOT_IMPL
void CSHA1::Finalize(unsigned char hash[OUTPUT_SIZE]) NOT_IMPL

// header already included
bool CPubKey::CheckLowS(const std::vector<unsigned char>& vchSig) NOT_IMPL
bool CPubKey::IsFullyValid() const NOT_IMPL
bool CPubKey::Verify(const uint256& hash, const std::vector<unsigned char>& vchSig) const NOT_IMPL

// header already included
bool XOnlyPubKey::CheckTapTweak(const XOnlyPubKey& internal, const uint256& merkle_root, bool parity) const NOT_IMPL
std::optional<std::pair<XOnlyPubKey, bool>> XOnlyPubKey::CreateTapTweak(const uint256* merkle_root) const NOT_IMPL
CPubKey XOnlyPubKey::GetEvenCorrespondingCPubKey() const NOT_IMPL
std::vector<CKeyID> XOnlyPubKey::GetKeyIDs() const NOT_IMPL
bool XOnlyPubKey::IsFullyValid() const NOT_IMPL
bool XOnlyPubKey::VerifySchnorr(const uint256& msg, Span<const unsigned char> sigbytes) const NOT_IMPL
XOnlyPubKey::XOnlyPubKey(Span<const unsigned char> bytes) NOT_IMPL

struct CPartialMerkleTree {
    CPartialMerkleTree();
    uint256 ExtractMatches(std::vector<uint256> &vMatch, std::vector<unsigned int> &vnIndex);
};
CPartialMerkleTree::CPartialMerkleTree() {}
uint256 CPartialMerkleTree::ExtractMatches(std::vector<uint256> &vMatch, std::vector<unsigned int> &vnIndex) NOT_IMPL

// header already included
bool CKey::Check(const unsigned char* vch) NOT_IMPL
CPrivKey CKey::GetPrivKey() const NOT_IMPL
CPubKey CKey::GetPubKey() const NOT_IMPL
bool CKey::Load(const CPrivKey& privkey, const CPubKey& vchPubKey, bool fSkipCheck) NOT_IMPL
void CKey::MakeNewKey(bool fCompressed) NOT_IMPL
bool CKey::Sign(const uint256& hash, std::vector<unsigned char>& vchSig, bool grind, uint32_t test_case) const NOT_IMPL
bool CKey::SignSchnorr(const uint256& hash, Span<unsigned char> sig, const uint256* merkle_root, const uint256& aux) const NOT_IMPL
bool CKey::VerifyPubKey(const CPubKey& vchPubKey) const NOT_IMPL

struct CHMAC_SHA512 {
    CHMAC_SHA512(const unsigned char* key, size_t keylen);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
};
CHMAC_SHA512::CHMAC_SHA512(const unsigned char* key, size_t keylen) NOT_IMPL
void CHMAC_SHA512::Finalize(unsigned char hash[OUTPUT_SIZE]) NOT_IMPL

struct CFeeRate {
    CFeeRate(const CAmount& nFeePaid, uint32_t num_bytes);
    CAmount GetFee(uint32_t num_bytes) const;
    std::string ToString(const FeeEstimateMode& fee_estimate_mode) const;
};
CFeeRate::CFeeRate(const CAmount& nFeePaid, uint32_t num_bytes) NOT_IMPL
CAmount CFeeRate::GetFee(uint32_t num_bytes) const NOT_IMPL
std::string CFeeRate::ToString(const FeeEstimateMode& fee_estimate_mode) const NOT_IMPL

// header already included
void CExtPubKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const NOT_IMPL
void CExtPubKey::Decode(const unsigned char code[BIP32_EXTKEY_SIZE]) NOT_IMPL
void CExtPubKey::EncodeWithVersion(unsigned char code[BIP32_EXTKEY_WITH_VERSION_SIZE]) const NOT_IMPL;

// header already included
bool CExtKey::Derive(CExtKey& out, unsigned int nChild) const NOT_IMPL
CExtPubKey CExtKey::Neuter() const NOT_IMPL
void CExtKey::SetSeed(Span<const std::byte> seed) NOT_IMPL

struct CCoinsViewCache {
    void AddToken(const uint256& tokenId, blsct::TokenEntry&& token);
    void EraseToken(const uint256& tokenId);
    bool HaveInputs(const CTransaction& tx) const;
};
void CCoinsViewCache::AddToken(const uint256& tokenId, blsct::TokenEntry&& token) NOT_IMPL
void CCoinsViewCache::EraseToken(const uint256& tokenId) NOT_IMPL
bool CCoinsViewCache::HaveInputs(const CTransaction& tx) const NOT_IMPL

struct CBlockIndex {
    CBlockIndex* GetAncestor(int height) const;
};
CBlockIndex* CBlockIndex::GetAncestor(int height) const NOT_IMPL

struct ByteVectorHash final {
    ByteVectorHash();
    size_t operator()(const std::vector<unsigned char>& input) const;
};
ByteVectorHash::ByteVectorHash() {}
size_t ByteVectorHash::operator()(const std::vector<unsigned char>& input) const NOT_IMPL

std::vector<bool> BytesToBits(const std::vector<unsigned char>& bytes) NOT_IMPL

uint256 ArithToUint256(const arith_uint256 &a) NOT_IMPL

bilingual_str AmountHighWarn(const std::string& optname) NOT_IMPL
bilingual_str AmountErrMsg(const std::string& optname, const std::string& strValue) NOT_IMPL

void AddOutputs(CMutableTransaction& rawTx, const UniValue& outputs_in) NOT_IMPL

struct AES256CBCDecrypt {
    AES256CBCDecrypt(const unsigned char key[AES256_KEYSIZE], const unsigned char ivIn[AES_BLOCKSIZE], bool padIn);
    ~AES256CBCDecrypt();
    int Decrypt(const unsigned char* data, int size, unsigned char* out) const;
};

AES256CBCDecrypt::AES256CBCDecrypt(const unsigned char key[AES256_KEYSIZE], const unsigned char ivIn[AES_BLOCKSIZE], bool padIn) NOT_IMPL
int AES256CBCDecrypt::Decrypt(const unsigned char* data, int size, unsigned char* out) const NOT_IMPL
AES256CBCDecrypt::~AES256CBCDecrypt() {}

struct AES256CBCEncrypt {
    AES256CBCEncrypt(const unsigned char key[AES256_KEYSIZE], const unsigned char ivIn[AES_BLOCKSIZE], bool padIn);
    ~AES256CBCEncrypt();
    int Encrypt(const unsigned char* data, int size, unsigned char* out) const;
};

AES256CBCEncrypt::AES256CBCEncrypt(const unsigned char key[AES256_KEYSIZE], const unsigned char ivIn[AES_BLOCKSIZE], bool padIn) NOT_IMPL
int AES256CBCEncrypt::Encrypt(const unsigned char* data, int size, unsigned char* out) const NOT_IMPL
AES256CBCEncrypt::~AES256CBCEncrypt() {}

namespace wallet {
struct BerkeleyDatabase;
struct SQLiteDatabase;
struct DatabaseOptions;
struct DatabaseStatus;

std::unique_ptr<BerkeleyDatabase> MakeBerkeleyDatabase(const fs::path& path, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error) NOT_IMPL

std::unique_ptr<SQLiteDatabase> MakeSQLiteDatabase(const fs::path& path, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error) NOT_IMPL

} // namespace wallet

namespace BCLog {
struct LogFlags {};
struct Level {};

struct Logger {
    void LogPrintStr(const std::string& str, const std::string& logging_function, const std::string& source_file, int source_line, BCLog::LogFlags category, BCLog::Level level);
    bool WillLogCategoryLevel(LogFlags category, Level level) const;
};

void Logger::LogPrintStr(const std::string& str, const std::string& logging_function, const std::string& source_file, int source_line, BCLog::LogFlags category, BCLog::Level level) NOT_IMPL

bool Logger::WillLogCategoryLevel(LogFlags, Level) const NOT_IMPL

} // namespace BCLog

BCLog::Logger& LogInstance() NOT_IMPL

std::string EncodeExtKey(const CExtKey& key) NOT_IMPL

void ReplaceAll(std::string& in_out, const std::string& search, const std::string& substitute) NOT_IMPL

UniValue RunCommandParseJSON(const std::string& str_command, const std::string& str_std_in) NOT_IMPL

CTxDestination DecodeDestination(const std::string& str, std::string& error_msg, std::vector<int>* error_locations) NOT_IMPL

CTxDestination DecodeDestination(const std::string& str) NOT_IMPL

std::string EncodeDestination(const CTxDestination& dest) NOT_IMPL

std::optional<OutputType> OutputTypeFromDestination(const CTxDestination& dest) NOT_IMPL

CExtKey DecodeExtKey(const std::string& str) NOT_IMPL

CExtPubKey DecodeExtPubKey(const std::string& str) NOT_IMPL

CKey DecodeSecret(const std::string& str) NOT_IMPL

bool IsValidDestinationString(const std::string& str) NOT_IMPL

UniValue JSONRPCError(int code, const std::string& message) NOT_IMPL

std::optional<OutputType> ParseOutputType(const std::string& type) NOT_IMPL

CTxDestination AddAndGetDestinationForScript(FillableSigningProvider& keystore, const CScript& script, OutputType type) NOT_IMPL

std::optional<ChainType> ChainTypeFromString(std::string_view chain) NOT_IMPL

std::string ChainTypeToString(ChainType chain) NOT_IMPL

CTxDestination GetDestinationForKey(const CPubKey& key, OutputType type) NOT_IMPL

std::vector<CTxDestination> GetAllDestinationsForKey(const CPubKey& key) NOT_IMPL

std::string EncodeExtPubKey(const CExtPubKey& key) NOT_IMPL

std::string EncodeSecret(const CKey& key) NOT_IMPL

Span<const CRPCCommand> GetBLSCTWalletRPCCommands() NOT_IMPL

const std::string& FormatOutputType(OutputType type) NOT_IMPL

std::string FormatFullVersion() NOT_IMPL

std::string SysErrorString(int err) NOT_IMPL

struct CBlockHeader {
    uint256 GetHash() const;
};
uint256 CBlockHeader::GetHash() const NOT_IMPL

const CBaseChainParams& BaseParams() NOT_IMPL

const CChainParams& Params() NOT_IMPL

namespace common {
struct Settings;
struct SettingsValue {};

SettingsValue GetSetting(
    const Settings& settings,
    const std::string& section,
    const std::string& name,
    bool ignore_default_section_config,
    bool ignore_nonpersistent,
    bool get_chain_type) NOT_IMPL

std::vector<SettingsValue> GetSettingsList(
    const Settings& settings,
    const std::string& section,
    const std::string& name,
    bool ignore_default_section_config) NOT_IMPL

bool OnlyHasDefaultSectionSetting(const Settings& settings, const std::string& section, const std::string& name) NOT_IMPL

bool ReadSettings(const fs::path& path, std::map<std::string, UniValue>& values, std::vector<std::string>& errors) NOT_IMPL

bool WriteSettings(const fs::path& path,
    const std::map<std::string, UniValue>& values,
    std::vector<std::string>& errors) NOT_IMPL

struct SettingsSpan {
    SettingsSpan(const std::vector<UniValue>& vec);
    bool empty() const;
    void begin() const;
};

SettingsSpan::SettingsSpan(const std::vector<UniValue>&) NOT_IMPL

bool SettingsSpan::empty() const NOT_IMPL

void SettingsSpan::begin() const NOT_IMPL

} // namespace common

