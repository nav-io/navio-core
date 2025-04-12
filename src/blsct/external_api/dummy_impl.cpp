#include <uint256.h>
#include <util/fs.h>
#include <blsct/double_public_key.h>

#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

struct bilingual_str;
struct CBaseChainParams;
struct CChainParams;
struct CExtKey;
struct CExtPubKey;
struct CKey;
struct ChainType {};
struct CNoDestination {};
struct CPubKey;
struct CRPCCommand {};
struct CScript;
struct FillableSigningProvider;
struct OutputType {};
struct Params {};
struct PKHash {};
struct PubKeyDestination {};
struct ScriptHash {};
struct UniValue {};
struct WitnessV0ScriptHash {};
struct WitnessV0KeyHash {};
struct WitnessV1Taproot {};
struct WitnessUnknown {};

using CTxDestination = std::variant<CNoDestination, PubKeyDestination, PKHash, ScriptHash, WitnessV0ScriptHash, WitnessV0KeyHash, WitnessV1Taproot, WitnessUnknown, blsct::DoublePublicKey>;

namespace wallet {
struct BerkeleyDatabase;
struct SQLiteDatabase;
struct DatabaseOptions;
struct DatabaseStatus;

std::unique_ptr<BerkeleyDatabase> MakeBerkeleyDatabase(const fs::path& path, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error) {
    throw std::logic_error("Not implemented");
}

std::unique_ptr<SQLiteDatabase> MakeSQLiteDatabase(const fs::path& path, const DatabaseOptions& options, DatabaseStatus& status, bilingual_str& error) {
    throw std::logic_error("Not implemented");
}

} // namespace wallet

namespace BCLog {
struct LogFlags {};
struct Level {};

struct Logger {
    void LogPrintStr(const std::string& str, const std::string& logging_function, const std::string& source_file, int source_line, BCLog::LogFlags category, BCLog::Level level);
    bool WillLogCategoryLevel(LogFlags category, Level level) const;
};

void Logger::LogPrintStr(const std::string& str, const std::string& logging_function, const std::string& source_file, int source_line, BCLog::LogFlags category, BCLog::Level level) {
    throw std::logic_error("Not implemented");
}

bool Logger::WillLogCategoryLevel(LogFlags, Level) const {
    throw std::logic_error("Not implemented");
}

} // namespace BCLog

BCLog::Logger& LogInstance() {
    throw std::logic_error("Not implemented");
}

std::string EncodeExtKey(const CExtKey& key) {
    throw std::logic_error("Not implemented");
}

void ReplaceAll(std::string& in_out, const std::string& search, const std::string& substitute) {
    throw std::logic_error("Not implemented");
}

UniValue RunCommandParseJSON(const std::string& str_command, const std::string& str_std_in) {
    throw std::logic_error("Not implemented");
}

CTxDestination DecodeDestination(const std::string& str, std::string& error_msg, std::vector<int>* error_locations) {
    throw std::logic_error("Not implemented");
}

CTxDestination DecodeDestination(const std::string& str) {
    throw std::logic_error("Not implemented");
}

std::string EncodeDestination(const CTxDestination& dest) {
    throw std::logic_error("Not implemented");
}

std::optional<OutputType> OutputTypeFromDestination(const CTxDestination& dest) {
    throw std::logic_error("Not implemented");
}

CExtKey DecodeExtKey(const std::string& str) {
    throw std::logic_error("Not implemented");
}

CExtPubKey DecodeExtPubKey(const std::string& str) {
    throw std::logic_error("Not implemented");
}

CKey DecodeSecret(const std::string& str) {
    throw std::logic_error("Not implemented");
}

bool IsValidDestinationString(const std::string& str) {
    throw std::logic_error("Not implemented");
}

UniValue JSONRPCError(int code, const std::string& message) {
    throw std::logic_error("Not implemented");
}

std::optional<OutputType> ParseOutputType(const std::string& type) {
    throw std::logic_error("Not implemented");
}

CTxDestination AddAndGetDestinationForScript(FillableSigningProvider& keystore, const CScript& script, OutputType type) {
    throw std::logic_error("Not implemented");
}

std::optional<ChainType> ChainTypeFromString(std::string_view chain) {
    throw std::logic_error("Not implemented");
}

std::string ChainTypeToString(ChainType chain) {
    throw std::logic_error("Not implemented");
}

CTxDestination GetDestinationForKey(const CPubKey& key, OutputType type) {
    throw std::logic_error("Not implemented");
}

std::vector<CTxDestination> GetAllDestinationsForKey(const CPubKey& key) {
    throw std::logic_error("Not implemented");
}

std::string EncodeExtPubKey(const CExtPubKey& key) {
    throw std::logic_error("Not implemented");
}

std::string EncodeSecret(const CKey& key) {
    throw std::logic_error("Not implemented");
}

Span<const CRPCCommand> GetBLSCTWalletRPCCommands() {
    throw std::logic_error("Not implemented");
}

const std::string& FormatOutputType(OutputType type) {
    throw std::logic_error("Not implemented");
}

std::string FormatFullVersion() {
    throw std::logic_error("Not implemented");
}

std::string SysErrorString(int err) {
    throw std::logic_error("Not implemented");
}

struct CBlockHeader {
    uint256 GetHash() const;
};
uint256 CBlockHeader::GetHash() const {
    throw std::logic_error("Not implemented");
}

const CBaseChainParams& BaseParams() {
    throw std::logic_error("Not implemented");
}

const CChainParams& Params() {
    throw std::logic_error("Not implemented");
}

namespace common {
struct Settings;
struct SettingsValue {};

SettingsValue GetSetting(
    const Settings& settings,
    const std::string& section,
    const std::string& name,
    bool ignore_default_section_config,
    bool ignore_nonpersistent,
    bool get_chain_type) {
    throw std::logic_error("Not implemented");
}

std::vector<SettingsValue> GetSettingsList(
    const Settings& settings,
    const std::string& section,
    const std::string& name,
    bool ignore_default_section_config) {
    throw std::logic_error("Not implemented");
}

bool OnlyHasDefaultSectionSetting(const Settings& settings, const std::string& section, const std::string& name) {
    throw std::logic_error("Not implemented");
}

bool ReadSettings(const fs::path& path, std::map<std::string, UniValue>& values, std::vector<std::string>& errors) {
    throw std::logic_error("Not implemented");
}

bool WriteSettings(const fs::path& path,
    const std::map<std::string, UniValue>& values,
    std::vector<std::string>& errors) {
    throw std::logic_error("Not implemented");
}

struct SettingsSpan {
    SettingsSpan(const std::vector<UniValue>& vec);
    bool empty() const;
    void begin() const;
};

SettingsSpan::SettingsSpan(const std::vector<UniValue>&) {
    throw std::logic_error("Not implemented");
}

bool SettingsSpan::empty() const {
    throw std::logic_error("Not implemented");
}

void SettingsSpan::begin() const {
    throw std::logic_error("Not implemented");
}

} // namespace common


