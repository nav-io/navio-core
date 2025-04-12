#include <util/fs.h>

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

struct bilingual_str;
struct CExtKey;

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

std::string EncodeExtKey(const CExtKey& key) {
    throw std::logic_error("Not implemented");
}

namespace common {
struct Settings;
struct SettingsValue;

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

} // namespace common

