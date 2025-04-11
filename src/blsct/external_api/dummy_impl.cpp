#include <util/fs.h>

#include <memory>
#include <stdexcept>

struct bilingual_str;

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

