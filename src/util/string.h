// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_STRING_H
#define BITCOIN_UTIL_STRING_H

#include <util/spanparsing.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <locale>
#include <optional>
#include <sstream>
#include <string>      // IWYU pragma: export
#include <string_view> // IWYU pragma: export
#include <vector>

void ReplaceAll(std::string& in_out, const std::string& search, const std::string& substitute);

[[nodiscard]] inline std::vector<std::string> SplitString(std::string_view str, char sep)
{
    return spanparsing::Split<std::string>(str, sep);
}

[[nodiscard]] inline std::vector<std::string> SplitString(std::string_view str, std::string_view separators)
{
    return spanparsing::Split<std::string>(str, separators);
}

[[nodiscard]] inline std::string_view TrimStringView(std::string_view str, std::string_view pattern = " \f\n\r\t\v")
{
    std::string::size_type front = str.find_first_not_of(pattern);
    if (front == std::string::npos) {
        return {};
    }
    std::string::size_type end = str.find_last_not_of(pattern);
    return str.substr(front, end - front + 1);
}

[[nodiscard]] inline std::string TrimString(std::string_view str, std::string_view pattern = " \f\n\r\t\v")
{
    return std::string(TrimStringView(str, pattern));
}

[[nodiscard]] inline std::string_view RemovePrefixView(std::string_view str, std::string_view prefix)
{
    if (str.starts_with(prefix)) {
        return str.substr(prefix.size());
    }
    return str;
}

[[nodiscard]] inline std::string RemovePrefix(std::string_view str, std::string_view prefix)
{
    return std::string(RemovePrefixView(str, prefix));
}

/**
 * Join all container items. Typically used to concatenate strings but accepts
 * containers with elements of any type.
 *
 * @param container The items to join
 * @param separator The separator
 * @param unary_op  Apply this operator to each item
 */
template <typename C, typename S, typename UnaryOp>
// NOLINTNEXTLINE(misc-no-recursion)
auto Join(const C& container, const S& separator, UnaryOp unary_op)
{
    decltype(unary_op(*container.begin())) ret;
    bool first{true};
    for (const auto& item : container) {
        if (!first) ret += separator;
        ret += unary_op(item);
        first = false;
    }
    return ret;
}

template <typename C, typename S>
auto Join(const C& container, const S& separator)
{
    return Join(container, separator, [](const auto& i) { return i; });
}

/**
 * Create an unordered multi-line list of items.
 */
inline std::string MakeUnorderedList(const std::vector<std::string>& items)
{
    return Join(items, "\n", [](const std::string& item) { return "- " + item; });
}

/**
 * Check if a string does not contain any embedded NUL (\0) characters
 */
[[nodiscard]] inline bool ContainsNoNUL(std::string_view str) noexcept
{
    for (auto c : str) {
        if (c == 0) return false;
    }
    return true;
}

/**
 * Locale-independent version of std::to_string
 */
template <typename T>
std::string ToString(const T& t)
{
    std::ostringstream oss;
    oss.imbue(std::locale::classic());
    oss << t;
    return oss.str();
}

/**
 * Check whether a container begins with the given prefix.
 */
template <typename T1, size_t PREFIX_LEN>
[[nodiscard]] inline bool HasPrefix(const T1& obj,
                                const std::array<uint8_t, PREFIX_LEN>& prefix)
{
    return obj.size() >= PREFIX_LEN &&
           std::equal(std::begin(prefix), std::end(prefix), std::begin(obj));
}

namespace util {
struct LineReader {
    const std::span<const std::byte>::iterator start;
    const std::span<const std::byte>::iterator end;
    const size_t max_line_length;
    std::span<const std::byte>::iterator it;

    explicit LineReader(std::span<const std::byte> buffer, size_t max_line_length);

    /**
     * Returns a string from current iterator position up to (but not including) next \n
     * and advances iterator to the character following the \n on success.
     * Will not return a line longer than max_line_length.
     * @returns the next string from the buffer.
     *          std::nullopt if end of buffer is reached without finding a \n.
     * @throws a std::runtime_error if max_line_length + 1 bytes are read without finding \n.
     */
    std::optional<std::string> ReadLine();

    /**
     * Returns string from current iterator position of specified length
     * if possible and advances iterator on success.
     * May exceed max_line_length but will not read past end of buffer.
     * @param[in]   len     The number of bytes to read from the buffer
     * @returns a string of the expected length.
     * @throws a std::runtime_error if there is not enough data in the buffer.
     */
    std::string ReadLength(size_t len);

    /**
     * Returns remaining size of bytes in buffer
     */
    size_t Remaining() const;
};
} // namespace util

#endif // BITCOIN_UTIL_STRING_H
