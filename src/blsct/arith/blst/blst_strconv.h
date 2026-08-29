// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_ARITH_BLST_BLST_STRCONV_H
#define NAVIO_BLSCT_ARITH_BLST_BLST_STRCONV_H

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

// Small big-endian byte-string <-> radix-string helpers for the blst arith
// backend. mcl ships its own bignum I/O (mclBnFr_getStr / mclBnG1_getStr);
// blst deliberately has none, so the wrapper carries the few conversions the
// codebase relies on (hex/dec/bin rendering for debug strings, hex parsing).
namespace blst_arith {

// Render an unsigned big-endian integer in `radix` (2, 10 or 16), no prefix,
// leading zeros stripped, "0" for zero — matching mcl's getStr formatting.
inline std::string BytesToRadixString(const uint8_t* be, size_t n, int radix)
{
    static const char* digits = "0123456789abcdef";
    if (radix != 2 && radix != 10 && radix != 16) {
        throw std::runtime_error("BytesToRadixString: unsupported radix");
    }
    std::vector<uint8_t> v(be, be + n);
    std::string out;
    if (radix == 16 || radix == 2) {
        const int bits = radix == 16 ? 4 : 1;
        for (uint8_t b : v) {
            for (int sh = 8 - bits; sh >= 0; sh -= bits) {
                out.push_back(digits[(b >> sh) & (radix - 1)]);
            }
        }
    } else {
        // Schoolbook division by 10 on the byte array.
        while (true) {
            bool all_zero = true;
            for (uint8_t b : v) if (b) { all_zero = false; break; }
            if (all_zero) break;
            unsigned rem = 0;
            for (size_t i = 0; i < v.size(); ++i) {
                unsigned cur = (rem << 8) | v[i];
                v[i] = static_cast<uint8_t>(cur / 10);
                rem = cur % 10;
            }
            out.push_back(digits[rem]);
        }
        std::string rev(out.rbegin(), out.rend());
        out = rev;
    }
    size_t first = out.find_first_not_of('0');
    if (first == std::string::npos) return "0";
    return out.substr(first);
}

// Parse a radix-`radix` (2/10/16) digit string into a big-endian byte vector
// of exactly `out_len` bytes (left-padded with zeros). Values that do not fit
// are rejected. An optional "0x" prefix is accepted for radix 16.
inline std::vector<uint8_t> RadixStringToBytes(const std::string& s_in, int radix, size_t out_len)
{
    if (radix != 2 && radix != 10 && radix != 16) {
        throw std::runtime_error("RadixStringToBytes: unsupported radix");
    }
    std::string s = s_in;
    if (radix == 16 && s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s = s.substr(2);
    if (s.empty()) throw std::runtime_error("RadixStringToBytes: empty string");

    std::vector<uint8_t> acc(out_len, 0);
    for (char c : s) {
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else throw std::runtime_error("RadixStringToBytes: bad digit");
        if (d >= radix) throw std::runtime_error("RadixStringToBytes: digit out of radix");
        // acc = acc * radix + d
        unsigned carry = static_cast<unsigned>(d);
        for (size_t i = acc.size(); i-- > 0;) {
            unsigned cur = acc[i] * static_cast<unsigned>(radix) + carry;
            acc[i] = static_cast<uint8_t>(cur & 0xff);
            carry = cur >> 8;
        }
        if (carry) throw std::runtime_error("RadixStringToBytes: overflow");
    }
    return acc;
}

} // namespace blst_arith

#endif // NAVIO_BLSCT_ARITH_BLST_BLST_STRCONV_H
