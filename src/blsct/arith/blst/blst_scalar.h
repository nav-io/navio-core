// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Fr (BLS12-381 scalar field) wrapper over supranational/blst. API-compatible
// with MclScalar so the templated BLSCT proof code can be instantiated with
// either backend (see blsct/arith/blst/blst.h). Evaluation prototype for the
// mcl -> blst migration; see doc/blsct-blst-evaluation.md.

#ifndef NAVIO_BLSCT_ARITH_BLST_BLST_SCALAR_H
#define NAVIO_BLSCT_ARITH_BLST_BLST_SCALAR_H

#include <blst.h>
#include <hash.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <functional>
#include <stddef.h>
#include <string>
#include <vector>

class BlstScalar
{
public:
    // blst_fr holds the element in Montgomery form; every public
    // constructor/setter converts to it and every getter converts back.
    using Underlying = blst_fr;

    BlstScalar();
    BlstScalar(const int64_t& n);
    BlstScalar(const std::vector<uint8_t>& v);
    template <size_t L>
    BlstScalar(const std::array<uint8_t, L>& a);
    BlstScalar(const Underlying& other_underlying);
    BlstScalar(const uint256& n);
    BlstScalar(const std::string& s, int radix);
    BlstScalar(const std::vector<uint8_t>& msg, uint8_t index);

    BlstScalar ApplyBitwiseOp(const BlstScalar& a, const BlstScalar& b,
                              std::function<uint8_t(uint8_t, uint8_t)> op) const;

    void operator=(const int64_t& n);

    BlstScalar operator+(const BlstScalar& b) const;
    BlstScalar operator-(const BlstScalar& b) const;
    BlstScalar operator*(const BlstScalar& b) const;
    BlstScalar operator/(const BlstScalar& b) const;
    BlstScalar operator|(const BlstScalar& b) const;
    BlstScalar operator^(const BlstScalar& b) const;
    BlstScalar operator&(const BlstScalar& b) const;
    BlstScalar operator~() const;
    BlstScalar operator<<(const uint32_t& shift) const;
    BlstScalar operator>>(const uint32_t& shift) const;

    bool operator==(const BlstScalar& b) const;
    bool operator==(const int32_t& b) const;
    bool operator!=(const BlstScalar& b) const;
    bool operator!=(const int32_t& b) const;

    bool operator<(const BlstScalar& b) const;
    bool operator>(const BlstScalar& b) const;

    const Underlying& GetUnderlying() const;
    bool IsValid() const;
    bool IsZero() const;

    BlstScalar Invert() const;
    BlstScalar Negate() const;
    BlstScalar Square() const;
    BlstScalar Cube() const;
    BlstScalar Pow(const BlstScalar& n) const;

    static BlstScalar Rand(bool exclude_zero = true);

    uint64_t GetUint64() const;

    std::vector<uint8_t> GetVch(bool trim_preceeding_zeros = false) const;
    void SetVch(const std::vector<uint8_t>& v);

    void SetPow2(const uint32_t& n);

    uint256 GetHashWithSalt(const uint64_t& salt) const;

    std::string GetString(const int8_t& radix = 16) const;

    bool GetSeriBit(const uint8_t& n) const;
    std::vector<bool> ToBinaryVec() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        auto vec = GetVch();
        s.write(MakeByteSpan(vec));
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        std::vector<unsigned char> vec(SERIALIZATION_SIZE);
        s.read(MakeWritableByteSpan(vec));
        SetVch(vec);
        // Canonical-encoding check, as in MclScalar::Unserialize. The blst
        // backend has no legacy-decode scope: it is strict everywhere.
        if (GetVch() != vec) {
            throw std::ios_base::failure("BlstScalar: non-canonical encoding");
        }
    }

    static constexpr int SERIALIZATION_SIZE = 32;

    Underlying m_scalar;

private:
    // Canonical little-endian 32-byte form (blst_scalar) of m_scalar.
    blst_scalar ToScalar() const;
    void FromScalar(const blst_scalar& s);
};

#endif // NAVIO_BLSCT_ARITH_BLST_BLST_SCALAR_H
