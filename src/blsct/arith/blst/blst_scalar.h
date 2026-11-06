// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Fr (BLS12-381 scalar field) wrapper over supranational/blst. `Blst::Scalar`
// for the templated BLSCT proof code (see blsct/arith/blst/blst.h).

#ifndef NAVIO_BLSCT_ARITH_BLST_BLST_SCALAR_H
#define NAVIO_BLSCT_ARITH_BLST_BLST_SCALAR_H

#include <blst.h>
#include <hash.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <support/cleanse.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <functional>
#include <stddef.h>
#include <string>
#include <vector>

// Defined in blst_g1point.cpp. True while BlstG1Point::LegacyPointDecodeScope
// is active on this thread; honoured when strict deserialization must stay
// lenient for binary-baked consensus-parameter data (genesis blobs).
bool BlstLegacyPointDecodeActive();

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

    BlstScalar(const BlstScalar&) = default;
    BlstScalar(BlstScalar&&) = default;
    BlstScalar& operator=(const BlstScalar&) = default;
    BlstScalar& operator=(BlstScalar&&) = default;
    // A scalar can be a secret (a key, a blinding factor, a nonce), and the
    // proof code makes many temporaries of them, so every one is wiped when
    // it goes away rather than left in freed stack or heap memory.
    ~BlstScalar() { memory_cleanse(&m_scalar, sizeof(m_scalar)); }

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
    void SetVch(Span<const uint8_t> v);

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
        memory_cleanse(vec.data(), vec.size());
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        std::vector<unsigned char> vec(SERIALIZATION_SIZE);
        s.read(MakeWritableByteSpan(vec));
        SetVch(vec);
        // Enforce the canonical encoding. SetVch reduces mod r, so a
        // non-canonical input (v >= r) would silently deserialize to a
        // DIFFERENT scalar than its byte string denotes; reject it instead.
        // The legacy-decode scope (baked consensus parameters whose encoding
        // predates the canonical serializer) keeps the lenient behaviour.
        // Note GetVch() here must be the untrimmed 32-byte form.
        bool canonical{true};
        if (!BlstLegacyPointDecodeActive()) {
            auto reencoded = GetVch();
            canonical = reencoded == vec;
            memory_cleanse(reencoded.data(), reencoded.size());
        }
        memory_cleanse(vec.data(), vec.size());
        if (!canonical) {
            throw std::ios_base::failure("BlstScalar: non-canonical encoding");
        }
    }

    static constexpr int SERIALIZATION_SIZE = 32;

    // Value-initialised so every constructor hands blst a zeroed object:
    // blst's assembly is invisible to MemorySanitizer, and a poisoned
    // destination would stay poisoned after it is written.
    Underlying m_scalar{};

private:
    // Canonical little-endian 32-byte form (blst_scalar) of m_scalar.
    blst_scalar ToScalar() const;
    void FromScalar(const blst_scalar& s);
};

#endif // NAVIO_BLSCT_ARITH_BLST_BLST_SCALAR_H
