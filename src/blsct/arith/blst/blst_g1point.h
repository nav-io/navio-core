// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// G1 wrapper over supranational/blst, API-compatible with MclG1Point so the
// templated BLSCT proof code can be instantiated with either backend.
// Evaluation prototype for the mcl -> blst migration; the deferral / skip /
// legacy decode scopes of MclG1Point are intentionally NOT reproduced here:
// this backend always decodes strictly (curve + prime-order subgroup).

#ifndef NAVIO_BLSCT_ARITH_BLST_BLST_G1POINT_H
#define NAVIO_BLSCT_ARITH_BLST_BLST_G1POINT_H

#include <blst.h>
#include <blsct/arith/blst/blst_scalar.h>
#include <blsct/arith/endianness.h>
#include <uint256.h>

#include <span>
#include <stdexcept>
#include <string>
#include <vector>

class BlstG1Point
{
public:
    using Underlying = blst_p1; // Jacobian, Montgomery-form coordinates
    using Scalar = BlstScalar;

    BlstG1Point();
    BlstG1Point(const std::vector<uint8_t>& v);
    BlstG1Point(const uint256& n);
    BlstG1Point(const Underlying& p);

    BlstG1Point operator=(const Underlying& rhs);
    BlstG1Point operator+(const BlstG1Point& rhs) const;
    BlstG1Point operator-(const BlstG1Point& rhs) const;
    BlstG1Point operator*(const Scalar& rhs) const;
    std::vector<BlstG1Point> operator*(const std::vector<Scalar>& ss) const;

    bool operator==(const BlstG1Point& rhs) const;
    bool operator!=(const BlstG1Point& rhs) const;
    bool operator<(const BlstG1Point& b) const
    {
        return this->GetVch() < b.GetVch();
    }

    BlstG1Point Double() const;
    const Underlying& GetUnderlying() const;

    static BlstG1Point GetBasePoint();
    static BlstG1Point MapToPoint(const std::vector<uint8_t>& vec, Endianness e = Endianness::Little);
    static BlstG1Point MapToPoint(const std::string& s, Endianness e = Endianness::Little);
    static BlstG1Point HashAndMap(const std::vector<uint8_t>& vec);
    static BlstG1Point Rand();

    bool IsValid() const;
    bool IsZero() const;

    std::vector<uint8_t> GetVch() const;
    bool SetVch(const std::vector<uint8_t>& vec);
    bool SetVchUnchecked(const std::vector<uint8_t>& vec);

    static bool BatchCheckSubgroup(std::span<const BlstG1Point> pts);
    static void BatchNormalize(std::span<BlstG1Point> pts);
    static void BatchNormalize(std::span<BlstG1Point* const> pts);

    std::string GetString(const uint8_t& radix = 16) const;
    void SetString(const std::string& hex);

    Scalar GetHashWithSalt(uint64_t salt) const;

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
        if (!SetVch(vec)) {
            throw std::ios_base::failure("BlstG1Point: invalid or off-subgroup encoding");
        }
    }

    Underlying m_point;

    static constexpr int SERIALIZATION_SIZE = 384 / 8;

    // The DST mcl uses for G1 hash-to-curve in BLS_ETH mode
    // (mapto_wb19.hpp); kept identical so HashAndMap is bit-compatible.
    static constexpr const char* HASH_TO_G1_DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
};

#endif // NAVIO_BLSCT_ARITH_BLST_BLST_G1POINT_H
