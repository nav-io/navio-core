// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/arith/blst/blst_g1point.h>
#include <blsct/arith/blst/blst_strconv.h>
#include <random.h>
#include <streams.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstring>
#include <sstream>

namespace {

// Reduce an arbitrary-length big-endian integer mod p into an Fp element.
// Horner over bytes in Fp (acc = acc*256 + b); cost is irrelevant for the
// 32-byte inputs the codebase actually maps, and it is exact for any length,
// which mirrors mclBnFp_setBigEndianMod.
blst_fp FpFromBigEndianMod(const uint8_t* be, size_t n)
{
    blst_fp acc;
    std::memset(&acc, 0, sizeof(acc));
    if (n <= 48) {
        // Fast path: value < 2^384. blst_fp_from_bendian requires the input
        // to be < p; a 48-byte value may not be, so only take it for <= 47
        // bytes (< 2^376 < p) and fall through otherwise.
        if (n <= 47) {
            uint8_t buf[48] = {0};
            std::memcpy(buf + (48 - n), be, n);
            blst_fp_from_bendian(&acc, buf);
            return acc;
        }
    }
    blst_fp c256;
    {
        const uint64_t v[6] = {256, 0, 0, 0, 0, 0};
        blst_fp_from_uint64(&c256, v);
    }
    for (size_t i = 0; i < n; ++i) {
        blst_fp digit;
        const uint64_t v[6] = {be[i], 0, 0, 0, 0, 0};
        blst_fp_from_uint64(&digit, v);
        blst_fp_mul(&acc, &acc, &c256);
        blst_fp_add(&acc, &acc, &digit);
    }
    return acc;
}

BlstG1Point MapFpToG1(const blst_fp& u)
{
    // Single-element SSWU + 11-isogeny + cofactor clearing: what mcl's
    // mapToG1(Fp) does in BLS_ETH (hash-to-curve draft-07 / RFC 9380) mode.
    BlstG1Point out;
    blst_map_to_g1(&out.m_point, &u, nullptr);
    return out;
}

} // namespace

BlstG1Point::BlstG1Point()
{
    // All-zero blst_p1 (Z == 0) is the point at infinity.
    std::memset(&m_point, 0, sizeof(Underlying));
}

BlstG1Point::BlstG1Point(const std::vector<uint8_t>& v)
{
    SetVch(v);
}

BlstG1Point::BlstG1Point(const Underlying& p)
{
    m_point = p;
}

BlstG1Point::BlstG1Point(const uint256& n)
{
    // uint256 raw bytes taken as big-endian, mod p (see MclG1Point).
    blst_fp u = FpFromBigEndianMod(n.data(), n.size());
    *this = MapFpToG1(u);
}

const BlstG1Point::Underlying& BlstG1Point::GetUnderlying() const
{
    return m_point;
}

BlstG1Point BlstG1Point::operator=(const Underlying& rhs)
{
    m_point = rhs;
    return *this;
}

BlstG1Point BlstG1Point::operator+(const BlstG1Point& rhs) const
{
    BlstG1Point ret;
    blst_p1_add_or_double(&ret.m_point, &m_point, &rhs.m_point);
    return ret;
}

BlstG1Point BlstG1Point::operator-(const BlstG1Point& rhs) const
{
    BlstG1Point neg(rhs);
    blst_p1_cneg(&neg.m_point, true);
    return *this + neg;
}

BlstG1Point BlstG1Point::operator*(const Scalar& rhs) const
{
    BlstG1Point ret;
    blst_scalar s;
    blst_scalar_from_fr(&s, &rhs.m_scalar);
    blst_p1_mult(&ret.m_point, &m_point, s.b, 255);
    return ret;
}

std::vector<BlstG1Point> BlstG1Point::operator*(const std::vector<Scalar>& ss) const
{
    if (ss.size() == 0) {
        throw std::runtime_error(std::string(__func__) + ": Cannot multiply BlstG1Point by empty scalar vector");
    }
    std::vector<BlstG1Point> ret;
    ret.reserve(ss.size());
    for (const auto& s : ss) {
        ret.push_back(*this * s);
    }
    return ret;
}

BlstG1Point BlstG1Point::Double() const
{
    BlstG1Point ret;
    blst_p1_double(&ret.m_point, &m_point);
    return ret;
}

BlstG1Point BlstG1Point::GetBasePoint()
{
    return BlstG1Point(*blst_p1_generator());
}

BlstG1Point BlstG1Point::MapToPoint(const std::vector<uint8_t>& vec, const Endianness e)
{
    if (vec.size() == 0) {
        throw std::runtime_error(std::string(__func__) + ": Cannot map empty input vector to a point");
    }
    if (vec.size() > 48 * 2) {
        throw std::runtime_error(std::string(__func__) + ": Size of vector must be smaller or equal to the size of Fp * 2");
    }
    blst_fp u;
    if (e == Endianness::Little) {
        std::vector<uint8_t> be(vec.rbegin(), vec.rend());
        u = FpFromBigEndianMod(be.data(), be.size());
    } else {
        u = FpFromBigEndianMod(vec.data(), vec.size());
    }
    return MapFpToG1(u);
}

BlstG1Point BlstG1Point::MapToPoint(const std::string& s, const Endianness e)
{
    std::vector<uint8_t> vec(s.begin(), s.end());
    return MapToPoint(vec, e);
}

BlstG1Point BlstG1Point::HashAndMap(const std::vector<uint8_t>& vec)
{
    BlstG1Point ret;
    blst_hash_to_g1(&ret.m_point, vec.data(), vec.size(),
                    reinterpret_cast<const byte*>(HASH_TO_G1_DST), std::strlen(HASH_TO_G1_DST),
                    nullptr, 0);
    return ret;
}

bool BlstG1Point::operator==(const BlstG1Point& rhs) const
{
    return blst_p1_is_equal(&m_point, &rhs.m_point);
}

bool BlstG1Point::operator!=(const BlstG1Point& rhs) const
{
    return !operator==(rhs);
}

BlstG1Point BlstG1Point::Rand()
{
    return GetBasePoint() * BlstScalar::Rand();
}

bool BlstG1Point::IsValid() const
{
    // mclBnG1_isValid checks the curve equation (order verification is off
    // for G1 in mcl's BLS12-381 init; SetVch adds the subgroup check).
    if (IsZero()) return true;
    return blst_p1_on_curve(&m_point);
}

bool BlstG1Point::IsZero() const
{
    return blst_p1_is_inf(&m_point);
}

std::vector<uint8_t> BlstG1Point::GetVch() const
{
    std::vector<uint8_t> b(SERIALIZATION_SIZE);
    blst_p1_compress(b.data(), &m_point);
    return b;
}

bool BlstG1Point::SetVchUnchecked(const std::vector<uint8_t>& b)
{
    if (b.size() != SERIALIZATION_SIZE) {
        *this = BlstG1Point();
        return false;
    }
    blst_p1_affine aff;
    // blst_p1_uncompress validates the encoding and the curve equation.
    if (blst_p1_uncompress(&aff, b.data()) != BLST_SUCCESS) {
        *this = BlstG1Point();
        return false;
    }
    blst_p1_from_affine(&m_point, &aff);
    return true;
}

bool BlstG1Point::SetVch(const std::vector<uint8_t>& b)
{
    if (!SetVchUnchecked(b)) return false;
    // Prime-order subgroup membership, as in MclG1Point::SetVch. The
    // identity is permitted.
    if (!IsZero() && !blst_p1_in_g1(&m_point)) {
        *this = BlstG1Point();
        return false;
    }
    return true;
}

void BlstG1Point::BatchNormalize(std::span<BlstG1Point> pts)
{
    if (pts.empty()) return;
    static_assert(sizeof(BlstG1Point) == sizeof(blst_p1),
                  "BlstG1Point must be layout-compatible with blst_p1");
    std::vector<blst_p1_affine> aff(pts.size());
    const blst_p1* in[2] = {&pts.data()->m_point, nullptr};
    blst_p1s_to_affine(aff.data(), in, pts.size());
    for (size_t i = 0; i < pts.size(); ++i) {
        blst_p1_from_affine(&pts[i].m_point, &aff[i]);
    }
}

void BlstG1Point::BatchNormalize(std::span<BlstG1Point* const> pts)
{
    if (pts.empty()) return;
    std::vector<BlstG1Point> buffer;
    buffer.reserve(pts.size());
    for (auto* p : pts) buffer.push_back(*p);
    BatchNormalize(std::span<BlstG1Point>(buffer));
    for (size_t i = 0; i < pts.size(); ++i) *pts[i] = buffer[i];
}

std::string BlstG1Point::GetString(const uint8_t& radix) const
{
    // mcl getStr format: "0" for the identity, "1 <x> <y>" otherwise.
    if (IsZero()) return "0";
    blst_p1_affine aff;
    blst_p1_to_affine(&aff, &m_point);
    uint8_t x[48], y[48];
    blst_bendian_from_fp(x, &aff.x);
    blst_bendian_from_fp(y, &aff.y);
    return "1 " + blst_arith::BytesToRadixString(x, 48, radix) + " " + blst_arith::BytesToRadixString(y, 48, radix);
}

void BlstG1Point::SetString(const std::string& hex)
{
    std::istringstream is(hex);
    std::string flag, xs, ys;
    is >> flag;
    if (flag == "0") {
        *this = BlstG1Point();
        return;
    }
    is >> xs >> ys;
    if (flag != "1" || xs.empty() || ys.empty()) {
        throw std::runtime_error(std::string(__func__) + ": blst_p1 setStr failed");
    }
    auto xb = blst_arith::RadixStringToBytes(xs, 16, 48);
    auto yb = blst_arith::RadixStringToBytes(ys, 16, 48);
    blst_p1_affine aff;
    blst_fp_from_bendian(&aff.x, xb.data());
    blst_fp_from_bendian(&aff.y, yb.data());
    if (!blst_p1_affine_on_curve(&aff)) {
        throw std::runtime_error(std::string(__func__) + ": blst_p1 setStr failed (not on curve)");
    }
    blst_p1_from_affine(&m_point, &aff);
}

BlstG1Point::Scalar BlstG1Point::GetHashWithSalt(const uint64_t salt) const
{
    HashWriter hasher{};
    hasher << *this;
    hasher << salt;
    return BlstScalar(hasher.GetHash());
}
