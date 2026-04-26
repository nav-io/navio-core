// Copyright (c) 2022 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/arith/mcl/mcl_g1point.h>
#include <random.h>
#include <streams.h>

#include <numeric>

namespace {
thread_local std::vector<MclG1Point>* g_mcl_g1_deferral_collector = nullptr;
thread_local int g_mcl_g1_skip_depth = 0;
}

MclG1Point::MclG1Point()
{
    // Replacement of mclBnG1_clear to avoid segfault in static context
    std::memset(&m_point, 0, sizeof(MclG1Point::Underlying));
}

MclG1Point::MclG1Point(const std::vector<uint8_t>& v)
{
    MclG1Point::SetVch(v);
}

MclG1Point::MclG1Point(const MclG1Point::Underlying& p)
{
    m_point = p;
}

MclG1Point::MclG1Point(const uint256& n)
{
    // Not using MclG1Point::MapToPoint since uint256 deserialization is big-endian
    MclG1Point temp;
    mclBnFp v;
    if (mclBnFp_setBigEndianMod(&v, n.data(), n.size()) != 0) {
        throw std::runtime_error(std::string(__func__) + ": mclBnFp_setLittleEndianMod failed");
    }
    if (mclBnFp_mapToG1(&temp.m_point, &v) != 0) {
        throw std::runtime_error(std::string(__func__) + ": mclBnFp_mapToG1 failed");
    }
    m_point = temp.m_point;
}

const MclG1Point::Underlying& MclG1Point::GetUnderlying() const
{
    return m_point;
}

MclG1Point MclG1Point::operator=(const Underlying& rhs)
{
    m_point = rhs;
    return *this;
}

MclG1Point MclG1Point::operator+(const MclG1Point& rhs) const
{
    MclG1Point ret;
    mclBnG1_add(&ret.m_point, &m_point, &rhs.m_point);
    return ret;
}

MclG1Point MclG1Point::operator-(const MclG1Point& rhs) const
{
    MclG1Point ret;
    mclBnG1_sub(&ret.m_point, &m_point, &rhs.m_point);
    return ret;
}

MclG1Point MclG1Point::operator*(const MclG1Point::Scalar& rhs) const
{
    MclG1Point ret;
    mclBnG1_mul(&ret.m_point, &m_point, &rhs.m_scalar);
    return ret;
}

std::vector<MclG1Point> MclG1Point::operator*(const std::vector<MclG1Point::Scalar>& ss) const
{
    if (ss.size() == 0) {
        throw std::runtime_error(std::string(__func__) + ": Cannot multiply MclG1Point by empty scalar vector");
    }
    std::vector<MclG1Point> ret;

    MclG1Point p = *this;
    for (size_t i = 0; i < ss.size(); ++i) {
        MclG1Point q = p * ss[i];
        ret.push_back(q);
    }
    return ret;
}

MclG1Point MclG1Point::Double() const
{
    MclG1Point temp;
    mclBnG1_dbl(&temp.m_point, &m_point);
    return temp;
}

MclG1Point MclG1Point::GetBasePoint()
{
    using Point = MclG1Point::Underlying;
    static Point* g = nullptr;
    if (g == nullptr) {
        g = new Point();
        auto g_str = "1 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569"s;
        if (mclBnG1_setStr(g, g_str.c_str(), g_str.length(), 10) == -1) {
            throw std::runtime_error(std::string(__func__) + ": mclBnG1_setStr failed");
        }
    }
    MclG1Point ret(*g);
    return ret;
}

MclG1Point MclG1Point::MapToPoint(const std::vector<uint8_t>& vec, const Endianness e)
{
    if (vec.size() == 0) {
        throw std::runtime_error(std::string(__func__) + ": Cannot map empty input vector to a point");
    }
    if (vec.size() > sizeof(mclBnFp) * 2) {
        throw std::runtime_error(std::string(__func__) + ": Size of vector must be smaller or equal to the size of mclBnFp * 2");
    }
    MclG1Point temp;
    mclBnFp v;
    if (e == Endianness::Little) {
        if (mclBnFp_setLittleEndianMod(&v, &vec[0], vec.size()) != 0) {
            throw std::runtime_error(std::string(__func__) + ": mclBnFp_setLittleEndianMod failed");
        }
    } else {
        if (mclBnFp_setBigEndianMod(&v, &vec[0], vec.size()) != 0) {
            throw std::runtime_error(std::string(__func__) + ": mclBnFp_setBigEndianMod failed");
        }
    }
    if (mclBnFp_mapToG1(&temp.m_point, &v) != 0) {
        throw std::runtime_error(std::string(__func__) + ": mclBnFp_mapToG1 failed");
    }
    return temp;
}

MclG1Point MclG1Point::MapToPoint(const std::string& s, const Endianness e)
{
    std::vector<uint8_t> vec(s.begin(), s.end());
    return MapToPoint(vec, e);
}

MclG1Point MclG1Point::HashAndMap(const std::vector<uint8_t>& vec)
{
    mclBnG1 p;
    if (mclBnG1_hashAndMapTo(&p, &vec[0], vec.size()) != 0) {
        throw std::runtime_error(std::string(__func__) + ": mclBnG1_hashAndMapTo failed");
    }
    MclG1Point temp(p);
    return temp;
}

bool MclG1Point::operator==(const MclG1Point& rhs) const
{
    return mclBnG1_isEqual(&m_point, &rhs.m_point);
}

bool MclG1Point::operator!=(const MclG1Point& rhs) const
{
    return !operator==(rhs);
}

MclG1Point MclG1Point::Rand()
{
    auto g = GetBasePoint();
    return g * MclScalar::Rand();
}

bool MclG1Point::IsValid() const
{
    return mclBnG1_isValid(&m_point) == 1;
}

bool MclG1Point::IsZero() const
{
    MclG1Point zero;
    if (std::memcmp(&m_point, &zero.m_point, sizeof(MclG1Point::Underlying)) == 0) return true;
    return mclBnG1_isZero(&m_point);
}

std::vector<uint8_t> MclG1Point::GetVch() const
{
    std::vector<uint8_t> b(SERIALIZATION_SIZE);
    if (mclBnG1_serialize(&b[0], SERIALIZATION_SIZE, &m_point) == 0) {
        MclG1Point ret;
        return ret.GetVch();
    }
    return b;
}

bool MclG1Point::SetVch(const std::vector<uint8_t>& b)
{
    // auto g = GetBasePoint();
    // auto x = GetBasePoint().GetVch();
    // if (mclBnG1_deserialize(&m_point, &x[0], x.size()) == 0) {
    if (mclBnG1_deserialize(&m_point, &b[0], b.size()) == 0) {
        mclBnG1_clear(&m_point);
        return false;
    }
    // Enforce prime-order subgroup membership. BLS12-381 G1 has a cofactor,
    // so curve membership alone is insufficient: an attacker could submit a
    // point on E(F_p) that lies outside the order-r subgroup where the
    // discrete-log assumption does not apply. mclBnG1_isValidOrder returns 1
    // iff the point has order dividing r.
    //
    // The point at infinity (zero commitment) is explicitly permitted — it
    // is the identity in G1 and is used throughout commitment arithmetic.
    if (!mclBnG1_isZero(&m_point) && mclBnG1_isValidOrder(&m_point) != 1) {
        mclBnG1_clear(&m_point);
        return false;
    }
    return true;
}

bool MclG1Point::SetVchUnchecked(const std::vector<uint8_t>& b)
{
    if (mclBnG1_deserialize(&m_point, &b[0], b.size()) == 0) {
        mclBnG1_clear(&m_point);
        return false;
    }
    return true;
}

std::vector<MclG1Point>* MclG1Point::CurrentDeferralCollector()
{
    return g_mcl_g1_deferral_collector;
}

bool MclG1Point::IsSubgroupCheckSkipped()
{
    return g_mcl_g1_skip_depth > 0;
}

MclG1Point::SubgroupCheckSkipScope::SubgroupCheckSkipScope()
    : m_prev_depth(g_mcl_g1_skip_depth)
{
    g_mcl_g1_skip_depth = m_prev_depth + 1;
}

MclG1Point::SubgroupCheckSkipScope::~SubgroupCheckSkipScope()
{
    g_mcl_g1_skip_depth = m_prev_depth;
}

MclG1Point::SubgroupCheckDeferralScope::SubgroupCheckDeferralScope()
    : m_prev(g_mcl_g1_deferral_collector)
{
    g_mcl_g1_deferral_collector = &m_collected;
}

MclG1Point::SubgroupCheckDeferralScope::~SubgroupCheckDeferralScope()
{
    g_mcl_g1_deferral_collector = m_prev;
}

std::vector<MclG1Point> MclG1Point::SubgroupCheckDeferralScope::Take()
{
    return std::exchange(m_collected, {});
}

// mclBnG1_normalizeVec uses __builtin_alloca(sizeof(Fp) * n) inside
// mcl::ec::normalizeVecJacobi. For BLS12-381 sizeof(Fp) ≈ 48 bytes, so
// n=10000 asks for ~480 KB stack. Cap batch size so nested callers never
// blow the stack — particularly important when UndoWriteToDisk feeds
// thousands of G1 points from a single 2000+ input BLSCT block.
static constexpr size_t kMclG1NormalizeChunk = 512;

void MclG1Point::BatchNormalize(std::span<MclG1Point> pts)
{
    if (pts.empty()) return;
    // MclG1Point wraps one mclBnG1 with no other non-static fields, so the
    // span of MclG1Point is a contiguous array of mclBnG1 in memory.
    static_assert(sizeof(MclG1Point) == sizeof(mclBnG1),
                  "MclG1Point must be layout-compatible with mclBnG1");
    auto* raw = reinterpret_cast<mclBnG1*>(&pts.data()->m_point);
    for (size_t off = 0; off < pts.size(); off += kMclG1NormalizeChunk) {
        const size_t chunk = std::min(kMclG1NormalizeChunk, pts.size() - off);
        mclBnG1_normalizeVec(raw + off, raw + off, chunk);
    }
}

void MclG1Point::BatchNormalize(std::span<MclG1Point* const> pts)
{
    if (pts.empty()) return;
    // Scattered-pointer path: copy the inputs into a contiguous buffer,
    // batch-normalise, then write back. Chunked for the same alloca-stack
    // safety reason as the contiguous overload above.
    for (size_t off = 0; off < pts.size(); off += kMclG1NormalizeChunk) {
        const size_t chunk = std::min(kMclG1NormalizeChunk, pts.size() - off);
        std::vector<mclBnG1> buffer(chunk);
        for (size_t i = 0; i < chunk; ++i) {
            buffer[i] = pts[off + i]->m_point;
        }
        mclBnG1_normalizeVec(buffer.data(), buffer.data(), chunk);
        for (size_t i = 0; i < chunk; ++i) {
            pts[off + i]->m_point = buffer[i];
        }
    }
}

// BatchCheckSubgroup pulls in OS randomness (GetRandBytes) which is not part
// of the minimal libblsct.a public API surface. Compile it out of the
// libblsct-only build; it is only consumed by full-node code paths
// (e.g. pos/proof.h::Unserialize).
#ifndef LIBBLSCT
bool MclG1Point::BatchCheckSubgroup(std::span<const MclG1Point> pts)
{
    if (pts.empty()) return true;

    // Fast path: a single point — per-point check, avoids RNG + multiexp overhead.
    if (pts.size() == 1) {
        if (mclBnG1_isZero(&pts[0].m_point)) return true;
        return mclBnG1_isValidOrder(&pts[0].m_point) == 1;
    }

    // Sample fresh 256-bit scalars r_i from OS randomness. Verification runs
    // after the proof is committed on-chain, so the attacker cannot grind
    // against the scalars.
    std::vector<mclBnG1> bases;
    std::vector<mclBnFr> exps;
    bases.reserve(pts.size());
    exps.reserve(pts.size());
    for (const auto& p : pts) {
        if (mclBnG1_isZero(&p.m_point)) continue;
        bases.push_back(p.m_point);
        uint256 r;
        GetRandBytes(r);
        mclBnFr scalar;
        if (mclBnFr_setLittleEndianMod(&scalar, r.data(), r.size()) != 0) {
            return false;
        }
        exps.push_back(scalar);
    }

    if (bases.empty()) return true;

    mclBnG1 combined;
    mclBnG1_mulVec(&combined, bases.data(), exps.data(), bases.size());

    if (mclBnG1_isZero(&combined)) return true;
    return mclBnG1_isValidOrder(&combined) == 1;
}
#endif // LIBBLSCT

std::string MclG1Point::GetString(const uint8_t& radix) const
{
    char str[1024];
    if (mclBnG1_getStr(str, sizeof(str), &m_point, radix) == 0) {
        throw std::runtime_error(std::string(__func__) + ": mclBnG1_getStr failed");
    }
    return std::string(str);
}

void MclG1Point::SetString(const std::string& hex)
{
    if (mclBnG1_setStr(&m_point, hex.c_str(), hex.size(), 16) == 0) {
        throw std::runtime_error(std::string(__func__) + ": mclBnG1_setStr failed");
    }
}

MclG1Point::Scalar MclG1Point::GetHashWithSalt(const uint64_t salt) const
{
    HashWriter hasher{};
    hasher << *this;
    hasher << salt;
    MclScalar hash(hasher.GetHash());
    return hash;
}
