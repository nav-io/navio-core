// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/arith/blst/blst_scalar.h>
#include <blsct/arith/blst/blst_strconv.h>
#include <blsct/common.h>
#include <crypto/sha256.h>
#ifndef LIBBLSCT
#include <random.h>
#endif
#include <util/strencodings.h>

#include <cstring>
#include <stdexcept>

#ifdef LIBBLSCT
#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#if defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__) || (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)))
#include <sys/random.h>
#define BLST_SCALAR_HAVE_GETENTROPY 1
#endif
#endif
#endif // LIBBLSCT

namespace {
const blst_scalar& ZeroScalar()
{
    static const blst_scalar z{};
    return z;
}

// Fill `buf` with OS entropy. The full node uses random.cpp's GetRandBytes;
// the standalone libblsct.a does not carry random.cpp (it needs the whole
// util layer), and the mcl backend it replaced brought its own CSPRNG, so
// keep an OS-only source here for that build. Throws if the OS refuses.
void RandBytes(unsigned char* buf, size_t n)
{
#ifndef LIBBLSCT
    GetRandBytes({buf, n});
#elif defined(_WIN32)
    if (BCryptGenRandom(nullptr, buf, static_cast<ULONG>(n), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        throw std::runtime_error("BlstScalar::Rand: BCryptGenRandom failed");
    }
#else
#ifdef BLST_SCALAR_HAVE_GETENTROPY
    if (getentropy(buf, n) == 0) return;
#endif
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) throw std::runtime_error("BlstScalar::Rand: cannot open /dev/urandom");
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r <= 0) { close(fd); throw std::runtime_error("BlstScalar::Rand: /dev/urandom read failed"); }
        got += static_cast<size_t>(r);
    }
    close(fd);
#endif
}
} // namespace

blst_scalar BlstScalar::ToScalar() const
{
    blst_scalar s{};
    blst_scalar_from_fr(&s, &m_scalar);
    return s;
}

void BlstScalar::FromScalar(const blst_scalar& s)
{
    blst_fr_from_scalar(&m_scalar, &s);
}

BlstScalar::BlstScalar()
{
    std::memset(&m_scalar, 0, sizeof(Underlying));
}

BlstScalar::BlstScalar(const int64_t& n)
{
    operator=(n);
}

BlstScalar::BlstScalar(const std::vector<uint8_t>& v)
{
    SetVch(v);
}

template <size_t L>
BlstScalar::BlstScalar(const std::array<uint8_t, L>& a)
{
    std::vector<uint8_t> v(a.cbegin(), a.cend());
    SetVch(v);
}
template BlstScalar::BlstScalar(const std::array<uint8_t, 48ul>& v);

BlstScalar::BlstScalar(const Underlying& other_underlying)
{
    m_scalar = other_underlying;
}

BlstScalar::BlstScalar(const uint256& n)
{
    // Mirrors mclBnFr_setBigEndianMod(n.data(), 32): the raw uint256 bytes
    // are interpreted as a big-endian integer and reduced mod r.
    blst_scalar s{};
    blst_scalar_from_be_bytes(&s, n.data(), 32);
    FromScalar(s);
}

BlstScalar::BlstScalar(const std::string& s, int radix)
{
    // Horner evaluation in Fr: acc = acc * radix + digit. Inputs are < r in
    // every caller, so this equals mcl's setStr for the same string.
    std::vector<uint8_t> be;
    try {
        be = blst_arith::RadixStringToBytes(s, radix, 64);
    } catch (const std::exception&) {
        throw std::runtime_error(std::string(__func__) + ": Failed to instantiate Scalar from " + s);
    }
    blst_scalar sc{};
    blst_scalar_from_be_bytes(&sc, be.data(), be.size());
    FromScalar(sc);
}

BlstScalar::BlstScalar(const std::vector<uint8_t>& msg, uint8_t index)
{
    std::vector<uint8_t> vec;
    vec.resize(msg.size() + 1);
    vec[0] = index;
    std::copy(msg.begin(), msg.end(), &vec[1]);

    CSHA256 hasher;
    hasher.Write(&vec[0], vec.size());
    uint8_t hash[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(hash);

    // mclBnFr_setLittleEndianMod equivalent.
    blst_scalar s{};
    blst_scalar_from_le_bytes(&s, hash, CSHA256::OUTPUT_SIZE);
    FromScalar(s);
}

BlstScalar BlstScalar::operator+(const BlstScalar& rhs) const
{
    BlstScalar ret;
    blst_fr_add(&ret.m_scalar, &m_scalar, &rhs.m_scalar);
    return ret;
}

BlstScalar BlstScalar::operator-(const BlstScalar& rhs) const
{
    BlstScalar ret;
    blst_fr_sub(&ret.m_scalar, &m_scalar, &rhs.m_scalar);
    return ret;
}

BlstScalar BlstScalar::operator*(const BlstScalar& rhs) const
{
    BlstScalar ret;
    blst_fr_mul(&ret.m_scalar, &m_scalar, &rhs.m_scalar);
    return ret;
}

BlstScalar BlstScalar::operator/(const BlstScalar& rhs) const
{
    // mcl's Fr::div maps division by zero to zero (inv(0) == 0); keep that.
    if (rhs.IsZero()) return BlstScalar();
    BlstScalar inv;
    blst_fr_inverse(&inv.m_scalar, &rhs.m_scalar);
    return *this * inv;
}

BlstScalar BlstScalar::ApplyBitwiseOp(const BlstScalar& a, const BlstScalar& b,
                                      std::function<uint8_t(uint8_t, uint8_t)> op) const
{
    BlstScalar ret;
    auto a_vec = a.GetVch();
    auto b_vec = b.GetVch();

    auto& longer = a_vec.size() > b_vec.size() ? a_vec : b_vec;
    auto& shorter = b_vec.size() < a_vec.size() ? b_vec : a_vec;

    std::vector<uint8_t> c_vec(longer.size());

    for (size_t i = 0; i < shorter.size(); i++) {
        c_vec[i] = op(longer[i], shorter[i]);
    }
    for (size_t i = shorter.size(); i < longer.size(); i++) {
        c_vec[i] = op(longer[i], 0);
    }
    ret.SetVch(c_vec);
    return ret;
}

BlstScalar BlstScalar::operator|(const BlstScalar& rhs) const
{
    return ApplyBitwiseOp(*this, rhs, [](uint8_t a, uint8_t b) -> uint8_t { return a | b; });
}

BlstScalar BlstScalar::operator^(const BlstScalar& rhs) const
{
    return ApplyBitwiseOp(*this, rhs, [](uint8_t a, uint8_t b) -> uint8_t { return a ^ b; });
}

BlstScalar BlstScalar::operator&(const BlstScalar& rhs) const
{
    return ApplyBitwiseOp(*this, rhs, [](uint8_t a, uint8_t b) -> uint8_t { return a & b; });
}

BlstScalar BlstScalar::operator~() const
{
    // Same semantics as MclScalar: complement of the low 8 bytes only.
    const int64_t n_complement_scalar = (int64_t)~GetUint64();
    return BlstScalar(n_complement_scalar);
}

BlstScalar BlstScalar::operator<<(const uint32_t& shift) const
{
    BlstScalar ret(*this);
    for (uint32_t i = 0; i < shift; ++i) {
        blst_fr_add(&ret.m_scalar, &ret.m_scalar, &ret.m_scalar);
    }
    return ret;
}

BlstScalar BlstScalar::operator>>(const uint32_t& shift) const
{
    // Integer right shift over the canonical representative, as in
    // MclScalar: subtract 1 when odd, then divide by two (in the field).
    static const BlstScalar one(int64_t{1});
    static const BlstScalar two(int64_t{2});
    BlstScalar temp(*this);
    for (uint32_t n = shift; n > 0; --n) {
        blst_scalar s = temp.ToScalar();
        if (s.b[0] & 1) {
            temp = temp - one;
        }
        temp = temp / two;
    }
    return temp;
}

void BlstScalar::operator=(const int64_t& n)
{
    const uint64_t mag = n < 0 ? static_cast<uint64_t>(-(n + 1)) + 1 : static_cast<uint64_t>(n);
    const uint64_t a[4] = {mag, 0, 0, 0};
    blst_fr_from_uint64(&m_scalar, a);
    if (n < 0) blst_fr_cneg(&m_scalar, &m_scalar, true);
}

bool BlstScalar::operator==(const int32_t& rhs) const
{
    BlstScalar temp;
    temp = rhs;
    return *this == temp;
}

bool BlstScalar::operator==(const BlstScalar& rhs) const
{
    return std::memcmp(&m_scalar, &rhs.m_scalar, sizeof(Underlying)) == 0;
}

bool BlstScalar::operator!=(const int32_t& b) const
{
    return !operator==(b);
}

bool BlstScalar::operator!=(const BlstScalar& b) const
{
    return !operator==(b);
}

bool BlstScalar::operator<(const BlstScalar& b) const
{
    return std::memcmp(&(GetVch()[0]), &(b.GetVch()[0]), SERIALIZATION_SIZE) < 0;
}

bool BlstScalar::operator>(const BlstScalar& b) const
{
    return std::memcmp(&(GetVch()[0]), &(b.GetVch()[0]), SERIALIZATION_SIZE) > 0;
}

const BlstScalar::Underlying& BlstScalar::GetUnderlying() const
{
    return m_scalar;
}

bool BlstScalar::IsValid() const
{
    // blst_fr is always a reduced field element.
    return true;
}

bool BlstScalar::IsZero() const
{
    return std::memcmp(&m_scalar, &ZeroScalar(), sizeof(Underlying)) == 0;
}

BlstScalar BlstScalar::Invert() const
{
    if (IsZero()) {
        throw std::runtime_error(std::string(__func__) + ": Inverse of zero is undefined");
    }
    BlstScalar temp;
    blst_fr_inverse(&temp.m_scalar, &m_scalar);
    return temp;
}

BlstScalar BlstScalar::Negate() const
{
    BlstScalar temp;
    blst_fr_cneg(&temp.m_scalar, &m_scalar, true);
    return temp;
}

BlstScalar BlstScalar::Square() const
{
    BlstScalar temp;
    blst_fr_sqr(&temp.m_scalar, &m_scalar);
    return temp;
}

BlstScalar BlstScalar::Cube() const
{
    return *this * Square();
}

BlstScalar BlstScalar::Pow(const BlstScalar& n) const
{
    BlstScalar temp(int64_t{1});
    BlstScalar bit_val(*this);
    auto bits = n.ToBinaryVec();
    for (auto it = bits.rbegin(); it != bits.rend(); ++it) {
        if (*it) temp = temp * bit_val;
        bit_val = bit_val.Square();
    }
    return temp;
}

BlstScalar BlstScalar::Rand(bool exclude_zero)
{
    BlstScalar temp;
    while (true) {
        unsigned char buf[32];
        RandBytes(buf, sizeof(buf));
        blst_scalar s{};
        blst_scalar_from_le_bytes(&s, buf, sizeof(buf));
        temp.FromScalar(s);
        if (!exclude_zero || !temp.IsZero()) break;
    }
    return temp;
}

uint64_t BlstScalar::GetUint64() const
{
    uint64_t ret = 0;
    std::vector<uint8_t> vch = GetVch();
    for (auto i = 0; i < 8; ++i) {
        ret |= (uint64_t)vch[vch.size() - 1 - i] << i * 8;
    }
    return ret;
}

std::vector<uint8_t> BlstScalar::GetVch(const bool trim_preceeding_zeros) const
{
    std::vector<uint8_t> vec(SERIALIZATION_SIZE);
    blst_scalar s = ToScalar();
    blst_bendian_from_scalar(vec.data(), &s);
    if (trim_preceeding_zeros) {
        vec = blsct::Common::TrimPreceedingZeros<uint8_t>(vec);
    }
    return vec;
}

void BlstScalar::SetVch(const std::vector<uint8_t>& v)
{
    // mclBnFr_setBigEndianMod rejects inputs longer than 2 * sizeof(Fr) and
    // the wrapper then falls back to zero; mirror that.
    if (v.size() == 0 || v.size() > 2 * SERIALIZATION_SIZE) {
        std::memset(&m_scalar, 0, sizeof(Underlying));
        return;
    }
    blst_scalar s{};
    blst_scalar_from_be_bytes(&s, v.data(), v.size());
    FromScalar(s);
}

void BlstScalar::SetPow2(const uint32_t& n)
{
    BlstScalar temp(int64_t{1});
    for (uint32_t i = n; i != 0; --i) {
        temp = temp * BlstScalar(int64_t{2});
    }
    m_scalar = temp.m_scalar;
}

uint256 BlstScalar::GetHashWithSalt(const uint64_t& salt) const
{
    HashWriter hasher{};
    hasher << *this;
    hasher << salt;
    return hasher.GetHash();
}

std::string BlstScalar::GetString(const int8_t& radix) const
{
    auto be = GetVch();
    return blst_arith::BytesToRadixString(be.data(), be.size(), radix);
}

std::vector<bool> BlstScalar::ToBinaryVec() const
{
    auto bitStr = GetString(2);
    std::vector<bool> vec;
    vec.reserve(bitStr.size());
    for (auto& c : bitStr) {
        vec.push_back(c == '0' ? 0 : 1);
    }
    return vec;
}

bool BlstScalar::GetSeriBit(const uint8_t& n) const
{
    std::vector<uint8_t> vch = GetVch();
    assert(vch.size() == SERIALIZATION_SIZE);
    const uint8_t vchIdx = 31 - n / 8;
    const uint8_t bitIdx = n % 8;
    const uint8_t mask = 1 << bitIdx;
    return (vch[vchIdx] & mask) != 0;
}
