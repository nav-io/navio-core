// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <p2pmsg/fmd.h>

#include <crypto/sha256.h>
#include <crypto/sha512.h>

#include <cstring>

namespace p2pmsg {

namespace {

//! Domain separation. H : G^3 -> {0,1} and G : G x {0,1}^gamma -> Zq in the
//! paper; distinct tags keep them independent random oracles.
constexpr char TAG_BIT[] = "navio-p2pmsg/fmd/v1/bit";
constexpr char TAG_SCALAR[] = "navio-p2pmsg/fmd/v1/scalar";
constexpr char TAG_KEY[] = "navio-p2pmsg/fmd/v1/key";

void WriteTag(CSHA256& h, const char* tag)
{
    h.Write(reinterpret_cast<const uint8_t*>(tag), std::strlen(tag));
}
void WriteTag(CSHA512& h, const char* tag)
{
    h.Write(reinterpret_cast<const uint8_t*>(tag), std::strlen(tag));
}

void WritePoint(CSHA256& h, const BlstG1Point& p)
{
    const auto v = p.GetVch();
    h.Write(v.data(), v.size());
}
void WritePoint(CSHA512& h, const BlstG1Point& p)
{
    const auto v = p.GetVch();
    h.Write(v.data(), v.size());
}

//! H(u || s || w) -> one bit. `s` is h_i^r for the sender and u^{x_i} for the
//! detector; they are the same point exactly when the flag was made for this
//! key, which is what makes the scheme work.
uint8_t HashBit(const BlstG1Point& u, const BlstG1Point& s, const BlstG1Point& w)
{
    CSHA256 h;
    WriteTag(h, TAG_BIT);
    WritePoint(h, u);
    WritePoint(h, s);
    WritePoint(h, w);
    uint8_t out[CSHA256::OUTPUT_SIZE];
    h.Finalize(out);
    return out[0] & 1;
}

//! G(u || c_1..c_gamma) -> Zq. Hashed to 64 bytes and reduced, so the result is
//! statistically uniform mod r (a 32-byte reduction would be measurably biased).
BlstScalar HashScalar(const BlstG1Point& u, std::span<const uint8_t> bits)
{
    CSHA512 h;
    WriteTag(h, TAG_SCALAR);
    WritePoint(h, u);
    h.Write(bits.data(), bits.size());
    uint8_t out[CSHA512::OUTPUT_SIZE];
    h.Finalize(out);
    BlstScalar s;
    s.SetVch(std::vector<uint8_t>(out, out + CSHA512::OUTPUT_SIZE));
    return s;
}

bool GetBit(std::span<const uint8_t> bits, size_t i)
{
    return (bits[i >> 3] >> (i & 7)) & 1;
}

void SetBit(std::vector<uint8_t>& bits, size_t i, bool v)
{
    if (v) bits[i >> 3] |= static_cast<uint8_t>(1u << (i & 7));
}

BlstScalar ScalarFromBytes(std::span<const uint8_t> b)
{
    BlstScalar s;
    s.SetVch(std::vector<uint8_t>(b.begin(), b.end()));
    return s;
}

} // namespace

std::vector<uint8_t> FmdClueKey::ToBytes() const
{
    std::vector<uint8_t> out;
    out.reserve(FMD_CLUE_KEY_SIZE);
    for (const auto& p : h) {
        const auto v = p.GetVch();
        out.insert(out.end(), v.begin(), v.end());
    }
    return out;
}

std::optional<FmdClueKey> FmdClueKey::FromBytes(std::span<const uint8_t> bytes)
{
    if (bytes.size() != FMD_CLUE_KEY_SIZE) return std::nullopt;
    FmdClueKey ck;
    for (size_t i = 0; i < FMD_GAMMA; ++i) {
        const auto chunk = bytes.subspan(i * FMD_POINT_SIZE, FMD_POINT_SIZE);
        // SetVch checks the curve equation AND prime-order subgroup membership.
        if (!ck.h[i].SetVch(std::vector<uint8_t>(chunk.begin(), chunk.end()))) return std::nullopt;
        // Infinity would make h_i^r infinity for every r, so every sender would
        // derive the same bit and the flag would carry no information.
        if (ck.h[i].IsZero()) return std::nullopt;
    }
    return ck;
}

FmdClueKey FmdSecretKey::GetClueKey() const
{
    const BlstG1Point g = BlstG1Point::GetBasePoint();
    FmdClueKey ck;
    for (size_t i = 0; i < FMD_GAMMA; ++i) ck.h[i] = g * x[i];
    return ck;
}

std::vector<uint8_t> FmdSecretKey::Extract(size_t n) const
{
    if (n == 0 || n > FMD_GAMMA) return {};
    std::vector<uint8_t> out;
    out.reserve(n * FMD_SCALAR_SIZE);
    for (size_t i = 0; i < n; ++i) {
        const auto v = x[i].GetVch();
        out.insert(out.end(), v.begin(), v.end());
    }
    return out;
}

FmdSecretKey FmdSecretKey::Random()
{
    FmdSecretKey sk;
    for (auto& s : sk.x) s = BlstScalar::Rand(/*exclude_zero=*/true);
    return sk;
}

FmdSecretKey FmdSecretKey::FromSeed(std::span<const uint8_t> seed, uint32_t epoch)
{
    FmdSecretKey sk;
    for (uint32_t i = 0; i < FMD_GAMMA; ++i) {
        CSHA512 h;
        WriteTag(h, TAG_KEY);
        h.Write(seed.data(), seed.size());
        const uint8_t ep[4] = {static_cast<uint8_t>(epoch), static_cast<uint8_t>(epoch >> 8),
                               static_cast<uint8_t>(epoch >> 16), static_cast<uint8_t>(epoch >> 24)};
        h.Write(ep, sizeof(ep));
        const uint8_t idx[4] = {static_cast<uint8_t>(i), static_cast<uint8_t>(i >> 8),
                                static_cast<uint8_t>(i >> 16), static_cast<uint8_t>(i >> 24)};
        h.Write(idx, sizeof(idx));
        uint8_t out[CSHA512::OUTPUT_SIZE];
        h.Finalize(out);
        sk.x[i].SetVch(std::vector<uint8_t>(out, out + CSHA512::OUTPUT_SIZE));
    }
    return sk;
}

std::vector<uint8_t> FmdFlag(const FmdClueKey& ck)
{
    const BlstG1Point g = BlstG1Point::GetBasePoint();

    // u = g^r is the shared ElGamal element; every k_i is keyed off h_i^r.
    const BlstScalar r = BlstScalar::Rand(/*exclude_zero=*/true);
    const BlstG1Point u = g * r;

    // w = g^z is a chameleon-hash commitment. Binding (y, m) to the whole
    // ciphertext below is what makes the scheme CCA-secure: mauling any c_i
    // changes m, and w then fails to reproduce, randomising every bit.
    const BlstScalar z = BlstScalar::Rand(/*exclude_zero=*/true);
    const BlstG1Point w = g * z;

    std::vector<uint8_t> bits(FMD_BITS_SIZE, 0);
    for (size_t i = 0; i < FMD_GAMMA; ++i) {
        const uint8_t k = HashBit(u, ck.h[i] * r, w);
        SetBit(bits, i, (k ^ 1) != 0);
    }

    // Spans are built explicitly from containers throughout p2pmsg: libc++ 14
    // (the Ubuntu 22.04 CI compiler) ships no std::span range constructor, so
    // a std::vector does not convert on its own.
    const BlstScalar m = HashScalar(u, std::span<const uint8_t>{bits.data(), bits.size()});
    const BlstScalar y = (z - m) * r.Invert();

    std::vector<uint8_t> out;
    out.reserve(FMD_FLAG_SIZE);
    const auto ub = u.GetVch();
    out.insert(out.end(), ub.begin(), ub.end());
    const auto yb = y.GetVch();
    out.insert(out.end(), yb.begin(), yb.end());
    out.insert(out.end(), bits.begin(), bits.end());
    return out;
}

bool FmdTest(std::span<const uint8_t> detection_key, std::span<const uint8_t> flag)
{
    if (flag.size() != FMD_FLAG_SIZE) return false;
    if (detection_key.empty() || detection_key.size() % FMD_SCALAR_SIZE != 0) return false;
    const size_t n = detection_key.size() / FMD_SCALAR_SIZE;
    if (n > FMD_GAMMA) return false;

    const auto u_bytes = flag.subspan(0, FMD_POINT_SIZE);
    BlstG1Point u;
    if (!u.SetVch(std::vector<uint8_t>(u_bytes.begin(), u_bytes.end()))) return false;
    // An infinity u makes u^{x_i} infinity for every key, so the same flag
    // would match every recipient -- free targeted spam into every bucket.
    if (u.IsZero() || !u.IsValid()) return false;

    // Reject a non-canonical y. SetVch() reduces mod r, so y and y + r parse
    // to the same scalar and the flag's encoding would otherwise be malleable:
    // a relay could rewrite those 32 bytes and the flag would still match its
    // recipient. Re-serialising and comparing tests canonicality without
    // hardcoding r -- GetVch() always returns the reduced form.
    const auto y_bytes = flag.subspan(FMD_POINT_SIZE, FMD_SCALAR_SIZE);
    const BlstScalar y = ScalarFromBytes(y_bytes);
    if (y.GetVch() != std::vector<uint8_t>(y_bytes.begin(), y_bytes.end())) return false;
    const auto bits = flag.subspan(FMD_POINT_SIZE + FMD_SCALAR_SIZE, FMD_BITS_SIZE);

    const BlstG1Point g = BlstG1Point::GetBasePoint();
    const BlstScalar m = HashScalar(u, bits);
    // Recover the sender's w from the collision (y, m): g^m * u^y = g^m * g^{ry}
    // = g^{m + (z-m)} = g^z.
    const BlstG1Point w = g * m + u * y;

    for (size_t i = 0; i < n; ++i) {
        const BlstScalar xi = ScalarFromBytes(detection_key.subspan(i * FMD_SCALAR_SIZE, FMD_SCALAR_SIZE));
        const uint8_t k = HashBit(u, u * xi, w);
        const uint8_t c = GetBit(bits, i) ? 1 : 0;
        // Every bit of a genuine flag decrypts to the sentinel 1.
        if ((k ^ c) != 1) return false;
    }
    return true;
}

} // namespace p2pmsg
