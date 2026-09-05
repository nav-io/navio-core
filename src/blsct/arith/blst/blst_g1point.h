// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// G1 (BLS12-381) wrapper over supranational/blst. `Blst::Point` for the
// templated BLSCT proof code (see blsct/arith/blst/blst.h).

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

// True while BlstG1Point::LegacyPointDecodeScope is active on this thread;
// honoured by BlstScalar / blsct::Signature deserialization too.
bool BlstLegacyPointDecodeActive();

class FixedBaseWindow; // reads m_point for blst fixed-base wbits tables

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
    // Decode a compressed encoding; enforces the curve equation AND
    // prime-order subgroup membership (the identity is permitted).
    bool SetVch(const std::vector<uint8_t>& vec);

    // SetVch variant that decodes and checks the curve equation but skips the
    // prime-order subgroup check. Used inside a SubgroupCheckDeferralScope so
    // many points can be checked as a single batched multiexp, and under a
    // SubgroupCheckSkipScope for data from trusted-integrity storage.
    bool SetVchUnchecked(const std::vector<uint8_t>& vec);

    // Verify that every point in `pts` lies in the prime-order subgroup of G1
    // (the identity is permitted). Deterministic per-point check; see the
    // note in blst_util.cpp on why a random linear combination is unsound
    // here (G1's cofactor is divisible by 3).
    static bool BatchCheckSubgroup(std::span<const BlstG1Point> pts);

    // Canonicalise every point to its affine (z=1) representation with one
    // batched inversion (Montgomery's trick); pure representation change.
    static void BatchNormalize(std::span<BlstG1Point> pts);
    static void BatchNormalize(std::span<BlstG1Point* const> pts);

    // RAII scope that reroutes subsequent BlstG1Point::Unserialize calls on the
    // current thread through SetVchUnchecked and records the decoded points.
    // On destruction the recorded points are exposed via Take() so the caller
    // can run BatchCheckSubgroup in one multiexp.
    class SubgroupCheckDeferralScope
    {
    public:
        SubgroupCheckDeferralScope();
        ~SubgroupCheckDeferralScope();
        SubgroupCheckDeferralScope(const SubgroupCheckDeferralScope&) = delete;
        SubgroupCheckDeferralScope& operator=(const SubgroupCheckDeferralScope&) = delete;

        // Transfer ownership of the collected points out of the scope. Safe
        // to call multiple times; subsequent calls return an empty vector.
        std::vector<BlstG1Point> Take();

    private:
        std::vector<BlstG1Point>* m_prev;
        std::vector<BlstG1Point> m_collected;
    };

    // RAII scope that disables the subgroup check entirely on the current
    // thread for the duration of the scope. Use ONLY for data loaded from
    // trusted-integrity storage (e.g. our own block files) where the check
    // was already performed on first receipt. Dominates the deferral scope
    // when both are active. Never use for data received from the network.
    class SubgroupCheckSkipScope
    {
    public:
        SubgroupCheckSkipScope();
        ~SubgroupCheckSkipScope();
        SubgroupCheckSkipScope(const SubgroupCheckSkipScope&) = delete;
        SubgroupCheckSkipScope& operator=(const SubgroupCheckSkipScope&) = delete;

    private:
        int m_prev_depth;
    };

    // Internal: if a deferral scope is active on the current thread, the
    // Unserialize path appends to it and skips the per-point subgroup check.
    static std::vector<BlstG1Point>* CurrentDeferralCollector();
    // Internal: non-zero depth means the SubgroupCheckSkipScope is active.
    static bool IsSubgroupCheckSkipped();

    // RAII scope that restores the pre-hardening lenient decoding on the
    // current thread: an undecodable encoding maps to the identity point
    // instead of throwing. Use ONLY for data that is baked into the binary as
    // consensus parameters (e.g. the BLSCT genesis output, whose committed
    // encoding predates the canonical serializer and is never
    // proof-verified) — never for network/peer-supplied data or wallet state.
    class LegacyPointDecodeScope
    {
    public:
        LegacyPointDecodeScope();
        ~LegacyPointDecodeScope();
        LegacyPointDecodeScope(const LegacyPointDecodeScope&) = delete;
        LegacyPointDecodeScope& operator=(const LegacyPointDecodeScope&) = delete;

    private:
        int m_prev_depth;
    };
    // Internal: non-zero depth means LegacyPointDecodeScope is active.
    static bool IsLegacyDecodeActive();

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
        // Fail loudly on undecodable input: any malformed or non-canonical
        // 48-byte field is a deserialization error, never a silent identity
        // commitment/key. The legacy-decode scope keeps the historical
        // lenient behaviour for binary-baked consensus parameters ONLY.
        const bool legacy = IsLegacyDecodeActive();
        if (IsSubgroupCheckSkipped()) {
            if (!SetVchUnchecked(vec)) {
                if (legacy) { SetZeroPoint(); return; }
                throw std::ios_base::failure("BlstG1Point: invalid encoding");
            }
        } else if (auto* collector = CurrentDeferralCollector()) {
            if (!SetVchUnchecked(vec)) {
                if (legacy) { SetZeroPoint(); return; }
                throw std::ios_base::failure("BlstG1Point: invalid encoding");
            }
            collector->push_back(*this);
        } else {
            if (!SetVch(vec)) {
                if (legacy) { SetZeroPoint(); return; }
                throw std::ios_base::failure("BlstG1Point: invalid or off-subgroup encoding");
            }
        }
    }

    // Value-initialised (see BlstScalar::m_scalar): all-zero blst_p1 is the
    // identity and MemorySanitizer needs the memory unpoisoned before blst's
    // assembly writes it.
    Underlying m_point{};

    static constexpr int SERIALIZATION_SIZE = 384 / 8;

    // Domain separation tag for HashAndMap (RFC 9380 hash-to-curve, the
    // BLS-signature G1 "POP" ciphersuite tag; consensus-critical).
    static constexpr const char* HASH_TO_G1_DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

private:
    // Set this point to the group identity (point at infinity).
    void SetZeroPoint() { *this = BlstG1Point(); }
};

#endif // NAVIO_BLSCT_ARITH_BLST_BLST_G1POINT_H
