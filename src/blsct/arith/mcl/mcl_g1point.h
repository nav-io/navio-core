// Copyright (c) 2022 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_ARITH_MCL_MCL_G1POINT_H
#define NAVIO_BLSCT_ARITH_MCL_MCL_G1POINT_H

#define BLS_ETH 1

#include <bls/bls384_256.h>
#include <blsct/arith/endianness.h>
#include <blsct/arith/mcl/mcl_scalar.h>
#include <uint256.h>

#include <stddef.h>
#include <span>
#include <string>
#include <vector>

class MclG1Point
{
public:
    using Underlying = mclBnG1;
    using Scalar = MclScalar;

    MclG1Point();
    MclG1Point(const std::vector<uint8_t>& v);
    MclG1Point(const uint256& n);
    MclG1Point(const Underlying& p);

    MclG1Point operator=(const Underlying& rhs);
    MclG1Point operator+(const MclG1Point& rhs) const;
    MclG1Point operator-(const MclG1Point& rhs) const;
    MclG1Point operator*(const Scalar& rhs) const;

    /**
     * Because  Elements cannot be used here, std::vector is used instead
     */
    std::vector<MclG1Point> operator*(const std::vector<Scalar>& ss) const;

    bool operator==(const MclG1Point& rhs) const;
    bool operator!=(const MclG1Point& rhs) const;

    bool operator<(const MclG1Point& b) const
    {
        return this->GetVch() < b.GetVch();
    };

    MclG1Point Double() const;
    const Underlying& GetUnderlying() const;

    static MclG1Point GetBasePoint();
    static MclG1Point MapToPoint(const std::vector<uint8_t>& vec, const Endianness e = Endianness::Little);
    static MclG1Point MapToPoint(const std::string& s, const Endianness e = Endianness::Little);
    static MclG1Point HashAndMap(const std::vector<uint8_t>& vec);
    static MclG1Point Rand();

    bool IsValid() const;
    bool IsZero() const;

    std::vector<uint8_t> GetVch() const;
    bool SetVch(const std::vector<uint8_t>& vec);

    // SetVch variant that performs the curve-membership decode but skips the
    // prime-order subgroup check. Used inside a SubgroupCheckDeferralScope so
    // many points can be checked as a single batched multiexp instead of one
    // scalar-mul-by-r per point.
    bool SetVchUnchecked(const std::vector<uint8_t>& vec);

    // Verify that every point in `pts` lies in the prime-order subgroup of G1.
    // Uses a random linear combination Q = Σ r_i · P_i and a single
    // mclBnG1_isValidOrder(&Q) check. Sound because the r_i are sampled from
    // OS randomness after the points were committed (post-hoc verification).
    // Probability that Q passes while any P_i is off-subgroup is ≤ 2^-256.
    static bool BatchCheckSubgroup(std::span<const MclG1Point> pts);

    // Canonicalise every point in `pts` to its affine (z=1) representation
    // using Montgomery's trick: one field inversion amortised across the
    // whole batch instead of one inversion per point. This is a pure
    // representation change — the points are mathematically unchanged.
    // Use this before serialising a bulk collection of points to avoid N
    // expensive normalise-on-serialise inversions.
    static void BatchNormalize(std::span<MclG1Point> pts);
    // Overload that accepts a vector of raw pointers for use when points are
    // scattered across nested data structures (e.g. range proofs inside
    // block undo entries).
    static void BatchNormalize(std::span<MclG1Point* const> pts);

    // RAII scope that reroutes subsequent MclG1Point::Unserialize calls on the
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
        std::vector<MclG1Point> Take();

    private:
        std::vector<MclG1Point>* m_prev;
        std::vector<MclG1Point> m_collected;
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
    static std::vector<MclG1Point>* CurrentDeferralCollector();
    // Internal: non-zero depth means the SubgroupCheckSkipScope is active.
    static bool IsSubgroupCheckSkipped();

    std::string GetString(const uint8_t& radix = 16) const;
    void SetString(const std::string& hex);

    Scalar GetHashWithSalt(const uint64_t salt) const;

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
        if (IsSubgroupCheckSkipped()) {
            SetVchUnchecked(vec);
        } else if (auto* collector = CurrentDeferralCollector()) {
            SetVchUnchecked(vec);
            collector->push_back(*this);
        } else {
            SetVch(vec);
        }
    }

    Underlying m_point;

    static constexpr int SERIALIZATION_SIZE = 384 / 8;
};

#endif // NAVIO_BLSCT_ARITH_MCL_MCL_G1POINT_H