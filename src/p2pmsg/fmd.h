// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_P2PMSG_FMD_H
#define BITCOIN_P2PMSG_FMD_H

#include <blsct/arith/blst/blst_g1point.h>
#include <blsct/arith/blst/blst_scalar.h>

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace p2pmsg {

/**
 * Fuzzy Message Detection (FMD2), instantiated over BLS12-381 G1.
 *
 * Scheme: Beck, Len, Miers, Green, "Fuzzy Message Detection", ePrint 2021/089,
 * Figure 3. Only the group, the hash instantiations and the seed-derived
 * KeyGen are ours; the algorithms below are the paper's.
 *
 * WHAT IT IS FOR. The bus deliberately carries no recipient field: an envelope
 * is kind || PoWHeader || EciesPacket and the only way to learn who a message
 * is for is to hold the key and try. Excellent for privacy, useless for a
 * store that wants to hand a returning client the messages it missed, because
 * there is nothing to index on.
 *
 * FMD gives the store a filter that matches the recipient's messages plus a
 * 2^-n fraction of everyone else's, where n is chosen by the RETRIEVING CLIENT.
 * The property that matters: holding someone's public clue key does NOT let you
 * test whether a flag is theirs. Testing needs a detection key, derived from
 * the secret. A plain tag like H(pubkey || epoch) fails exactly here, which is
 * why this is worth 83 bytes per envelope.
 *
 * WHAT THE DETECTOR LEARNS. The set of envelopes matching the precision-n key
 * it was given -- the recipient's, plus 2^-n of everything else -- and nothing
 * about which is which. A detection key keeps working on future flags, so it is
 * scoped to a key epoch and rotated with the inbox prekey.
 *
 * NOT USED: the compact single-point clue key some deployments use, where
 * x_i = x + H(X||i). It is 48 bytes instead of 1152, and unusable here: H(X||i)
 * is public, so a detector given x_1 recovers x and can then test at full
 * precision 2^-gamma. Precision would stop being the client's choice and become
 * the detector's. We pay the 1152 bytes, once per epoch, to keep it enforced.
 */

//! Number of flag bits, i.e. the maximum detection precision (2^-gamma).
static constexpr size_t FMD_GAMMA = 24;

static constexpr size_t FMD_POINT_SIZE = 48;  //!< compressed G1
static constexpr size_t FMD_SCALAR_SIZE = 32; //!< Fr, big-endian

//! gamma is a multiple of 8, so the packed bits have no spare padding. (Spare
//! bits would not be malleable either -- the scalar hash covers whole bytes --
//! but keeping it exact avoids having to reason about it.)
static_assert(FMD_GAMMA % 8 == 0, "FMD_GAMMA must be a multiple of 8");
static constexpr size_t FMD_BITS_SIZE = FMD_GAMMA / 8;

//! Wire size of a flag: u (48) || y (32) || c (3) = 83 bytes.
static constexpr size_t FMD_FLAG_SIZE = FMD_POINT_SIZE + FMD_SCALAR_SIZE + FMD_BITS_SIZE;

//! Wire size of a clue key: gamma compressed G1 points.
static constexpr size_t FMD_CLUE_KEY_SIZE = FMD_GAMMA * FMD_POINT_SIZE;

//! The public key a sender needs in order to flag a message to someone.
struct FmdClueKey {
    std::array<BlstG1Point, FMD_GAMMA> h;

    //! FMD_CLUE_KEY_SIZE bytes, h_1 .. h_gamma compressed.
    std::vector<uint8_t> ToBytes() const;
    //! Parses and validates every point (on-curve, in-subgroup, not infinity).
    static std::optional<FmdClueKey> FromBytes(std::span<const uint8_t> bytes);
};

//! The recipient's root secret. Never leaves the owner; detection keys are
//! derived from it per precision.
struct FmdSecretKey {
    std::array<BlstScalar, FMD_GAMMA> x;

    FmdClueKey GetClueKey() const;

    //! Detection key for false-positive rate 2^-n: the first n scalars, 32
    //! bytes each. Returns empty for n == 0 or n > FMD_GAMMA. The x_i are
    //! INDEPENDENT, so a precision-n key does not yield precision n+1.
    std::vector<uint8_t> Extract(size_t n) const;

    static FmdSecretKey Random();
    //! Deterministic derivation so a key survives a restore from seed.
    static FmdSecretKey FromSeed(std::span<const uint8_t> seed, uint32_t epoch);
};

//! Flag a message to `ck`. Returns FMD_FLAG_SIZE bytes. Costs gamma + 2 G1
//! multiplications -- negligible beside the envelope's proof of work.
std::vector<uint8_t> FmdFlag(const FmdClueKey& ck);

//! Test `flag` against a detection key from Extract(). Precision is taken from
//! the key length. False for any malformed input. Costs n + 2 G1
//! multiplications; this is the per-envelope cost of an archive scan.
bool FmdTest(std::span<const uint8_t> detection_key, std::span<const uint8_t> flag);

} // namespace p2pmsg

#endif // BITCOIN_P2PMSG_FMD_H
