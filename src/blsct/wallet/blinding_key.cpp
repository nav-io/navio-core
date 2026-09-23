// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/private_key.h>
#include <blsct/wallet/blinding_key.h>
#include <crypto/sha256.h>
#include <support/cleanse.h>
#include <tinyformat.h>

#include <cassert>
#include <cstring>
#include <stdexcept>

namespace blsct {

BlstScalar DeriveBlindingKey(Span<const unsigned char> seed, const Outid& outid, const uint32_t counter)
{
    if (seed.size() != BLINDING_KEY_SEED_SIZE) {
        throw std::runtime_error(strprintf("%s: the blinding seed must be %u bytes (got %u)",
                                           __func__, (unsigned)BLINDING_KEY_SEED_SIZE, (unsigned)seed.size()));
    }

    // The material carries the seed, so it is wiped before returning.
    unsigned char material[BLINDING_KEY_MATERIAL_SIZE];
    size_t pos{0};

    std::memcpy(material + pos, BLINDING_KEY_DOMAIN.data(), BLINDING_KEY_DOMAIN.size());
    pos += BLINDING_KEY_DOMAIN.size();

    std::memcpy(material + pos, seed.data(), BLINDING_KEY_SEED_SIZE);
    pos += BLINDING_KEY_SEED_SIZE;

    // Raw serialized (internal) byte order, NOT the reversed display form
    // GetHex() prints. navio-sdk keeps output hashes in display order and
    // reverses them before hashing to land on these same bytes.
    const uint256& outid_bytes = outid.ToUint256();
    std::memcpy(material + pos, outid_bytes.begin(), outid_bytes.size());
    pos += outid_bytes.size();

    material[pos++] = static_cast<unsigned char>((counter >> 24) & 0xff);
    material[pos++] = static_cast<unsigned char>((counter >> 16) & 0xff);
    material[pos++] = static_cast<unsigned char>((counter >> 8) & 0xff);
    material[pos++] = static_cast<unsigned char>(counter & 0xff);

    assert(pos == BLINDING_KEY_MATERIAL_SIZE);

    unsigned char digest[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(material, BLINDING_KEY_MATERIAL_SIZE).Finalize(digest);
    memory_cleanse(material, BLINDING_KEY_MATERIAL_SIZE);

    // BlstScalar's byte constructor reads big-endian and reduces mod r, which
    // is exactly "sha256 interpreted big-endian, reduced mod the group order".
    const BlstScalar k{std::vector<uint8_t>(digest, digest + sizeof(digest))};
    memory_cleanse(digest, sizeof(digest));

    if (k.IsZero()) {
        // ~2^-255. A zero blinding scalar would publish an identity ephemeral
        // key and make the output anyone-can-spend, so never paper over it.
        throw std::runtime_error(strprintf("%s: derived blinding scalar is zero", __func__));
    }

    return k;
}

uint256 OutputAuthDigest(const std::string_view message)
{
    CSHA256 h;
    h.Write(reinterpret_cast<const unsigned char*>(OUTPUT_AUTH_DOMAIN.data()), OUTPUT_AUTH_DOMAIN.size());
    h.Write(reinterpret_cast<const unsigned char*>(message.data()), message.size());

    uint256 digest;
    h.Finalize(digest.begin());
    return digest;
}

std::optional<Outid> CanonicalAnchor(const std::vector<COutPoint>& outpoints)
{
    std::optional<Outid> anchor;
    for (const COutPoint& outpoint : outpoints) {
        // transaction_identifier::operator< forwards to base_blob::Compare,
        // which is a memcmp over the internal byte array -- exactly the
        // "smallest of the 32 bytes in internal order" the derivation
        // specifies, and NOT the reversed display ordering.
        if (!anchor || outpoint.hash < *anchor) anchor = outpoint.hash;
    }
    return anchor;
}

namespace {
//! Try every ordinal below MAX_OUTPUT_SEARCH for one anchor.
std::optional<BlstScalar> TryAnchor(Span<const unsigned char> seed, const Outid& anchor, const BlstG1Point& publicBlindingKey)
{
    for (uint32_t counter = 0; counter < MAX_OUTPUT_SEARCH; ++counter) {
        BlstScalar k;
        try {
            k = DeriveBlindingKey(seed, anchor, counter);
        } catch (const std::exception&) {
            // Only the (untestable) zero-scalar case gets here; skip that
            // ordinal rather than abandoning the whole search.
            continue;
        }
        if (PrivateKey(k).GetPoint() == publicBlindingKey) return k;
    }
    return std::nullopt;
}
} // namespace

std::optional<BlstScalar> RecoverBlindingKey(Span<const unsigned char> seed,
                                             const std::vector<CTxIn>& vin,
                                             const BlstG1Point& publicBlindingKey,
                                             const std::optional<Outid>& canonicalAnchor)
{
    if (seed.size() != BLINDING_KEY_SEED_SIZE) return std::nullopt;
    // The identity is never a legitimate k*G (DeriveBlindingKey refuses to
    // return a zero scalar), so matching against it could only ever be a
    // false positive on a malformed output.
    if (publicBlindingKey.IsZero()) return std::nullopt;

    // Fast path: the anchor the builder would have chosen. Normally hits on
    // the first ordinal.
    if (canonicalAnchor) {
        if (auto k = TryAnchor(seed, *canonicalAnchor, publicBlindingKey)) return k;
    }

    // Fallback: every input, in case the caller could not identify its own
    // inputs (a partial rescan, say) or identified a different set than the
    // build did. Kept deliberately -- the match against publicBlindingKey is
    // self-verifying, so a wrong anchor costs time and nothing else, while
    // relying on the canonical anchor alone would fail silently.
    for (const CTxIn& in : vin) {
        if (canonicalAnchor && in.prevout.hash == *canonicalAnchor) continue; // just tried
        if (auto k = TryAnchor(seed, in.prevout.hash, publicBlindingKey)) return k;
    }

    return std::nullopt;
}

} // namespace blsct
