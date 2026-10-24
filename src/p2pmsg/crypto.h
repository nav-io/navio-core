// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_P2PMSG_CRYPTO_H
#define BITCOIN_P2PMSG_CRYPTO_H

#include <blsct/private_key.h>
#include <blsct/public_key.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace p2pmsg {

//! 1-layer ECIES over BLS G1 ECDH + ChaCha20Poly1305, no persistent identity.
//!
//! Sender picks a fresh ephemeral BLS keypair per message, derives the shared
//! secret `eph_sk * recipient_pub`, runs it through HKDF to an AEAD key, and
//! encrypts with a zero nonce (safe: the key is unique per message because the
//! ephemeral key is). The recipient recovers the same secret as
//! `recipient_sk * eph_pub` and decrypts.

//! G1 ephemeral pubkey size on the wire.
static constexpr size_t ECIES_EPH_SIZE = blsct::PublicKey::SIZE; // 48
//! Poly1305 tag length.
static constexpr size_t ECIES_TAG_SIZE = 16;

//! Byte-vector formatter that enforces a protocol maximum at the length prefix,
//! before resizing. The generic std::vector<uint8_t> Unserialize allocates up
//! to 5 MiB from an untrusted CompactSize before the stream's short read fails,
//! which a 4 KiB p2pmsg packet must not be able to trigger.
template <uint64_t MaxBytes>
struct BoundedByteVectorFormatter {
    template <typename Stream>
    void Ser(Stream& s, const std::vector<uint8_t>& v) const
    {
        ::WriteCompactSize(s, v.size());
        if (!v.empty()) s.write(MakeByteSpan(v));
    }

    template <typename Stream>
    void Unser(Stream& s, std::vector<uint8_t>& v) const
    {
        const uint64_t size = ::ReadCompactSize(s);
        if (size > MaxBytes) {
            throw std::ios_base::failure("BoundedByteVectorFormatter: length exceeds limit");
        }
        v.resize(static_cast<size_t>(size));
        if (size != 0) s.read(MakeWritableByteSpan(v));
    }
};

//! Largest ciphertext this wire format accepts. The transport caps the whole
//! body at MAX_JOB_BYTES (4096) and the padding ladder tops out at 3584 bytes
//! of plaintext, so this leaves ample headroom while bounding the allocation.
static constexpr uint64_t MAX_ECIES_CIPHERTEXT_BYTES = 4096;

struct EciesPacket {
    blsct::PublicKey eph;                    //!< sender's per-message ephemeral pubkey
    std::vector<uint8_t> ciphertext;         //!< AEAD ciphertext (== plaintext length)
    std::array<uint8_t, ECIES_TAG_SIZE> tag; //!< Poly1305 tag

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, eph);
        ::Serialize(s, Using<BoundedByteVectorFormatter<MAX_ECIES_CIPHERTEXT_BYTES>>(ciphertext));
        ::Serialize(s, tag);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, eph);
        ::Unserialize(s, Using<BoundedByteVectorFormatter<MAX_ECIES_CIPHERTEXT_BYTES>>(ciphertext));
        ::Unserialize(s, tag);
    }

    //! Stable identifier for replay detection: SHA256(eph || ciphertext || tag).
    uint256 MsgHash() const;
};

//! Encrypt `plaintext` to `recipient`. Returns a packet bound to a fresh
//! ephemeral key. `aad` is authenticated but not encrypted (may be empty).
EciesPacket Encrypt(const blsct::PublicKey& recipient,
                    std::span<const uint8_t> plaintext,
                    std::span<const uint8_t> aad = {});

//! Decrypt `pkt` with `sk`. Returns the plaintext on success, std::nullopt on
//! AEAD authentication failure or malformed ephemeral key. Constant-ish:
//! always runs the full ECDH+AEAD before reporting failure.
std::optional<std::vector<uint8_t>> Decrypt(const blsct::PrivateKey& sk,
                                            const EciesPacket& pkt,
                                            std::span<const uint8_t> aad = {});

//! Well-known keypair for PUBLIC announcements (e.g. RFQ requests, standing
//! orders). Its private key is a fixed constant known to everyone, so any node
//! can decrypt these — the encryption is only framing to keep every bus message
//! uniform (same envelope, same PoW gate), not confidentiality. Confidential
//! replies still use the recipient's per-session key.
const blsct::PrivateKey& BroadcastPrivKey();
const blsct::PublicKey& BroadcastPubKey();

} // namespace p2pmsg

#endif // BITCOIN_P2PMSG_CRYPTO_H
