// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_P2PMSG_CRYPTO_H
#define BITCOIN_P2PMSG_CRYPTO_H

#include <blsct/private_key.h>
#include <blsct/public_key.h>
#include <p2pmsg/worker_pool.h>
#include <serialize.h>
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

//! Largest ciphertext this wire format accepts. A packet only ever arrives
//! inside a transport body, which is capped at MAX_JOB_BYTES, so no valid
//! ciphertext can be longer than that. (The padding ladder does not bound it:
//! a payload above the top bucket is sent unpadded.) This bounds the
//! allocation at the length prefix, before the body cap is known to hold.
static constexpr size_t MAX_ECIES_CIPHERTEXT_BYTES = MAX_JOB_BYTES;

struct EciesPacket {
    blsct::PublicKey eph;                    //!< sender's per-message ephemeral pubkey
    std::vector<uint8_t> ciphertext;         //!< AEAD ciphertext (== plaintext length)
    std::array<uint8_t, ECIES_TAG_SIZE> tag; //!< Poly1305 tag

    SERIALIZE_METHODS(EciesPacket, obj)
    {
        READWRITE(obj.eph, LIMITED_BYTES(obj.ciphertext, MAX_ECIES_CIPHERTEXT_BYTES), obj.tag);
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
