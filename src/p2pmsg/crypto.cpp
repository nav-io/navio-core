// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <p2pmsg/crypto.h>

#include <blsct/arith/mcl/mcl_g1point.h>
#include <blsct/arith/mcl/mcl_scalar.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/hkdf_sha256_32.h>
#include <hash.h>

#include <cstring>

namespace p2pmsg {

namespace {
//! HKDF salt/info domain separators — bind derived keys to this protocol.
const std::string HKDF_SALT = "navio-p2pmsg-ecies-v1";
const std::string HKDF_INFO = "aead-key";

//! Derive the 32-byte AEAD key from a serialized shared G1 point.
void DeriveKey(std::span<const uint8_t> shared_secret, std::byte out_key[32])
{
    CHKDF_HMAC_SHA256_L32 hkdf(shared_secret.data(), shared_secret.size(), HKDF_SALT);
    unsigned char k[32];
    hkdf.Expand32(HKDF_INFO, k);
    std::memcpy(out_key, k, 32);
}

//! All ECIES packets use a fixed zero nonce. This is safe because the AEAD key
//! is unique per message: it is derived from a fresh ephemeral key every time.
constexpr AEADChaCha20Poly1305::Nonce96 ZERO_NONCE{0, 0};

std::span<const std::byte> AsBytes(std::span<const uint8_t> s)
{
    return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}
} // namespace

uint256 EciesPacket::MsgHash() const
{
    HashWriter hw;
    hw << eph << ciphertext << tag;
    return hw.GetSHA256();
}

EciesPacket Encrypt(const blsct::PublicKey& recipient,
                    std::span<const uint8_t> plaintext,
                    std::span<const uint8_t> aad)
{
    // Fresh ephemeral keypair for this message.
    blsct::PrivateKey eph_sk(MclScalar::Rand(/*exclude_zero=*/true));

    EciesPacket pkt;
    pkt.eph = eph_sk.GetPublicKey();

    // Shared secret = eph_sk * recipient_pub (G1 point), serialized to 48 bytes.
    MclG1Point shared = recipient.GetG1Point() * eph_sk.GetScalar();
    std::vector<uint8_t> secret = shared.GetVch();

    std::byte key[32];
    DeriveKey(secret, key);

    AEADChaCha20Poly1305 aead(std::span<const std::byte>{key, 32});
    pkt.ciphertext.resize(plaintext.size() + ECIES_TAG_SIZE);
    aead.Encrypt(AsBytes(plaintext), AsBytes(aad), ZERO_NONCE,
                 std::span<std::byte>{reinterpret_cast<std::byte*>(pkt.ciphertext.data()),
                                      pkt.ciphertext.size()});

    // Split the trailing tag out of the ciphertext buffer for the wire struct.
    std::memcpy(pkt.tag.data(), pkt.ciphertext.data() + plaintext.size(), ECIES_TAG_SIZE);
    pkt.ciphertext.resize(plaintext.size());
    return pkt;
}

const blsct::PrivateKey& BroadcastPrivKey()
{
    // Fixed, public constant — NOT a secret. A small non-zero scalar so the
    // whole network shares one decryption key for public announcements.
    static const blsct::PrivateKey key{MclScalar(uint64_t{0x1})};
    return key;
}

const blsct::PublicKey& BroadcastPubKey()
{
    static const blsct::PublicKey pub{BroadcastPrivKey().GetPublicKey()};
    return pub;
}

std::optional<std::vector<uint8_t>> Decrypt(const blsct::PrivateKey& sk,
                                            const EciesPacket& pkt,
                                            std::span<const uint8_t> aad)
{
    // Shared secret = sk * eph_pub — the same point the sender computed.
    MclG1Point shared = pkt.eph.GetG1Point() * sk.GetScalar();
    std::vector<uint8_t> secret = shared.GetVch();

    std::byte key[32];
    DeriveKey(secret, key);

    // Reassemble ciphertext||tag for the AEAD.
    std::vector<uint8_t> ct_and_tag;
    ct_and_tag.reserve(pkt.ciphertext.size() + ECIES_TAG_SIZE);
    ct_and_tag.insert(ct_and_tag.end(), pkt.ciphertext.begin(), pkt.ciphertext.end());
    ct_and_tag.insert(ct_and_tag.end(), pkt.tag.begin(), pkt.tag.end());

    std::vector<uint8_t> plain(pkt.ciphertext.size());
    AEADChaCha20Poly1305 aead(std::span<const std::byte>{key, 32});
    bool ok = aead.Decrypt(AsBytes(ct_and_tag), AsBytes(aad), ZERO_NONCE,
                           std::span<std::byte>{reinterpret_cast<std::byte*>(plain.data()),
                                                plain.size()});
    if (!ok) return std::nullopt;
    return plain;
}

} // namespace p2pmsg
