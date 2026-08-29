// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <p2pmsg/crypto.h>

#include <blsct/arith/blst/blst_g1point.h>
#include <blsct/arith/blst/blst_scalar.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/hkdf_sha256_32.h>
#include <hash.h>

#include <algorithm>

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

// Length-hiding padding. The plaintext is framed as
//   u32 LE real_length || real_plaintext || zero padding
// and padded up to one of a small ladder of fixed bucket sizes before
// encryption, so a passive observer sees only a handful of distinct ciphertext
// lengths instead of the exact application payload size. Without this a PING, an
// RFQ request, and a multi-kilobyte BLSCT half-tx are trivially told apart on
// the wire by size alone.
constexpr size_t PAD_PREFIX = 4;
size_t PaddedSize(size_t framed)
{
    // Buckets stay well below the transport's MAX_JOB_BYTES (4096) once the
    // ~166 bytes of envelope overhead (eph key, tag, PoW header, framing) are
    // added. The largest bucket (3584) leaves that headroom. A payload larger
    // than the top bucket is NOT padded up -- rounding a near-limit message to
    // the next step would push the whole envelope over MAX_JOB_BYTES and get it
    // dropped. Such large messages (e.g. a swap half-tx) already vary little in
    // size, so shipping them unpadded costs almost no fingerprinting.
    static constexpr size_t buckets[] = {64, 256, 1024, 3072, 3584};
    for (size_t b : buckets) {
        if (framed <= b) return b;
    }
    return framed;
}

std::vector<uint8_t> Pad(std::span<const uint8_t> plaintext)
{
    const size_t framed = PAD_PREFIX + plaintext.size();
    std::vector<uint8_t> out(PaddedSize(framed), 0);
    const uint32_t len = static_cast<uint32_t>(plaintext.size());
    out[0] = static_cast<uint8_t>(len & 0xff);
    out[1] = static_cast<uint8_t>((len >> 8) & 0xff);
    out[2] = static_cast<uint8_t>((len >> 16) & 0xff);
    out[3] = static_cast<uint8_t>((len >> 24) & 0xff);
    std::copy(plaintext.begin(), plaintext.end(), out.begin() + PAD_PREFIX);
    return out;
}

std::optional<std::vector<uint8_t>> Unpad(const std::vector<uint8_t>& padded)
{
    if (padded.size() < PAD_PREFIX) return std::nullopt;
    const uint32_t len = static_cast<uint32_t>(padded[0]) |
                         (static_cast<uint32_t>(padded[1]) << 8) |
                         (static_cast<uint32_t>(padded[2]) << 16) |
                         (static_cast<uint32_t>(padded[3]) << 24);
    if (static_cast<size_t>(len) > padded.size() - PAD_PREFIX) return std::nullopt;
    return std::vector<uint8_t>(padded.begin() + PAD_PREFIX, padded.begin() + PAD_PREFIX + len);
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
    blsct::PrivateKey eph_sk(BlstScalar::Rand(/*exclude_zero=*/true));

    EciesPacket pkt;
    pkt.eph = eph_sk.GetPublicKey();

    // Shared secret = eph_sk * recipient_pub (G1 point), serialized to 48 bytes.
    BlstG1Point shared = recipient.GetG1Point() * eph_sk.GetScalar();
    std::vector<uint8_t> secret = shared.GetVch();

    std::byte key[32];
    DeriveKey(std::span<const uint8_t>{secret.data(), secret.size()}, key);

    // Pad to a bucket size so the ciphertext length does not reveal the exact
    // application payload size (see Pad()).
    const std::vector<uint8_t> padded = Pad(plaintext);

    AEADChaCha20Poly1305 aead(std::span<const std::byte>{key, 32});
    pkt.ciphertext.resize(padded.size() + ECIES_TAG_SIZE);
    aead.Encrypt(AsBytes(std::span<const uint8_t>{padded.data(), padded.size()}), AsBytes(aad), ZERO_NONCE,
                 std::span<std::byte>{reinterpret_cast<std::byte*>(pkt.ciphertext.data()),
                                      pkt.ciphertext.size()});

    // Split the trailing tag out of the ciphertext buffer for the wire struct.
    std::memcpy(pkt.tag.data(), pkt.ciphertext.data() + padded.size(), ECIES_TAG_SIZE);
    pkt.ciphertext.resize(padded.size());
    return pkt;
}

const blsct::PrivateKey& BroadcastPrivKey()
{
    // Fixed, public constant — NOT a secret. A small non-zero scalar so the
    // whole network shares one decryption key for public announcements.
    static const blsct::PrivateKey key{BlstScalar(uint64_t{0x1})};
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
    // Reject a point-at-infinity (or otherwise invalid) ephemeral key. MCL
    // clears malformed points to the identity on unserialization, and
    // infinity * sk == infinity for every sk — so an attacker could otherwise
    // force the ECDH shared secret (and thus the AEAD key) to a public
    // constant and craft packets that decrypt under any recipient key.
    const BlstG1Point eph_point = pkt.eph.GetG1Point();
    if (eph_point.IsZero() || !eph_point.IsValid()) return std::nullopt;

    // Shared secret = sk * eph_pub — the same point the sender computed.
    BlstG1Point shared = eph_point * sk.GetScalar();
    std::vector<uint8_t> secret = shared.GetVch();

    std::byte key[32];
    DeriveKey(std::span<const uint8_t>{secret.data(), secret.size()}, key);

    // Reassemble ciphertext||tag for the AEAD.
    std::vector<uint8_t> ct_and_tag;
    ct_and_tag.reserve(pkt.ciphertext.size() + ECIES_TAG_SIZE);
    ct_and_tag.insert(ct_and_tag.end(), pkt.ciphertext.begin(), pkt.ciphertext.end());
    ct_and_tag.insert(ct_and_tag.end(), pkt.tag.begin(), pkt.tag.end());

    std::vector<uint8_t> plain(pkt.ciphertext.size());
    AEADChaCha20Poly1305 aead(std::span<const std::byte>{key, 32});
    bool ok = aead.Decrypt(
        AsBytes(std::span<const uint8_t>{ct_and_tag.data(), ct_and_tag.size()}),
        AsBytes(aad),
        ZERO_NONCE,
        std::span<std::byte>{reinterpret_cast<std::byte*>(plain.data()), plain.size()});
    if (!ok) return std::nullopt;
    // Strip the length-hiding padding applied in Encrypt.
    return Unpad(plain);
}

} // namespace p2pmsg
