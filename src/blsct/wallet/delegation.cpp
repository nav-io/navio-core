// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/delegation.h>

#include <crypto/chacha20poly1305.h>
#include <crypto/sha256.h>
#include <streams.h>

namespace blsct {
namespace delegation {

namespace {

//! "NVDG" + format version. Identifies a DataPredicate as a stake delegation.
const std::vector<unsigned char> MAGIC{'N', 'V', 'D', 'G', 0x01};

//! Domain separator for the AEAD key derivation.
const std::string KDF_TAG = "navio/stake-delegation/v1";

//! Derive the 32-byte AEAD key from the ECDH shared point and both public
//! transcript halves, so the key commits to the full key-exchange context.
std::array<std::byte, AEADChaCha20Poly1305::KEYLEN> DeriveKey(const MclG1Point& shared, const std::vector<uint8_t>& ephemeralVch)
{
    const auto sharedVch = shared.GetVch();
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(KDF_TAG.data()), KDF_TAG.size());
    hasher.Write(sharedVch.data(), sharedVch.size());
    hasher.Write(ephemeralVch.data(), ephemeralVch.size());
    std::array<std::byte, AEADChaCha20Poly1305::KEYLEN> key;
    hasher.Finalize(reinterpret_cast<unsigned char*>(key.data()));
    return key;
}

std::vector<unsigned char> SerializePlaintext(const DelegationInfo& info)
{
    DataStream ss;
    ss << info.value;
    ss << info.gamma;
    ss << info.rewardAddress;
    return {UCharCast(ss.data()), UCharCast(ss.data()) + ss.size()};
}

} // namespace

bool IsDelegationData(const std::vector<unsigned char>& data)
{
    return data.size() > MAGIC.size() + EPHEMERAL_KEY_SIZE + AEADChaCha20Poly1305::EXPANSION &&
           std::equal(MAGIC.begin(), MAGIC.end(), data.begin());
}

std::vector<unsigned char> Encrypt(const DelegationInfo& info, const MclG1Point& delegateKey)
{
    const MclScalar ephemeralPriv = MclScalar::Rand(/*exclude_zero=*/true);
    const MclG1Point ephemeralPub = MclG1Point::GetBasePoint() * ephemeralPriv;
    const auto ephemeralVch = ephemeralPub.GetVch();

    const auto key = DeriveKey(delegateKey * ephemeralPriv, ephemeralVch);

    const auto plain = SerializePlaintext(info);
    std::vector<unsigned char> cipher(plain.size() + AEADChaCha20Poly1305::EXPANSION);

    std::vector<unsigned char> aad(MAGIC);
    aad.insert(aad.end(), ephemeralVch.begin(), ephemeralVch.end());

    AEADChaCha20Poly1305 aead{MakeByteSpan(key)};
    // The key is unique per blob (fresh ephemeral), so a fixed nonce is safe.
    aead.Encrypt(MakeByteSpan(plain), MakeByteSpan(aad), {0, 0}, MakeWritableByteSpan(cipher));

    std::vector<unsigned char> out(aad);
    out.insert(out.end(), cipher.begin(), cipher.end());
    return out;
}

std::optional<DelegationInfo> TryDecrypt(const std::vector<unsigned char>& data, const MclScalar& delegatePrivKey)
{
    if (!IsDelegationData(data)) return std::nullopt;

    const std::vector<uint8_t> ephemeralVch(data.begin() + MAGIC.size(), data.begin() + MAGIC.size() + EPHEMERAL_KEY_SIZE);
    MclG1Point ephemeralPub;
    if (!ephemeralPub.SetVch(ephemeralVch)) return std::nullopt;
    if (ephemeralPub.IsZero()) return std::nullopt;

    const auto key = DeriveKey(ephemeralPub * delegatePrivKey, ephemeralVch);

    const std::vector<unsigned char> aad(data.begin(), data.begin() + MAGIC.size() + EPHEMERAL_KEY_SIZE);
    const std::vector<unsigned char> cipher(data.begin() + aad.size(), data.end());
    std::vector<unsigned char> plain(cipher.size() - AEADChaCha20Poly1305::EXPANSION);

    AEADChaCha20Poly1305 aead{MakeByteSpan(key)};
    if (!aead.Decrypt(MakeByteSpan(cipher), MakeByteSpan(aad), {0, 0}, MakeWritableByteSpan(plain))) {
        return std::nullopt;
    }

    try {
        DataStream ss{plain};
        DelegationInfo info;
        ss >> info.value;
        ss >> info.gamma;
        ss >> info.rewardAddress;
        if (!ss.empty()) return std::nullopt;
        return info;
    } catch (const std::ios_base::failure&) {
        return std::nullopt;
    }
}

} // namespace delegation
} // namespace blsct
