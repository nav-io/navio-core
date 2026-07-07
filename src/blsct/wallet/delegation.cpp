// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/delegation.h>

#include <crypto/chacha20poly1305.h>
#include <crypto/sha256.h>
#include <streams.h>
#include <util/strencodings.h>

namespace blsct {
namespace delegation {

namespace {

//! "NVDG" + format version. Identifies a DataPredicate as a stake delegation.
const std::vector<unsigned char> MAGIC{'N', 'V', 'D', 'G', 0x01};

//! Domain separators for the AEAD key derivations.
const std::string KDF_TAG_DELEGATE = "navio/stake-delegation/delegate/v1";
const std::string KDF_TAG_OWNER = "navio/stake-delegation/owner/v1";

//! Fixed size of the encrypted owner section:
//! delegate key (48) + compact-size reward-address length. The address part
//! is variable, so the section carries an explicit 2-byte length prefix.
constexpr size_t OWNER_LEN_SIZE = 2;

std::array<std::byte, AEADChaCha20Poly1305::KEYLEN> DeriveKey(const std::string& tag, const std::vector<uint8_t>& secret, const std::vector<uint8_t>& context)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(tag.data()), tag.size());
    hasher.Write(secret.data(), secret.size());
    hasher.Write(context.data(), context.size());
    std::array<std::byte, AEADChaCha20Poly1305::KEYLEN> key;
    hasher.Finalize(reinterpret_cast<unsigned char*>(key.data()));
    return key;
}

std::vector<unsigned char> AeadEncrypt(const std::array<std::byte, AEADChaCha20Poly1305::KEYLEN>& key, const std::vector<unsigned char>& plain, const std::vector<unsigned char>& aad)
{
    std::vector<unsigned char> cipher(plain.size() + AEADChaCha20Poly1305::EXPANSION);
    AEADChaCha20Poly1305 aead{MakeByteSpan(key)};
    // Each key is unique (fresh ephemeral / per-output nonce), so a fixed
    // AEAD nonce is safe.
    aead.Encrypt(MakeByteSpan(plain), MakeByteSpan(aad), {0, 0}, MakeWritableByteSpan(cipher));
    return cipher;
}

std::optional<std::vector<unsigned char>> AeadDecrypt(const std::array<std::byte, AEADChaCha20Poly1305::KEYLEN>& key, const std::vector<unsigned char>& cipher, const std::vector<unsigned char>& aad)
{
    if (cipher.size() < AEADChaCha20Poly1305::EXPANSION) return std::nullopt;
    std::vector<unsigned char> plain(cipher.size() - AEADChaCha20Poly1305::EXPANSION);
    AEADChaCha20Poly1305 aead{MakeByteSpan(key)};
    if (!aead.Decrypt(MakeByteSpan(cipher), MakeByteSpan(aad), {0, 0}, MakeWritableByteSpan(plain))) {
        return std::nullopt;
    }
    return plain;
}

struct Sections {
    std::vector<unsigned char> aad;        // magic || version || E
    std::vector<uint8_t> ephemeralVch;     // E
    std::vector<unsigned char> ownerCt;    // owner section ciphertext
    std::vector<unsigned char> delegateCt; // delegate section ciphertext
};

std::optional<Sections> SplitSections(const std::vector<unsigned char>& data)
{
    if (!IsDelegationData(data)) return std::nullopt;

    Sections s;
    const size_t aadSize = MAGIC.size() + DELEGATION_POINT_SIZE;
    s.aad.assign(data.begin(), data.begin() + aadSize);
    s.ephemeralVch.assign(data.begin() + MAGIC.size(), data.begin() + aadSize);

    const size_t ownerLenPos = aadSize;
    const size_t ownerLen = data[ownerLenPos] | (data[ownerLenPos + 1] << 8);
    const size_t ownerPos = ownerLenPos + OWNER_LEN_SIZE;
    if (ownerPos + ownerLen + AEADChaCha20Poly1305::EXPANSION > data.size()) return std::nullopt;

    s.ownerCt.assign(data.begin() + ownerPos, data.begin() + ownerPos + ownerLen);
    s.delegateCt.assign(data.begin() + ownerPos + ownerLen, data.end());
    return s;
}

} // namespace

std::string DelegationRequest::GetId() const
{
    return HexStr(delegateKey.GetVch()) + ":" + rewardAddress;
}

bool IsDelegationData(const std::vector<unsigned char>& data)
{
    return data.size() > MAGIC.size() + DELEGATION_POINT_SIZE + OWNER_LEN_SIZE + 2 * AEADChaCha20Poly1305::EXPANSION &&
           std::equal(MAGIC.begin(), MAGIC.end(), data.begin());
}

std::vector<unsigned char> Encrypt(const DelegationInfo& info, const DelegationRequest& request, const MclG1Point& nonce)
{
    const MclScalar ephemeralPriv = MclScalar::Rand(/*exclude_zero=*/true);
    const MclG1Point ephemeralPub = MclG1Point::GetBasePoint() * ephemeralPriv;
    const auto ephemeralVch = ephemeralPub.GetVch();

    std::vector<unsigned char> aad(MAGIC);
    aad.insert(aad.end(), ephemeralVch.begin(), ephemeralVch.end());

    // Owner section: (delegateKey, rewardAddress) under the output-nonce key,
    // so the owner wallet can re-derive its delegations from the chain alone.
    DataStream ownerSs;
    ownerSs << request.delegateKey;
    ownerSs << request.rewardAddress;
    const std::vector<unsigned char> ownerPlain{UCharCast(ownerSs.data()), UCharCast(ownerSs.data()) + ownerSs.size()};
    const auto ownerKey = DeriveKey(KDF_TAG_OWNER, nonce.GetVch(), ephemeralVch);
    const auto ownerCt = AeadEncrypt(ownerKey, ownerPlain, aad);

    // Delegate section: the commitment opening plus the reward address, under
    // the ECDH key so only the delegate can stake with it.
    DataStream delegateSs;
    delegateSs << info.value;
    delegateSs << info.gamma;
    delegateSs << info.rewardAddress;
    const std::vector<unsigned char> delegatePlain{UCharCast(delegateSs.data()), UCharCast(delegateSs.data()) + delegateSs.size()};
    const auto delegateKey = DeriveKey(KDF_TAG_DELEGATE, (request.delegateKey * ephemeralPriv).GetVch(), ephemeralVch);
    const auto delegateCt = AeadEncrypt(delegateKey, delegatePlain, aad);

    std::vector<unsigned char> out(aad);
    out.push_back(static_cast<unsigned char>(ownerCt.size() & 0xFF));
    out.push_back(static_cast<unsigned char>((ownerCt.size() >> 8) & 0xFF));
    out.insert(out.end(), ownerCt.begin(), ownerCt.end());
    out.insert(out.end(), delegateCt.begin(), delegateCt.end());
    return out;
}

std::optional<DelegationInfo> TryDecrypt(const std::vector<unsigned char>& data, const MclScalar& delegatePrivKey)
{
    const auto sections = SplitSections(data);
    if (!sections.has_value()) return std::nullopt;

    MclG1Point ephemeralPub;
    if (!ephemeralPub.SetVch(sections->ephemeralVch)) return std::nullopt;
    if (ephemeralPub.IsZero()) return std::nullopt;

    const auto key = DeriveKey(KDF_TAG_DELEGATE, (ephemeralPub * delegatePrivKey).GetVch(), sections->ephemeralVch);
    const auto plain = AeadDecrypt(key, sections->delegateCt, sections->aad);
    if (!plain.has_value()) return std::nullopt;

    try {
        DataStream ss{*plain};
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

std::optional<DelegationRequest> RecoverOwnerInfo(const std::vector<unsigned char>& data, const MclG1Point& nonce)
{
    const auto sections = SplitSections(data);
    if (!sections.has_value()) return std::nullopt;

    const auto key = DeriveKey(KDF_TAG_OWNER, nonce.GetVch(), sections->ephemeralVch);
    const auto plain = AeadDecrypt(key, sections->ownerCt, sections->aad);
    if (!plain.has_value()) return std::nullopt;

    try {
        DataStream ss{*plain};
        DelegationRequest request;
        ss >> request.delegateKey;
        ss >> request.rewardAddress;
        if (!ss.empty()) return std::nullopt;
        return request;
    } catch (const std::ios_base::failure&) {
        return std::nullopt;
    }
}

} // namespace delegation
} // namespace blsct
