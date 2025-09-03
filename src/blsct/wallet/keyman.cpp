// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/eip_2333/bls12_381_keygen.h>
#include <blsct/wallet/keyman.h>
#include <script/script.h>

namespace blsct {
bool KeyMan::IsHDEnabled() const
{
    return !m_hd_chain.seed_id.IsNull();
}

bool KeyMan::CanGenerateKeys() const
{
    // A wallet can generate keys if it has an HD seed (IsHDEnabled)
    return IsHDEnabled();
}

bool KeyMan::AddKeyOutKeyInner(const PrivateKey& key, const uint256& outId)
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        return KeyRing::AddKeyOutKey(key, outId);
    }

    if (m_storage.IsLocked()) {
        return false;
    }

    std::vector<unsigned char> vchCryptedSecret;
    auto keyVch = key.GetScalar().GetVch();
    wallet::CKeyingMaterial vchSecret(keyVch.begin(), keyVch.end());
    if (!wallet::EncryptSecret(m_storage.GetEncryptionKey(), vchSecret, outId, vchCryptedSecret)) {
        return false;
    }

    if (!AddCryptedOutKey(outId, key.GetPublicKey(), vchCryptedSecret)) {
        return false;
    }
    return true;
}

bool KeyMan::AddKeyPubKeyInner(const PrivateKey& key, const PublicKey& pubkey)
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        return KeyRing::AddKeyPubKey(key, pubkey);
    }

    if (m_storage.IsLocked()) {
        return false;
    }

    std::vector<unsigned char> vchCryptedSecret;
    auto keyVch = key.GetScalar().GetVch();
    wallet::CKeyingMaterial vchSecret(keyVch.begin(), keyVch.end());
    if (!wallet::EncryptSecret(m_storage.GetEncryptionKey(), vchSecret, pubkey.GetHash(), vchCryptedSecret)) {
        return false;
    }

    if (!AddCryptedKey(pubkey, vchCryptedSecret)) {
        return false;
    }
    return true;
}

bool KeyMan::AddKeyPubKey(const PrivateKey& secret, const PublicKey& pubkey)
{
    LOCK(cs_KeyStore);
    wallet::WalletBatch batch(m_storage.GetDatabase());
    return KeyMan::AddKeyPubKeyWithDB(batch, secret, pubkey);
}

bool KeyMan::AddKeyOutKey(const PrivateKey& secret, const uint256& outId)
{
    LOCK(cs_KeyStore);
    wallet::WalletBatch batch(m_storage.GetDatabase());
    return KeyMan::AddKeyOutKeyWithDB(batch, secret, outId);
}

bool KeyMan::AddViewKey(const PrivateKey& secret, const PublicKey& pubkey)
{
    LOCK(cs_KeyStore);
    wallet::WalletBatch batch(m_storage.GetDatabase());
    AssertLockHeld(cs_KeyStore);

    if (!fViewKeyDefined) {
        KeyRing::AddViewKey(secret, pubkey);

        return batch.WriteViewKey(pubkey, secret,
                                  mapKeyMetadata[pubkey.GetID()]);
    }
    return true;
}

bool KeyMan::AddSpendKey(const PublicKey& pubkey)
{
    LOCK(cs_KeyStore);
    wallet::WalletBatch batch(m_storage.GetDatabase());
    AssertLockHeld(cs_KeyStore);
    if (!fSpendKeyDefined) {
        KeyRing::AddSpendKey(pubkey);
        if (!batch.WriteSpendKey(pubkey))
            return false;
    }

    return true;
}

bool KeyMan::AddKeyPubKeyWithDB(wallet::WalletBatch& batch, const PrivateKey& secret, const PublicKey& pubkey)
{
    AssertLockHeld(cs_KeyStore);

    bool needsDB = !encrypted_batch;
    if (needsDB) {
        encrypted_batch = &batch;
    }
    if (!AddKeyPubKeyInner(secret, pubkey)) {
        if (needsDB) encrypted_batch = nullptr;
        return false;
    }
    if (needsDB) encrypted_batch = nullptr;

    if (!m_storage.HasEncryptionKeys()) {
        return batch.WriteKey(pubkey,
                              secret,
                              mapKeyMetadata[pubkey.GetID()]);
    }
    return true;
}

bool KeyMan::AddKeyOutKeyWithDB(wallet::WalletBatch& batch, const PrivateKey& secret, const uint256& outId)
{
    AssertLockHeld(cs_KeyStore);

    bool needsDB = !encrypted_batch;
    if (needsDB) {
        encrypted_batch = &batch;
    }
    if (!AddKeyOutKeyInner(secret, outId)) {
        if (needsDB) encrypted_batch = nullptr;
        return false;
    }
    if (needsDB) encrypted_batch = nullptr;

    if (!m_storage.HasEncryptionKeys()) {
        return batch.WriteOutKey(outId,
                                 secret);
    }
    return true;
}

bool KeyMan::AddSubAddressPoolWithDB(wallet::WalletBatch& batch, const SubAddressIdentifier& id, const SubAddress& subAddress, const bool& fLock)
{
    LOCK(cs_KeyStore);

    setSubAddressPool[id.account].insert(id.address);

    return batch.WriteSubAddressPool(id, SubAddressPool(subAddress.GetKeys().GetID()));
}

bool KeyMan::AddSubAddressPoolInner(const SubAddressIdentifier& id, const bool& fLock)
{
    LOCK(cs_KeyStore);

    setSubAddressPool[id.account].insert(id.address);

    return true;
}

bool KeyMan::LoadCryptedKey(const PublicKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret, bool checksum_valid)
{
    // Set fDecryptionThoroughlyChecked to false when the checksum is invalid
    if (!checksum_valid) {
        fDecryptionThoroughlyChecked = false;
    }

    return AddCryptedKeyInner(vchPubKey, vchCryptedSecret);
}

bool KeyMan::LoadCryptedOutKey(const uint256& outId, const PublicKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret, bool checksum_valid)
{
    // Set fDecryptionThoroughlyChecked to false when the checksum is invalid
    if (!checksum_valid) {
        fDecryptionThoroughlyChecked = false;
    }

    return AddCryptedOutKeyInner(outId, vchPubKey, vchCryptedSecret);
}

bool KeyMan::AddCryptedKeyInner(const PublicKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret)
{
    LOCK(cs_KeyStore);
    assert(mapKeys.empty());

    mapCryptedKeys[vchPubKey.GetID()] = make_pair(vchPubKey, vchCryptedSecret);
    return true;
}

bool KeyMan::AddCryptedOutKeyInner(const uint256& outId, const PublicKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret)
{
    LOCK(cs_KeyStore);
    assert(mapOutKeys.empty());

    mapCryptedOutKeys[outId] = make_pair(vchPubKey, vchCryptedSecret);
    return true;
}

bool KeyMan::AddCryptedKey(const PublicKey& vchPubKey,
                           const std::vector<unsigned char>& vchCryptedSecret)
{
    if (!AddCryptedKeyInner(vchPubKey, vchCryptedSecret))
        return false;
    {
        LOCK(cs_KeyStore);
        if (encrypted_batch)
            return encrypted_batch->WriteCryptedKey(vchPubKey,
                                                    vchCryptedSecret,
                                                    mapKeyMetadata[vchPubKey.GetID()]);
        else
            return wallet::WalletBatch(m_storage.GetDatabase()).WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
    }
}

bool KeyMan::AddCryptedOutKey(const uint256& outId,
                              const PublicKey& vchPubKey,
                              const std::vector<unsigned char>& vchCryptedSecret)
{
    if (!AddCryptedOutKeyInner(outId, vchPubKey, vchCryptedSecret))
        return false;
    {
        LOCK(cs_KeyStore);
        if (encrypted_batch)
            return encrypted_batch->WriteCryptedOutKey(outId,
                                                       vchPubKey,
                                                       vchCryptedSecret);
        else
            return wallet::WalletBatch(m_storage.GetDatabase()).WriteCryptedOutKey(outId, vchPubKey, vchCryptedSecret);
    }
}

PrivateKey KeyMan::GenerateNewSeed()
{
    return GenRandomSeed();
}

void KeyMan::LoadHDChain(const blsct::HDChain& chain)
{
    LOCK(cs_KeyStore);
    m_hd_chain = chain;
}

void KeyMan::AddHDChain(const blsct::HDChain& chain)
{
    LOCK(cs_KeyStore);
    // Store the new chain
    if (!wallet::WalletBatch(m_storage.GetDatabase()).WriteBLSCTHDChain(chain)) {
        throw std::runtime_error(std::string(__func__) + ": writing chain failed");
    }
    // When there's an old chain, add it as an inactive chain as we are now rotating hd chains
    if (!m_hd_chain.seed_id.IsNull()) {
        AddInactiveHDChain(m_hd_chain);
    }

    m_hd_chain = chain;
}

void KeyMan::AddInactiveHDChain(const blsct::HDChain& chain)
{
    LOCK(cs_KeyStore);
    assert(!chain.seed_id.IsNull());
    m_inactive_hd_chains[chain.seed_id] = chain;
}


void KeyMan::SetHDSeed(const PrivateKey& key)
{
    LOCK(cs_KeyStore);
    // store the keyid (hash160) together with
    // the child index counter in the database
    // as a hdchain object
    blsct::HDChain newHdChain;

    auto seed = key.GetPublicKey();
    auto childKey = FromSeedToChildKey(key.GetScalar());
    auto transactionKey = FromChildToTransactionKey(childKey);
    auto blindingKey = PrivateKey(FromChildToBlindingKey(childKey));
    auto tokenKey = PrivateKey(FromChildToTokenKey(childKey));
    auto viewKey = PrivateKey(FromTransactionToViewKey(transactionKey));
    auto spendKey = PrivateKey(FromTransactionToSpendKey(transactionKey));

    newHdChain.nVersion = blsct::HDChain::VERSION_HD_BASE;
    newHdChain.seed_id = key.GetPublicKey().GetID();
    newHdChain.spend_id = spendKey.GetPublicKey().GetID();
    newHdChain.view_id = viewKey.GetPublicKey().GetID();
    newHdChain.token_id = tokenKey.GetPublicKey().GetID();
    newHdChain.blinding_id = blindingKey.GetPublicKey().GetID();

    int64_t nCreationTime = GetTime();

    wallet::CKeyMetadata spendMetadata(nCreationTime);
    wallet::CKeyMetadata viewMetadata(nCreationTime);
    wallet::CKeyMetadata blindingMetadata(nCreationTime);
    wallet::CKeyMetadata tokenMetadata(nCreationTime);

    spendMetadata.hdKeypath = "spend";
    spendMetadata.has_key_origin = false;
    spendMetadata.hd_seed_id = newHdChain.spend_id;

    viewMetadata.hdKeypath = "view";
    viewMetadata.has_key_origin = false;
    viewMetadata.hd_seed_id = newHdChain.view_id;

    blindingMetadata.hdKeypath = "blinding";
    blindingMetadata.has_key_origin = false;
    blindingMetadata.hd_seed_id = newHdChain.blinding_id;

    tokenMetadata.hdKeypath = "token";
    tokenMetadata.has_key_origin = false;
    tokenMetadata.hd_seed_id = newHdChain.token_id;

    // mem store the metadata
    mapKeyMetadata[newHdChain.spend_id] = spendMetadata;
    mapKeyMetadata[newHdChain.view_id] = viewMetadata;
    mapKeyMetadata[newHdChain.blinding_id] = blindingMetadata;
    mapKeyMetadata[newHdChain.token_id] = tokenMetadata;

    // write the keys to the database
    if (!AddKeyPubKey(key, seed))
        throw std::runtime_error(std::string(__func__) + ": AddKeyPubKey failed");

    if (!AddKeyPubKey(spendKey, spendKey.GetPublicKey()))
        throw std::runtime_error(std::string(__func__) + ": AddKeyPubKey failed");

    if (!AddSpendKey(spendKey.GetPublicKey()))
        throw std::runtime_error(std::string(__func__) + ": AddSpendKey failed");

    if (!AddViewKey(viewKey, viewKey.GetPublicKey()))
        throw std::runtime_error(std::string(__func__) + ": AddViewKey failed");

    if (!AddKeyPubKey(tokenKey, tokenKey.GetPublicKey()))
        throw std::runtime_error(std::string(__func__) + ": AddKeyPubKey failed");

    if (!AddKeyPubKey(blindingKey, blindingKey.GetPublicKey()))
        throw std::runtime_error(std::string(__func__) + ": AddKeyPubKey failed");

    AddHDChain(newHdChain);
    NotifyCanGetAddressesChanged();
    wallet::WalletBatch batch(m_storage.GetDatabase());
}

bool KeyMan::SetupGeneration(const std::vector<unsigned char>& seed, const SeedType& type, bool force)
{
    if ((CanGenerateKeys() && !force) || m_storage.IsLocked()) {
        return false;
    }

    if (seed.size() == 32) {
        if (type == IMPORT_MASTER_KEY) {
            MclScalar scalarSeed;
            scalarSeed.SetVch(seed);
            SetHDSeed(scalarSeed);
        }
    } else if (seed.size() == 80) {
        if (type == IMPORT_VIEW_KEY) {
            std::vector<unsigned char> viewVch(seed.begin(), seed.begin() + 32);
            std::vector<unsigned char> spendingVch(seed.begin() + 32, seed.end());

            MclScalar scalarView;
            scalarView.SetVch(viewVch);

            MclG1Point pointSpending;
            pointSpending.SetVch(spendingVch);

            if (!AddViewKey(scalarView, PrivateKey(scalarView).GetPublicKey()))
                throw std::runtime_error(std::string(__func__) + ": AddViewKey failed");

            if (!AddSpendKey(pointSpending))
                throw std::runtime_error(std::string(__func__) + ": AddSpendKey failed");
        }
    } else {
        SetHDSeed(GenerateNewSeed());
    }

    if (!NewSubAddressPool() || !NewSubAddressPool(-1) || !NewSubAddressPool(-2)) {
        return false;
    }
    return true;
}

bool KeyMan::CheckDecryptionKey(const wallet::CKeyingMaterial& master_key, bool accept_no_keys)
{
    {
        LOCK(cs_KeyStore);
        assert(mapKeys.empty());

        bool keyPass = mapCryptedKeys.empty(); // Always pass when there are no encrypted keys
        bool keyFail = false;
        CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
        wallet::WalletBatch batch(m_storage.GetDatabase());
        for (; mi != mapCryptedKeys.end(); ++mi) {
            const PublicKey& vchPubKey = (*mi).second.first;
            const std::vector<unsigned char>& vchCryptedSecret = (*mi).second.second;
            PrivateKey key;
            if (!wallet::DecryptKey(master_key, vchCryptedSecret, vchPubKey, key)) {
                keyFail = true;
                break;
            }
            keyPass = true;
            if (fDecryptionThoroughlyChecked)
                break;
            else {
                // Rewrite these encrypted keys with checksums
                batch.WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
            }
        }
        if (keyPass && keyFail) {
            LogPrintf("The wallet is probably corrupted: Some keys decrypt but not all.\n");
            throw std::runtime_error(std::string(__func__) + ": Error unlocking wallet: some keys decrypt but not all. Your wallet file may be corrupt.");
        }
        if (keyFail || (!keyPass && !accept_no_keys))
            return false;
        fDecryptionThoroughlyChecked = true;
    }
    return true;
}

void KeyMan::LoadKeyMetadata(const CKeyID& keyID, const wallet::CKeyMetadata& meta)
{
    LOCK(cs_KeyStore);
    UpdateTimeFirstKey(meta.nCreateTime);
    mapKeyMetadata[keyID] = meta;
}

bool KeyMan::LoadKey(const PrivateKey& key, const PublicKey& pubkey)
{
    return AddKeyPubKeyInner(key, pubkey);
}

bool KeyMan::LoadOutKey(const PrivateKey& key, const uint256& outId)
{
    return AddKeyOutKeyInner(key, outId);
}

bool KeyMan::LoadViewKey(const PrivateKey& key, const PublicKey& pubkey)
{
    return KeyRing::AddViewKey(key, pubkey);
}

bool KeyMan::LoadSpendKey(const PublicKey& pubkey)
{
    return KeyRing::AddSpendKey(pubkey);
}

/**
 * Update wallet first key creation time. This should be called whenever keys
 * are added to the wallet, with the oldest key creation time.
 */
void KeyMan::UpdateTimeFirstKey(int64_t nCreateTime)
{
    AssertLockHeld(cs_KeyStore);
    if (nCreateTime <= 1) {
        // Cannot determine birthday information, so set the wallet birthday to
        // the beginning of time.
        nTimeFirstKey = 1;
    } else if (!nTimeFirstKey || nCreateTime < nTimeFirstKey) {
        nTimeFirstKey = nCreateTime;
    }
}

SubAddress KeyMan::GetSubAddress(const SubAddressIdentifier& id) const
{
    return DeriveSubAddress(viewKey, spendPublicKey, id);
};

bool KeyMan::HaveKey(const CKeyID& id) const
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        return KeyRing::HaveKey(id);
    }
    return mapCryptedKeys.count(id) > 0;
}

bool KeyMan::GetKey(const CKeyID& id, PrivateKey& keyOut) const
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        return KeyRing::GetKey(id, keyOut);
    }

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(id);
    if (mi != mapCryptedKeys.end()) {
        const PublicKey& vchPubKey = (*mi).second.first;
        const std::vector<unsigned char>& vchCryptedSecret = (*mi).second.second;
        return wallet::DecryptKey(m_storage.GetEncryptionKey(), vchCryptedSecret, vchPubKey, keyOut);
    }
    return false;
}

bool KeyMan::GetOutKey(const uint256& id, PrivateKey& keyOut) const
{
    LOCK(cs_KeyStore);
    if (!m_storage.HasEncryptionKeys()) {
        return KeyRing::GetOutKey(id, keyOut);
    }

    CryptedOutKeyMap::const_iterator mi = mapCryptedOutKeys.find(id);
    if (mi != mapCryptedOutKeys.end()) {
        const uint256& outId = (*mi).first;
        const PublicKey& vchPubKey = (*mi).second.first;
        const std::vector<unsigned char>& vchCryptedSecret = (*mi).second.second;
        return wallet::DecryptKey(m_storage.GetEncryptionKey(), vchCryptedSecret, outId, vchPubKey, keyOut);
    }
    return false;
}

bool KeyMan::DeleteRecords()
{
    LOCK(cs_KeyStore);
    wallet::WalletBatch batch(m_storage.GetDatabase());
    return batch.EraseRecords(wallet::DBKeys::BLSCT_TYPES);
}

bool KeyMan::DeleteKeys()
{
    LOCK(cs_KeyStore);
    wallet::WalletBatch batch(m_storage.GetDatabase());
    return batch.EraseRecords(wallet::DBKeys::BLSCTKEY_TYPES);
}

bool KeyMan::Encrypt(const wallet::CKeyingMaterial& master_key, wallet::WalletBatch* batch)
{
    LOCK(cs_KeyStore);
    encrypted_batch = batch;
    if (!mapCryptedKeys.empty()) {
        encrypted_batch = nullptr;
        return false;
    }

    KeyMap keys_to_encrypt;
    keys_to_encrypt.swap(mapKeys); // Clear mapKeys so AddCryptedKeyInner will succeed.
    for (const KeyMap::value_type& mKey : keys_to_encrypt) {
        const PrivateKey& key = mKey.second;
        PublicKey pubKey = key.GetPublicKey();
        wallet::CKeyingMaterial vchSecret(key.begin(), key.end());
        std::vector<unsigned char> vchCryptedSecret;
        if (!wallet::EncryptSecret(master_key, vchSecret, pubKey.GetHash(), vchCryptedSecret)) {
            encrypted_batch = nullptr;
            return false;
        }
        if (!AddCryptedKey(pubKey, vchCryptedSecret)) {
            encrypted_batch = nullptr;
            return false;
        }
    }
    encrypted_batch = nullptr;
    return true;
}

CTxDestination KeyMan::GetDestination(const CTxOut& txout) const
{
    auto hashId = GetHashId(txout);
    blsct::SubAddress subAdd;
    CTxDestination ret;
    if (!GetSubAddress(hashId, subAdd)) {
        ret = CNoDestination();
    } else {
        ret = CTxDestination(subAdd.GetKeys());
    }
    return ret;
}

CKeyID KeyMan::GetHashId(const blsct::PublicKey& blindingKey, const blsct::PublicKey& spendingKey) const
{
    if (!fViewKeyDefined || !viewKey.IsValid())
        throw std::runtime_error(strprintf("%s: the wallet has no view key available", __func__));

    return CalculateHashId(blindingKey.GetG1Point(), spendingKey.GetG1Point(), viewKey.GetScalar());
};

blsct::PrivateKey KeyMan::GetMasterSeedKey() const
{
    if (!IsHDEnabled())
        throw std::runtime_error(strprintf("%s: the wallet has no HD enabled"));

    auto seedId = m_hd_chain.seed_id;

    PrivateKey ret;

    if (!GetKey(seedId, ret))
        throw std::runtime_error(strprintf("%s: could not access the master seed key", __func__));

    return ret;
}

blsct::PrivateKey KeyMan::GetMasterTokenKey() const
{
    if (!IsHDEnabled())
        throw std::runtime_error(strprintf("%s: the wallet has no HD enabled"));

    auto tokenKeyId = m_hd_chain.token_id;

    PrivateKey ret;

    if (!GetKey(tokenKeyId, ret))
        throw std::runtime_error(strprintf("%s: could not access the master token key", __func__));

    return ret;
}

blsct::PrivateKey KeyMan::GetPrivateViewKey() const
{
    if (!fViewKeyDefined)
        throw std::runtime_error(strprintf("%s: the wallet has no view key available"));

    return viewKey;
}

blsct::PublicKey KeyMan::GetPublicSpendingKey() const
{
    return spendPublicKey;
}

blsct::PrivateKey KeyMan::GetSpendingKey() const
{
    if (!fSpendKeyDefined)
        throw std::runtime_error(strprintf("%s: the wallet has no spend key available"));

    auto spendingKeyId = m_hd_chain.spend_id;

    PrivateKey ret;

    if (!GetKey(spendingKeyId, ret))
        throw std::runtime_error(strprintf("%s: could not access the spend key", __func__));

    return ret;
}

bool KeyMan::GetSpendingKeyForOutput(const CTxOut& out, blsct::PrivateKey& key) const
{
    auto hashId = GetHashId(out);

    return GetSpendingKeyForOutput(out, hashId, key);
}

bool KeyMan::GetSpendingKeyForOutput(const CTxOut& out, const CKeyID& hashId, blsct::PrivateKey& key) const
{
    SubAddressIdentifier id;

    if (!GetSubAddressId(hashId, id))
        return false;

    return GetSpendingKeyForOutput(out, id, key);
}

bool KeyMan::GetSpendingKeyForOutput(const CTxOut& out, const SubAddressIdentifier& id, blsct::PrivateKey& key) const
{
    if (!fViewKeyDefined || !viewKey.IsValid())
        throw std::runtime_error(strprintf("%s: the wallet has no view key available", __func__));

    auto sk = GetSpendingKey();

    key = CalculatePrivateSpendingKey(out.blsctData.blindingKey, viewKey.GetScalar(), sk.GetScalar(), id.account, id.address);

    return true;
}

bool KeyMan::GetSpendingKeyForOutputWithCache(const CTxOut& out, blsct::PrivateKey& key)
{
    auto hashId = GetHashId(out);

    return GetSpendingKeyForOutput(out, hashId, key);
}

bool KeyMan::GetSpendingKeyForOutputWithCache(const CTxOut& out, const CKeyID& hashId, blsct::PrivateKey& key)
{
    SubAddressIdentifier id;

    if (!GetSubAddressId(hashId, id))
        return false;

    return GetSpendingKeyForOutput(out, id, key);
}

bool KeyMan::GetSpendingKeyForOutputWithCache(const CTxOut& out, const SubAddressIdentifier& id, blsct::PrivateKey& key)
{
    if (!fViewKeyDefined || !viewKey.IsValid())
        throw std::runtime_error(strprintf("%s: the wallet has no view key available", __func__));

    auto sk = GetSpendingKey();

    auto outId = (HashWriter() << out.blsctData.blindingKey << viewKey.GetScalar() << sk.GetScalar() << id.account << id.address).GetHash();

    if (GetOutKey(outId, key))
        return true;

    key = CalculatePrivateSpendingKey(out.blsctData.blindingKey, viewKey.GetScalar(), sk.GetScalar(), id.account, id.address);

    AddKeyOutKey(key, outId);

    return true;
}

blsct::PrivateKey KeyMan::GetTokenKey(const uint256& tokenId) const
{
    auto masterTokenKey = GetMasterTokenKey();

    return BLS12_381_KeyGen::derive_child_SK_hash(masterTokenKey.GetScalar(), tokenId);
}

using Arith = Mcl;

bulletproofs_plus::AmountRecoveryResult<Arith> KeyMan::RecoverOutputs(const std::vector<CTxOut>& outs)
{
    if (!fViewKeyDefined || !viewKey.IsValid())
        return bulletproofs_plus::AmountRecoveryResult<Arith>::failure();

    bulletproofs_plus::RangeProofLogic<Arith> rp;
    std::vector<bulletproofs_plus::AmountRecoveryRequest<Arith>> reqs;
    reqs.reserve(outs.size());

    for (size_t i = 0; i < outs.size(); i++) {
        CTxOut out = outs[i];
        if (!out.HasBLSCTKeys() || !out.HasBLSCTRangeProof()) continue;
        if (out.blsctData.viewTag != CalculateViewTag(out.blsctData.blindingKey, viewKey.GetScalar()))
            continue;
        auto nonce = CalculateNonce(out.blsctData.blindingKey, viewKey.GetScalar());
        bulletproofs_plus::RangeProofWithSeed<Arith> proof = {out.blsctData.rangeProof, out.tokenId};
        reqs.push_back(bulletproofs_plus::AmountRecoveryRequest<Arith>::of(proof, nonce, i));
    }

    return rp.RecoverAmounts(reqs);
}

bulletproofs_plus::AmountRecoveryResult<Arith> KeyMan::RecoverOutputsWithNonce(const std::vector<CTxOut>& outs, const Point& nonce)
{
    if (!fViewKeyDefined || !viewKey.IsValid())
        return bulletproofs_plus::AmountRecoveryResult<Arith>::failure();

    bulletproofs_plus::RangeProofLogic<Arith> rp;
    std::vector<bulletproofs_plus::AmountRecoveryRequest<Arith>> reqs;
    reqs.reserve(outs.size());

    for (size_t i = 0; i < outs.size(); i++) {
        CTxOut out = outs[i];
        if (!out.HasBLSCTKeys() || !out.HasBLSCTRangeProof()) continue;
        // Use the provided nonce instead of calculating it
        bulletproofs_plus::RangeProofWithSeed<Arith> proof = {out.blsctData.rangeProof, out.tokenId};
        reqs.push_back(bulletproofs_plus::AmountRecoveryRequest<Arith>::of(proof, nonce, i));
    }

    return rp.RecoverAmounts(reqs);
}

bool KeyMan::IsMine(const CScript& script) const
{
    LOCK(cs_KeyStore);
    return setWatchOnly.count(script) > 0;
}

bool KeyMan::IsMine(const blsct::PublicKey& blindingKey, const blsct::PublicKey& spendingKey, const uint16_t& viewTag)
{
    if (!fViewKeyDefined || !viewKey.IsValid())
        return false;

    if (viewTag != CalculateViewTag(blindingKey.GetG1Point(), viewKey.GetScalar())) return false;

    auto hashId = GetHashId(blindingKey, spendingKey);

    {
        LOCK(cs_KeyStore);
        return HaveSubAddress(hashId);
    }
}

void KeyMan::LoadSubAddress(const CKeyID& hashId, const SubAddressIdentifier& index)
{
    LOCK(cs_KeyStore);
    mapSubAddresses[hashId] = index;
}

bool KeyMan::AddSubAddress(const CKeyID& hashId, const SubAddressIdentifier& index)
{
    LOCK(cs_KeyStore);
    wallet::WalletBatch batch(m_storage.GetDatabase());
    AssertLockHeld(cs_KeyStore);

    mapSubAddresses[hashId] = index;

    return batch.WriteSubAddress(hashId, index);
}

bool KeyMan::HaveSubAddress(const CKeyID& hashId) const
{
    return mapSubAddresses.count(hashId) > 0;
}

bool KeyMan::GetSubAddress(const CKeyID& hashId, SubAddress& address) const
{
    LOCK(cs_KeyStore);
    if (!HaveSubAddress(hashId)) return false;
    address = GetSubAddress(mapSubAddresses.at(hashId));
    return true;
}

bool KeyMan::GetSubAddressId(const CKeyID& hashId, SubAddressIdentifier& id) const
{
    LOCK(cs_KeyStore);
    if (!HaveSubAddress(hashId)) return false;
    id = mapSubAddresses.at(hashId);
    return true;
}

void KeyMan::LoadSubAddressStr(const SubAddress& subAddress, const CKeyID& hashId)
{
    LOCK(cs_KeyStore);
    mapSubAddressesStr[subAddress] = hashId;
}

bool KeyMan::AddSubAddressStr(const SubAddress& subAddress, const CKeyID& hashId)
{
    LOCK(cs_KeyStore);
    wallet::WalletBatch batch(m_storage.GetDatabase());
    AssertLockHeld(cs_KeyStore);

    mapSubAddressesStr[subAddress] = hashId;

    return batch.WriteSubAddressStr(subAddress, hashId);
}

bool KeyMan::HaveSubAddressStr(const SubAddress& subAddress) const
{
    LOCK(cs_KeyStore);
    return mapSubAddressesStr.count(subAddress) > 0;
}

SubAddress KeyMan::GenerateNewSubAddress(const int64_t& account, SubAddressIdentifier& id)
{
    if (m_hd_chain.nSubAddressCounter.count(account) == 0)
        m_hd_chain.nSubAddressCounter.insert(std::make_pair(account, 0));

    SubAddress subAddress{DoublePublicKey{}};

    {
        LOCK(cs_KeyStore);
        wallet::WalletBatch batch(m_storage.GetDatabase());
        do {
            id.account = account;
            id.address = m_hd_chain.nSubAddressCounter[account];

            subAddress = GetSubAddress(id);
            assert(id.address == m_hd_chain.nSubAddressCounter[account]);

            m_hd_chain.nSubAddressCounter[account] = m_hd_chain.nSubAddressCounter[account] + 1;

            // update the chain model in the database
            if (!batch.WriteBLSCTHDChain(m_hd_chain))
                throw std::runtime_error(std::string(__func__) + ": Writing HD chain model failed");

        } while (HaveSubAddress(subAddress.GetKeys().GetID()));
    }

    if (!AddSubAddress(subAddress.GetKeys().GetID(), id))
        throw std::runtime_error(std::string(__func__) + ": AddSubAddress failed");

    if (!AddSubAddressStr(subAddress, subAddress.GetKeys().GetID()))
        throw std::runtime_error(std::string(__func__) + ": AddSubAddressStr failed");

    return subAddress;
}

// BLSCT Sub Address Key Pool

bool KeyMan::NewSubAddressPool(const int64_t& account)
{
    LOCK(cs_KeyStore);
    wallet::WalletBatch batch(m_storage.GetDatabase());

    if (setSubAddressPool.count(account)) {
        for (uint64_t nIndex : setSubAddressPool[account])
            batch.EraseSubAddressPool({account, nIndex});
        setSubAddressPool[account].clear();
    } else {
        setSubAddressPool.insert(std::make_pair(account, std::set<uint64_t>()));
    }

    if (!TopUpAccount(account)) {
        return false;
    }

    WalletLogPrintf("blsct::KeyMan::NewSubAddressPool rewrote keypool\n");

    return true;
}

bool KeyMan::TopUp(const unsigned int& size)
{
    LOCK(cs_KeyStore);

    if (!CanGenerateKeys()) {
        return false;
    }

    for (auto& it : setSubAddressPool) {
        if (!TopUpAccount(it.first, size)) {
            return false;
        }
    }
    NotifyCanGetAddressesChanged();
    return true;
}

bool KeyMan::TopUpAccount(const int64_t& account, const unsigned int& size)
{
    LOCK(cs_KeyStore);

    if (m_storage.IsLocked()) return false;

    // Top up key pool
    unsigned int nTargetSize;
    if (size > 0) {
        nTargetSize = size;
    } else {
        nTargetSize = m_keypool_size;
    }
    int64_t target = std::max((int64_t)nTargetSize, int64_t{1});
    int64_t missing = std::max(target - (int64_t)setSubAddressPool[account].size(), int64_t{0});

    SubAddressIdentifier id;

    wallet::WalletBatch batch(m_storage.GetDatabase());
    for (int64_t i = missing; i--;) {
        auto sa = GenerateNewSubAddress(account, id);
        AddSubAddressPoolWithDB(batch, id, sa, false);
    }

    if (missing > 0)
        WalletLogPrintf("KeyMan::TopUpAccount(): added %d keys for account %d, size=%u \n", missing, account, setSubAddressPool[account].size());

    return true;
}

void KeyMan::ReserveSubAddressFromPool(const int64_t& account, int64_t& nIndex, SubAddressPool& keypool)
{
    nIndex = -1;
    keypool.hashId = CKeyID();
    {
        LOCK(cs_KeyStore);
        wallet::WalletBatch batch(m_storage.GetDatabase());

        if (!m_storage.IsLocked()) TopUpAccount(account);

        if (setSubAddressPool.count(account) == 0)
            setSubAddressPool.insert(std::make_pair(account, std::set<uint64_t>()));

        if (setSubAddressReservePool.count(account) == 0)
            setSubAddressReservePool.insert(std::make_pair(account, std::set<uint64_t>()));

        // Get the oldest key
        if (setSubAddressPool[account].empty())
            return;

        nIndex = *(setSubAddressPool[account].begin());
        setSubAddressPool[account].erase(setSubAddressPool[account].begin());
        setSubAddressReservePool[account].insert(nIndex);
        if (!batch.ReadSubAddressPool({account, (nIndex > -1 ? static_cast<uint64_t>(nIndex) : 0)}, keypool))
            throw std::runtime_error(std::string(__func__) + ": Read failed");
        if (!HaveSubAddress(keypool.hashId))
            throw std::runtime_error(std::string(__func__) + ": Unknown key in key pool");
        WalletLogPrintf("KeyMan::ReserveSubAddressFromPool(): reserve %d\n", nIndex);
    }
    NotifyCanGetAddressesChanged();
}

void KeyMan::KeepSubAddress(const SubAddressIdentifier& id)
{
    {
        LOCK(cs_KeyStore);
        wallet::WalletBatch batch(m_storage.GetDatabase());

        batch.EraseSubAddressPool(id);

        setSubAddressPool[id.account].erase(id.address);
        setSubAddressReservePool[id.account].erase(id.address);

        WalletLogPrintf("KeyMan::KeepSubAddress(): keep %d/%d\n", id.account, id.address);
    }
}

void KeyMan::ReturnSubAddress(const SubAddressIdentifier& id)
{
    // Return to key pool
    {
        LOCK(cs_KeyStore);
        if (setSubAddressPool.count(id.account) == 0)
            setSubAddressPool.insert(std::make_pair(id.account, std::set<uint64_t>()));
        setSubAddressPool[id.account].insert(id.address);
        setSubAddressReservePool[id.account].erase(id.address);
    }
    NotifyCanGetAddressesChanged();
    WalletLogPrintf("KeyMan::ReturnSubAddress(): return %d/%d\n", id.account / id.address);
}

bool KeyMan::GetSubAddressFromPool(const int64_t& account, CKeyID& result, SubAddressIdentifier& id)
{
    LOCK(cs_KeyStore);

    int64_t nIndex = 0;
    SubAddressPool keypool;

    ReserveSubAddressFromPool(account, nIndex, keypool);
    id = SubAddressIdentifier{account, (account > -1 ? static_cast<uint64_t>(nIndex) : 0)};
    if (nIndex <= -1) {
        if (m_storage.IsLocked()) return false;
        SubAddress subAddress = GenerateNewSubAddress(account, id);
        result = subAddress.GetKeys().GetID();
        return true;
    }
    KeepSubAddress({account, id.address});
    result = keypool.hashId;

    return true;
}

int KeyMan::GetSubAddressPoolSize(const int64_t& account) const
{
    LOCK(cs_KeyStore);
    return setSubAddressPool.count(account) > 0 ? setSubAddressPool.at(account).size() : 0;
}

int64_t KeyMan::GetOldestSubAddressPoolTime(const int64_t& account)
{
    LOCK(cs_KeyStore);

    if (setSubAddressPool.count(account) == 0)
        setSubAddressPool.insert(std::make_pair(account, std::set<uint64_t>()));

    // if the keypool is empty, return <NOW>
    if (setSubAddressPool[account].empty())
        return GetTime();

    // load oldest key from keypool, get time and return
    SubAddressPool keypool;
    wallet::WalletBatch batch(m_storage.GetDatabase());
    uint64_t nIndex = *(setSubAddressPool[account].begin());
    if (!batch.ReadSubAddressPool({account, nIndex}, keypool))
        throw std::runtime_error(std::string(__func__) + ": Read oldest key in keypool failed");
    return keypool.nTime;
}

util::Result<CTxDestination> KeyMan::GetNewDestination(const int64_t& account)
{
    // Fill-up keypool if needed
    TopUp();

    LOCK(cs_KeyStore);

    // Generate a new key that is added to wallet
    SubAddressIdentifier id;
    CKeyID keyId;
    if (!GetSubAddressFromPool(account, keyId, id)) {
        return util::Error{_("Error: Keypool ran out, please call keypoolrefill first")};
    }
    return CTxDestination(GetSubAddress(id).GetKeys());
}

bool KeyMan::OutputIsChange(const CTxOut& out) const
{
    auto id = GetHashId(out);
    blsct::SubAddressIdentifier subAddId;

    if (GetSubAddressId(id, subAddId)) {
        return subAddId.account == CHANGE_ACCOUNT;
    }

    return false;
}

int64_t KeyMan::GetTimeFirstKey() const
{
    LOCK(cs_KeyStore);
    return nTimeFirstKey;
}

bool KeyMan::ExtractSpendingKeyFromScript(const CScript& script, blsct::PublicKey& spendingKey) const
{
    // Parse the script to find OP_BLSCHECKSIG and extract the public key before it
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> vch;
    std::vector<unsigned char> lastData; // Keep track of the last data pushed

    if (script.size() != 50) return false;

    while (pc < script.end()) {
        if (!script.GetOp(pc, opcode, vch)) {
            return false;
        }

        if (opcode == OP_BLSCHECKSIG) {
            // We found OP_BLSCHECKSIG, the public key should be the last data pushed before this opcode
            if (lastData.size() == 48) { // BLS public keys are 48 bytes
                return spendingKey.SetVch(lastData);
            }
            return false;
        }

        // If this is a data push (not an opcode), store it as the last data
        if (opcode <= OP_PUSHDATA4) {
            lastData = vch;
        }
    }

    return false;
}
} // namespace blsct
