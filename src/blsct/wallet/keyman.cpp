// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/eip_2333/bls12_381_keygen.h>
#include <blsct/wallet/keyman.h>
#include <hash.h>
#include <script/script.h>
#include <wallet/walletdb.h>

#include <random.h>

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
    // Check if encryption keys exist first (doesn't require lock)
    if (!m_storage.HasEncryptionKeys()) {
        LOCK(cs_KeyStore);
        return KeyRing::AddKeyOutKey(key, outId);
    }

    // If encryption keys exist, we need cs_wallet to call GetEncryptionKey()
    // Acquire cs_wallet first, then cs_KeyStore to maintain consistent lock ordering
    LOCK2(m_storage.GetWalletMutex(), cs_KeyStore);
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
    // Check if encryption keys exist first (doesn't require lock)
    if (!m_storage.HasEncryptionKeys()) {
        LOCK(cs_KeyStore);
        return KeyRing::AddKeyPubKey(key, pubkey);
    }

    // If encryption keys exist, we need cs_wallet to call GetEncryptionKey()
    // Acquire cs_wallet first, then cs_KeyStore to maintain consistent lock ordering
    LOCK2(m_storage.GetWalletMutex(), cs_KeyStore);
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
    std::vector<unsigned char> seed(32);
    GetStrongRandBytes(seed);
    return BLS12_381_KeyGen::derive_master_SK(seed);
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

bool KeyMan::SetupMnemonicFromEntropy(const std::vector<unsigned char>& entropy)
{
    auto masterKey = PrivateKey(BLS12_381_KeyGen::derive_master_SK(entropy));
    SetHDSeed(masterKey);
    LoadMnemonicEntropy(entropy);
    wallet::WalletBatch batch(m_storage.GetDatabase());
    if (m_storage.HasEncryptionKeys()) {
        wallet::CKeyingMaterial plaintext(entropy.begin(), entropy.end());
        std::vector<unsigned char> crypted_entropy;
        uint256 iv = Hash(m_hd_chain.seed_id);
        if (!wallet::EncryptSecret(m_storage.GetEncryptionKey(), plaintext, iv, crypted_entropy)) {
            return false;
        }
        batch.WriteCryptedBLSCTMnemonicEntropy(crypted_entropy);
        LoadCryptedMnemonicEntropy(crypted_entropy);
    } else {
        batch.WriteBLSCTMnemonicEntropy(entropy);
    }
    return true;
}

bool KeyMan::SetupGeneration(const std::vector<unsigned char>& seed, const SeedType& type, bool force)
{
    if ((CanGenerateKeys() && !force) || m_storage.IsLocked()) {
        return false;
    }

    if (seed.size() == 32 && type == IMPORT_MNEMONIC) {
        if (!SetupMnemonicFromEntropy(seed)) return false;
    } else if (seed.size() == 32 && type == IMPORT_MASTER_KEY) {
        MclScalar scalarSeed;
        scalarSeed.SetVch(seed);
        SetHDSeed(scalarSeed);
    } else if (seed.size() == 80 && type == IMPORT_VIEW_KEY) {
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
    } else if (seed.empty()) {
        std::vector<unsigned char> entropy(32);
        GetStrongRandBytes(entropy);
        if (!SetupMnemonicFromEntropy(entropy)) return false;
    } else {
        return false;
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

        // Decrypt mnemonic entropy if present
        if (!m_crypted_mnemonic_entropy.empty() && m_mnemonic_entropy.empty()) {
            wallet::CKeyingMaterial plaintext;
            uint256 iv = Hash(m_hd_chain.seed_id);
            if (!wallet::DecryptSecret(master_key, m_crypted_mnemonic_entropy, iv, plaintext)) {
                LogPrintf("Failed to decrypt mnemonic entropy\n");
                return false;
            }
            m_mnemonic_entropy.assign(plaintext.begin(), plaintext.end());
        }
    }
    return true;
}

void KeyMan::ClearMnemonicEntropy()
{
    LOCK(cs_KeyStore);
    m_mnemonic_entropy.clear();
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
    return mapCryptedKeys.contains(id);
}

bool KeyMan::GetKey(const CKeyID& id, PrivateKey& keyOut) const
{
    // Check if encryption keys exist first (doesn't require lock)
    if (!m_storage.HasEncryptionKeys()) {
        LOCK(cs_KeyStore);
        return KeyRing::GetKey(id, keyOut);
    }

    // If encryption keys exist, we need cs_wallet to call GetEncryptionKey()
    // Acquire cs_wallet first, then cs_KeyStore to maintain consistent lock ordering
    LOCK2(m_storage.GetWalletMutex(), cs_KeyStore);
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
    // Check if encryption keys exist first (doesn't require lock)
    if (!m_storage.HasEncryptionKeys()) {
        LOCK(cs_KeyStore);
        return KeyRing::GetOutKey(id, keyOut);
    }

    // If encryption keys exist, we need cs_wallet to call GetEncryptionKey()
    // Acquire cs_wallet first, then cs_KeyStore to maintain consistent lock ordering
    LOCK2(m_storage.GetWalletMutex(), cs_KeyStore);
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

    // Encrypt mnemonic entropy if present
    if (!m_mnemonic_entropy.empty()) {
        wallet::CKeyingMaterial plaintext(m_mnemonic_entropy.begin(), m_mnemonic_entropy.end());
        std::vector<unsigned char> crypted_entropy;
        uint256 iv = Hash(m_hd_chain.seed_id);
        if (!wallet::EncryptSecret(master_key, plaintext, iv, crypted_entropy)) {
            encrypted_batch = nullptr;
            return false;
        }
        if (!encrypted_batch->WriteCryptedBLSCTMnemonicEntropy(crypted_entropy)) {
            encrypted_batch = nullptr;
            return false;
        }
        m_crypted_mnemonic_entropy = crypted_entropy;
        m_mnemonic_entropy.clear();
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
        throw std::runtime_error(strprintf("%s: the wallet has no HD enabled", __func__));

    auto seedId = m_hd_chain.seed_id;

    PrivateKey ret;

    if (!GetKey(seedId, ret))
        throw std::runtime_error(strprintf("%s: could not access the master seed key", __func__));

    return ret;
}

blsct::PrivateKey KeyMan::GetMasterTokenKey() const
{
    if (!IsHDEnabled())
        throw std::runtime_error(strprintf("%s: the wallet has no HD enabled", __func__));

    auto tokenKeyId = m_hd_chain.token_id;

    PrivateKey ret;

    if (!GetKey(tokenKeyId, ret))
        throw std::runtime_error(strprintf("%s: could not access the master token key", __func__));

    return ret;
}

blsct::PrivateKey KeyMan::GetPrivateViewKey() const
{
    if (!fViewKeyDefined)
        throw std::runtime_error(strprintf("%s: the wallet has no view key available", __func__));

    return viewKey;
}

blsct::PublicKey KeyMan::GetPublicSpendingKey() const
{
    return spendPublicKey;
}

blsct::PrivateKey KeyMan::GetSpendingKey() const
{
    if (!fSpendKeyDefined)
        throw std::runtime_error(strprintf("%s: the wallet has no spend key available", __func__));

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

    // Collect candidate blinding keys for parallel view-tag calculation.
    // We only do the v·R scalar mult for outputs that are structurally BLSCT;
    // per-output scalar mult is the hot cost, so batching amortises thread overhead.
    std::vector<size_t> candidateIdx;
    std::vector<MclG1Point> candidateBlindingKeys;
    candidateIdx.reserve(outs.size());
    candidateBlindingKeys.reserve(outs.size());

    for (size_t i = 0; i < outs.size(); ++i) {
        const CTxOut& out = outs[i];
        if (!out.HasBLSCTKeys() || !out.HasBLSCTRangeProof()) continue;
        candidateIdx.push_back(i);
        candidateBlindingKeys.push_back(out.blsctData.blindingKey);
    }

    auto tags = CalculateViewTagBatch(candidateBlindingKeys, viewKey.GetScalar());

    for (size_t k = 0; k < candidateIdx.size(); ++k) {
        size_t i = candidateIdx[k];
        const CTxOut& out = outs[i];
        if (out.blsctData.viewTag != tags[k])
            continue;
        auto nonce = CalculateNonce(out.blsctData.blindingKey, viewKey.GetScalar());
        bulletproofs_plus::RangeProofWithSeed<Arith> proof = {out.blsctData.rangeProof, out.tokenId};
        reqs.push_back(bulletproofs_plus::AmountRecoveryRequest<Arith>::of(proof, nonce, i));
    }

    return rp.RecoverAmounts(reqs);
}

bulletproofs_plus::AmountRecoveryResult<Arith> KeyMan::RecoverOutputsWithNonce(const std::vector<CTxOut>& outs, const Point& nonce)
{
    // No viewKey guard here: this function is used for watch-only scripts where
    // a pre-computed nonce is supplied by the caller (e.g. from an imported
    // script's recovery hint).  The viewKey is not consulted and may be absent.
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
    return setWatchOnly.contains(script);
}

wallet::isminetype KeyMan::IsMineMode(const CTxOut& txout)
{
    const auto spendable_kind = [&]() {
        return txout.IsStakedCommitment() ? wallet::ISMINE_STAKED_COMMITMENT_BLSCT
                                          : wallet::ISMINE_SPENDABLE_BLSCT;
    };

    if (txout.blsctData.spendingKey.IsZero()) {
        // The output's blsctData does not carry an explicit spending pubkey.
        // First try to extract one from the scriptPubKey: this covers the
        // standard `<48-byte pubkey> OP_BLSCHECKSIG` shape that some
        // codepaths produce without populating blsctData.spendingKey. If we
        // own the resulting subaddress, the output is fully spendable.
        blsct::PublicKey extractedSpendingKey;
        if (ExtractSpendingKeyFromScript(txout.scriptPubKey, extractedSpendingKey)) {
            if (IsMine(txout.blsctData.blindingKey, extractedSpendingKey, txout.blsctData.viewTag)) {
                return spendable_kind();
            }
        }
        // Next, the output may be ours via an explicitly imported watch-only
        // script (e.g. an HTLC added through importblsctscript). We can decrypt
        // the amount but cannot derive a signing key.
        if (IsMine(txout.scriptPubKey)) {
            return wallet::ISMINE_WATCH_ONLY;
        }
        // Finally, handle non-standard scripts (size != 50) that still embed one
        // or more 48-byte BLS pubkeys — e.g. an atomic-swap HTLC carrying redeem
        // and refund branches. The single-key extractor above bails on these via
        // its size==50 guard, so probe every branch pubkey: if any resolves to
        // one of our subaddresses, the output pays us. We can decrypt the amount,
        // but the standard spend path cannot reconstruct the HTLC signing key
        // (it needs the branch offset and the externally-supplied blinding key),
        // so classify as watch-only rather than spendable. Standard 50-byte
        // scripts were already fully handled by the single-key extractor above,
        // so skip the re-parse and vector allocation for them.
        std::vector<blsct::PublicKey> branchKeys;
        if (txout.scriptPubKey.size() != 50 &&
            ExtractAllSpendingKeysFromScript(txout.scriptPubKey, branchKeys)) {
            for (const auto& branchKey : branchKeys) {
                if (IsMine(txout.blsctData.blindingKey, branchKey, txout.blsctData.viewTag)) {
                    return wallet::ISMINE_WATCH_ONLY;
                }
            }
        }
        return wallet::ISMINE_NO;
    }

    if (IsMine(txout.blsctData.blindingKey, txout.blsctData.spendingKey, txout.blsctData.viewTag)) {
        return spendable_kind();
    }
    // Real BLSCT output that we don't own as a subaddress, but whose
    // scriptPubKey was imported as watch-only.
    if (IsMine(txout.scriptPubKey)) {
        return wallet::ISMINE_WATCH_ONLY;
    }
    return wallet::ISMINE_NO;
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
    return mapSubAddresses.contains(hashId);
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
    return mapSubAddressesStr.contains(subAddress);
}

SubAddress KeyMan::GenerateNewSubAddress(const int64_t& account, SubAddressIdentifier& id)
{
    if (!m_hd_chain.nSubAddressCounter.contains(account))
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

    if (setSubAddressPool.contains(account)) {
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

        if (!setSubAddressPool.contains(account))
            setSubAddressPool.insert(std::make_pair(account, std::set<uint64_t>()));

        if (!setSubAddressReservePool.contains(account))
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
        if (!setSubAddressPool.contains(id.account))
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
    id = SubAddressIdentifier{account, (nIndex > -1 ? static_cast<uint64_t>(nIndex) : 0)};
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
    return setSubAddressPool.contains(account) ? setSubAddressPool.at(account).size() : 0;
}

int64_t KeyMan::GetOldestSubAddressPoolTime(const int64_t& account)
{
    LOCK(cs_KeyStore);

    if (!setSubAddressPool.contains(account))
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

std::optional<wallet::WalletDestination> KeyMan::MarkUnusedSubAddress(const CTxOut& txout)
{
    try {
        // Cheap prefilter: viewTag must match before we do any expensive work.
        // Without this, every non-wallet BLSCT output forces the
        // 3 × keypool × full subaddress derivation scan below, which dominates
        // rescan cost (millions of BLS scalar multiplications per chain).
        if (!fViewKeyDefined || !viewKey.IsValid()) return std::nullopt;
        if (!txout.HasBLSCTKeys()) return std::nullopt;
        if (txout.blsctData.blindingKey.IsZero()) return std::nullopt;
        if (txout.blsctData.viewTag != CalculateViewTag(
                txout.blsctData.blindingKey, viewKey.GetScalar())) {
            return std::nullopt;
        }

        const CKeyID hash_id = GetHashId(txout);
        if (hash_id.IsNull()) return std::nullopt;

        std::optional<SubAddressIdentifier> matched_id;
        bool was_unused_pool_key = false;
        bool learned_beyond_lookahead = false;

        {
            LOCK(cs_KeyStore);

            const auto known_it = mapSubAddresses.find(hash_id);
            if (known_it != mapSubAddresses.end()) {
                matched_id = known_it->second;
                if (const auto pool_it = setSubAddressPool.find(matched_id->account);
                    pool_it != setSubAddressPool.end()) {
                    was_unused_pool_key = pool_it->second.contains(matched_id->address);
                }
            } else {
                const uint64_t lookahead = std::max<int64_t>(m_keypool_size, int64_t{1});
                for (const int64_t account : {int64_t{0}, CHANGE_ACCOUNT, STAKING_ACCOUNT}) {
                    const uint64_t start = m_hd_chain.nSubAddressCounter.contains(account)
                        ? m_hd_chain.nSubAddressCounter.at(account)
                        : 0;
                    for (uint64_t index = start; index < start + lookahead; ++index) {
                        if (GetSubAddress({account, index}).GetKeys().GetID() != hash_id) continue;
                        matched_id = SubAddressIdentifier{account, index};
                        learned_beyond_lookahead = true;
                        break;
                    }
                    if (matched_id) break;
                }
            }
        }

        if (!matched_id) return std::nullopt;

        if (learned_beyond_lookahead) {
            WalletLogPrintf("%s: learned BLSCT subaddress %d/%d beyond current lookahead\n",
                            __func__,
                            matched_id->account,
                            matched_id->address);
            for (;;) {
                SubAddressIdentifier generated_id;
                GenerateNewSubAddress(matched_id->account, generated_id);
                if (generated_id.account == matched_id->account && generated_id.address >= matched_id->address) {
                    break;
                }
            }
        }

        if (was_unused_pool_key) {
            {
                LOCK(cs_KeyStore);
                wallet::WalletBatch batch(m_storage.GetDatabase());
                auto& pool = setSubAddressPool[matched_id->account];
                for (auto it = pool.begin(); it != pool.end() && *it <= matched_id->address;) {
                    batch.EraseSubAddressPool({matched_id->account, *it});
                    if (auto reserve_it = setSubAddressReservePool.find(matched_id->account);
                        reserve_it != setSubAddressReservePool.end()) {
                        reserve_it->second.erase(*it);
                    }
                    it = pool.erase(it);
                }
            }
            WalletLogPrintf("%s: detected used BLSCT keypool entry %d/%d, topping up lookahead\n",
                            __func__,
                            matched_id->account,
                            matched_id->address);
        }

        if ((learned_beyond_lookahead || was_unused_pool_key) && !TopUpAccount(matched_id->account)) {
            WalletLogPrintf("%s: topping up BLSCT account %d failed (wallet likely locked)\n",
                            __func__,
                            matched_id->account);
        }

        return wallet::WalletDestination{
            CTxDestination(GetSubAddress(*matched_id).GetKeys()),
            matched_id->account != 0,
        };
    } catch (const std::exception& e) {
        WalletLogPrintf("%s: failed to mark BLSCT subaddress as used: %s\n", __func__, e.what());
        return std::nullopt;
    }
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

bool KeyMan::ExtractAllSpendingKeysFromScript(const CScript& script, std::vector<blsct::PublicKey>& spendingKeys) const
{
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> vch;
    std::vector<std::vector<unsigned char>> candidates;
    bool has_blschecksig = false;

    while (pc < script.end()) {
        if (!script.GetOp(pc, opcode, vch)) {
            break;
        }

        if (opcode == OP_BLSCHECKSIG) {
            has_blschecksig = true;
        } else if (opcode <= OP_PUSHDATA4 && vch.size() == 48) {
            candidates.push_back(vch);
        }
    }

    if (!has_blschecksig) return false;

    for (const auto& data : candidates) {
        blsct::PublicKey key;
        if (key.SetVch(data)) {
            spendingKeys.push_back(key);
        }
    }

    return !spendingKeys.empty();
}

bool KeyMan::AddWatchOnly(const CScript& script, const std::optional<blsct::PublicKey>& recovery_nonce)
{
    // Acquire cs_wallet before cs_KeyStore to match the lock order used
    // elsewhere in this file and in the wallet layer.  Callers that already
    // hold cs_wallet (e.g. RPC handlers) are safe because it is a
    // RecursiveMutex.
    LOCK2(m_storage.GetWalletMutex(), cs_KeyStore);
    wallet::WalletBatch batch(m_storage.GetDatabase());
    wallet::CKeyMetadata meta;
    if (!batch.WriteBLSCTWatchOnly(script, meta)) {
        return false;
    }
    if (recovery_nonce && !batch.WriteBLSCTWatchOnlyNonce(script, *recovery_nonce)) {
        return false;
    }
    // Mutate in-memory state only after all DB writes succeed.
    setWatchOnly.insert(script);
    if (recovery_nonce) {
        m_watch_only_nonces[CScriptID(script)] = *recovery_nonce;
    }
    return true;
}

void KeyMan::LoadWatchOnly(const CScript& script)
{
    LOCK(cs_KeyStore);
    setWatchOnly.insert(script);
}

void KeyMan::LoadWatchOnlyRecoveryNonce(const CScript& script, const blsct::PublicKey& nonce)
{
    LOCK(cs_KeyStore);
    m_watch_only_nonces[CScriptID(script)] = nonce;
}

std::optional<blsct::PublicKey> KeyMan::GetWatchOnlyRecoveryNonce(const CScript& script) const
{
    LOCK(cs_KeyStore);
    const auto it = m_watch_only_nonces.find(CScriptID(script));
    if (it == m_watch_only_nonces.end()) {
        return std::nullopt;
    }
    return it->second;
}
} // namespace blsct
