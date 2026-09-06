// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_WALLET_KEYMAN_H
#define NAVIO_BLSCT_WALLET_KEYMAN_H

#include <blsct/double_public_key.h>
#include <blsct/private_key.h>
#include <blsct/public_key.h>
#include <blsct/range_proof/bulletproofs_plus/amount_recovery_request.h>
#include <blsct/range_proof/bulletproofs_plus/amount_recovery_result.h>
#include <blsct/range_proof/bulletproofs_plus/range_proof_logic.h>
#include <blsct/wallet/address.h>
#include <blsct/wallet/hdchain.h>
#include <blsct/wallet/helpers.h>
#include <blsct/wallet/import_wallet_type.h>
#include <blsct/wallet/keyring.h>
#include <btcsignals.h>
#include <logging.h>
#include <support/allocators/secure.h>
#include <util/strencodings.h>
#include <wallet/crypter.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/walletdb.h>

#include <optional>

namespace blsct {

const int64_t CHANGE_ACCOUNT = -1;
const int64_t STAKING_ACCOUNT = -2;

using SecureBytes = std::vector<unsigned char, secure_allocator<unsigned char>>;

class Manager
{
protected:
    wallet::WalletStorage& m_storage;

public:
    explicit Manager(wallet::WalletStorage& storage) : m_storage(storage) {}
    virtual ~Manager()= default;

    virtual bool SetupGeneration(const std::vector<unsigned char>& seed, const SeedType& type, bool force = false, const std::string& mnemonic_passphrase = "", const std::optional<int64_t>& creation_time = std::nullopt) { return false; }

    /* Returns true if HD is enabled */
    virtual bool IsHDEnabled() const { return false; }
};

class KeyMan : public Manager, public KeyRing
{
private:
    blsct::HDChain m_hd_chain GUARDED_BY(cs_KeyStore);
    SecureBytes m_mnemonic_entropy GUARDED_BY(cs_KeyStore);
    std::vector<unsigned char> m_crypted_mnemonic_entropy GUARDED_BY(cs_KeyStore);
    std::unordered_map<CKeyID, blsct::HDChain, SaltedSipHasher> m_inactive_hd_chains GUARDED_BY(cs_KeyStore);
    std::optional<int64_t> m_wallet_birthday;

    bool AddKeyPubKeyInner(const PrivateKey& key, const PublicKey& pubkey);
    bool AddCryptedKeyInner(const PublicKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret);

    bool SetupMnemonicFromEntropy(const std::vector<unsigned char>& entropy, const std::string& mnemonic_passphrase = "", const std::optional<int64_t>& creation_time = std::nullopt);

    //! The HD-enabled predicate, for callers already holding cs_KeyStore.
    //! IsHDEnabled() takes the lock and answers on its own; the master-key
    //! accessors need this answer and the id they return to come from the
    //! *same* acquisition, so they read both inside one WITH_LOCK instead.
    //! Defined once here so the three cannot drift apart.
    bool HasHDSeed() const EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore)
    {
        return !m_hd_chain.seed_id.IsNull();
    }


    wallet::WalletBatch* encrypted_batch GUARDED_BY(cs_KeyStore) = nullptr;

    using CryptedKeyMap = std::map<CKeyID, std::pair<PublicKey, std::vector<unsigned char>>>;
    using SubAddressMap = std::map<CKeyID, SubAddressIdentifier>;
    using SubAddressStrMap = std::map<SubAddress, CKeyID>;
    using SubAddressPoolMapSet = std::map<int64_t, std::set<uint64_t>>;
    using WatchOnlyScriptMap = std::map<CScriptID, wallet::CKeyMetadata>;
    using WatchOnlyNonceMap = std::map<CScriptID, blsct::PublicKey>;

    CryptedKeyMap mapCryptedKeys GUARDED_BY(cs_KeyStore);
    SubAddressMap mapSubAddresses GUARDED_BY(cs_KeyStore);
    SubAddressStrMap mapSubAddressesStr GUARDED_BY(cs_KeyStore);
    SubAddressPoolMapSet setSubAddressPool GUARDED_BY(cs_KeyStore);
    SubAddressPoolMapSet setSubAddressReservePool GUARDED_BY(cs_KeyStore);
    std::set<CScript> setWatchOnly GUARDED_BY(cs_KeyStore);
    WatchOnlyScriptMap m_script_metadata GUARDED_BY(cs_KeyStore);
    WatchOnlyNonceMap m_watch_only_nonces GUARDED_BY(cs_KeyStore);

    int64_t nTimeFirstKey GUARDED_BY(cs_KeyStore) = 0;
    //! Number of pre-generated SubAddresses
    int64_t m_keypool_size GUARDED_BY(cs_KeyStore){wallet::DEFAULT_KEYPOOL_SIZE};

    bool fDecryptionThoroughlyChecked = true;

public:
    KeyMan(wallet::WalletStorage& storage, int64_t keypool_size)
        : Manager(storage), KeyRing(), m_keypool_size(keypool_size) {}

    bool SetupGeneration(const std::vector<unsigned char>& seed, const SeedType& type = IMPORT_MASTER_KEY, bool force = false, const std::string& mnemonic_passphrase = "", const std::optional<int64_t>& creation_time = std::nullopt) override;
    bool IsHDEnabled() const override;

    void LoadMnemonicEntropy(const std::vector<unsigned char>& entropy)
    {
        LOCK(cs_KeyStore);
        m_mnemonic_entropy.assign(entropy.begin(), entropy.end());
    }

    void LoadCryptedMnemonicEntropy(const std::vector<unsigned char>& crypted_entropy)
    {
        LOCK(cs_KeyStore);
        m_crypted_mnemonic_entropy = crypted_entropy;
    }

    bool HasMnemonicEntropy() const
    {
        LOCK(cs_KeyStore);
        return !m_mnemonic_entropy.empty();
    }

    bool HasCryptedMnemonicEntropy() const
    {
        LOCK(cs_KeyStore);
        return !m_crypted_mnemonic_entropy.empty();
    }

    SecureBytes GetMnemonicEntropy() const
    {
        LOCK(cs_KeyStore);
        return m_mnemonic_entropy;
    }

    /* Returns true if the wallet can generate new keys */
    bool CanGenerateKeys() const;

    /* Generates a new HD seed (will not be activated) */
    PrivateKey GenerateNewSeed();

    /* Set the current HD seed (will reset the chain child index counters)
       Sets the seed's version based on the current wallet version (so the
       caller must ensure the current wallet version is correct before calling
       this function). */
    void SetHDSeed(const PrivateKey& key, const std::optional<int64_t>& creation_time = std::nullopt);

    //! The wallet's genuine creation time, when known: recorded at setup for
    //! freshly created wallets (their creation instant) and for restores from
    //! a birthday mnemonic (the decoded time), persisted in the wallet DB. It
    //! is deliberately NOT inferred for other restores (e.g. a plain 24-word
    //! mnemonic), whose on-chain history can predate this instantiation.
    std::optional<int64_t> GetWalletBirthday() const { return m_wallet_birthday; }

    //! Persist a genuine-birthday record for this wallet (see above). Only
    //! called by the wallet-creation flow when the creation time is truly
    //! known.
    bool WriteWalletBirthday(int64_t birthday);

    //! Adds a key to the store, and saves it to disk.
    bool AddKeyPubKey(const PrivateKey& key, const PublicKey& pubkey) override;
    bool AddViewKey(const PrivateKey& key, const PublicKey& pubkey) override;
    bool AddSpendKey(const PublicKey& pubkey) override;

    //! Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadKey(const PrivateKey& key, const PublicKey& pubkey);
    bool LoadViewKey(const PrivateKey& key, const PublicKey& pubkey);
    bool LoadSpendKey(const PublicKey& pubkey);
    //! Adds an encrypted key to the store, and saves it to disk.
    bool AddCryptedKey(const PublicKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret);
    //! Adds an encrypted key to the store, without saving it to disk (used by LoadWallet)
    bool LoadCryptedKey(const PublicKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret, bool checksum_valid);
    bool AddKeyPubKeyWithDB(wallet::WalletBatch& batch, const PrivateKey& secret, const PublicKey& pubkey) EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);
    bool AddSubAddressPoolWithDB(wallet::WalletBatch& batch, const SubAddressIdentifier& id, const SubAddress& subAddress, const bool& fLock = true);
    bool AddSubAddressPoolInner(const SubAddressIdentifier& id, const bool& fLock = true);

    /* KeyRing overrides */
    bool HaveKey(const CKeyID& address) const override;
    bool GetKey(const CKeyID& address, PrivateKey& keyOut) const override;

    bool Encrypt(const wallet::CKeyingMaterial& master_key, wallet::WalletBatch* batch);
    bool CheckDecryptionKey(const wallet::CKeyingMaterial& master_key, bool accept_no_keys);
    void ClearMnemonicEntropy();

    SubAddress GenerateNewSubAddress(const int64_t& account, SubAddressIdentifier& id);
    SubAddress GetSubAddress(const SubAddressIdentifier& id = {0, 0}) const;
    util::Result<CTxDestination> GetNewDestination(const int64_t& account = 0);

    /* Set the HD chain model (chain child index counters) and writes it to the database */
    void AddHDChain(const blsct::HDChain& chain);
    void LoadHDChain(const blsct::HDChain& chain);
    /* Returns a snapshot of the HD chain model. Deliberately by value: a
       reference would let the caller keep reading m_hd_chain after cs_KeyStore
       is released, which the GUARDED_BY annotation cannot detect. */
    blsct::HDChain GetHDChain() const
    {
        LOCK(cs_KeyStore);
        return m_hd_chain;
    }
    void AddInactiveHDChain(const blsct::HDChain& chain);

    //! Load metadata (used by LoadWallet)
    void LoadKeyMetadata(const CKeyID& keyID, const wallet::CKeyMetadata& metadata);
    void UpdateTimeFirstKey(int64_t nCreateTime) EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);

    bool DeleteRecords();
    bool DeleteKeys();

    /** Detect ownership of outputs **/
    bool IsMine(const CTxOut& txout)
    {
        return IsMineMode(txout) != wallet::ISMINE_NO;
    };
    /**
     * Classify ownership of a BLSCT output. Returns one of:
     *   ISMINE_SPENDABLE_BLSCT          - paid to one of our subaddresses; the
     *                                     wallet can derive the spending key
     *                                     and produce a signature.
     *   ISMINE_STAKED_COMMITMENT_BLSCT  - same, for staked commitments.
     *   ISMINE_WATCH_ONLY               - the wallet only has decryption
     *                                     material via an imported scriptPubKey
     *                                     (e.g. an HTLC imported with
     *                                     importblsctscript). The amount can
     *                                     be recovered, but no signing key
     *                                     is available.
     *   ISMINE_NO                       - not ours.
     */
    wallet::isminetype IsMineMode(const CTxOut& txout);
    bool IsMine(const CScript& script) const;

    //! The nonce an output addressed to this wallet would share with us:
    //! blindingKey * ourViewKey — the expensive part of the ownership test
    //! (one BLS12-381 G1 scalar multiplication) and the intermediate every
    //! downstream check derives from (view tag via ViewTagFromNonce, hash id
    //! via CalculateHashId). Both MarkUnusedSubAddress and IsMineMode need it
    //! per output during a scan; compute it ONCE with this and pass it to the
    //! overloads below so the dominant per-output cost is paid a single time.
    //! Returns nullopt when the output cannot be ours (no view key / not a
    //! BLSCT output / zero blinding key) or when derivation throws (malformed
    //! blsctData), so callers outside a handler stay exception-safe.
    std::optional<BlstG1Point> GetExpectedNonce(const CTxOut& txout) const;
    //! IsMineMode / IsMine / MarkUnusedSubAddress variants that take the
    //! precomputed nonce instead of re-deriving it. A nullopt nonce (output
    //! cannot be a BLSCT output of ours) makes the BLSCT ownership checks
    //! fail without any EC work, falling through to the scriptPubKey
    //! watch-only path exactly as the original did. The hash id is computed
    //! from the nonce directly, so these need no view key access at all.
    wallet::isminetype IsMineMode(const CTxOut& txout, const std::optional<BlstG1Point>& expectedNonce);
    bool IsMine(const blsct::PublicKey& spendingKey, const uint16_t& viewTag, const std::optional<BlstG1Point>& expectedNonce);
    CKeyID GetHashId(const CTxOut& txout) const
    {
        if (!txout.scriptPubKey.IsSpendable() && !txout.IsStakedCommitment()) {
            return CKeyID();
        }
        if (txout.blsctData.spendingKey.IsZero()) {
            blsct::PublicKey extractedSpendingKey;
            if (ExtractSpendingKeyFromScript(txout.scriptPubKey, extractedSpendingKey)) {
                return GetHashId(txout.blsctData.blindingKey, extractedSpendingKey);
            }
            return CKeyID();
        }
        return GetHashId(txout.blsctData.blindingKey, txout.blsctData.spendingKey);
    }
    //! Same key selection as GetHashId(txout), but derives the id from a
    //! precomputed nonce (blindingKey * viewKey), so it needs no view key and
    //! pays no extra scalar multiplication.
    CKeyID GetHashId(const CTxOut& txout, const BlstG1Point& expectedNonce) const
    {
        if (!txout.scriptPubKey.IsSpendable() && !txout.IsStakedCommitment()) {
            return CKeyID();
        }
        if (txout.blsctData.spendingKey.IsZero()) {
            blsct::PublicKey extractedSpendingKey;
            if (ExtractSpendingKeyFromScript(txout.scriptPubKey, extractedSpendingKey)) {
                return CalculateHashId(expectedNonce, extractedSpendingKey.GetG1Point());
            }
            return CKeyID();
        }
        return CalculateHashId(expectedNonce, txout.blsctData.spendingKey);
    }
    CKeyID GetHashId(const blsct::PublicKey& blindingKey, const blsct::PublicKey& spendingKey) const;
    CTxDestination GetDestination(const CTxOut& txout) const;
    blsct::PrivateKey GetMasterSeedKey() const;
    blsct::PrivateKey GetPrivateViewKey() const;
    blsct::PublicKey GetPublicSpendingKey() const;
    blsct::PrivateKey GetMasterTokenKey() const;
    blsct::PrivateKey GetSpendingKey() const;
    bool GetSpendingKeyForOutput(const CTxOut& out, blsct::PrivateKey& key) const;
    bool GetSpendingKeyForOutput(const CTxOut& out, const CKeyID& id, blsct::PrivateKey& key) const;
    bool GetSpendingKeyForOutput(const CTxOut& out, const SubAddressIdentifier& id, blsct::PrivateKey& key) const;
    bulletproofs_plus::AmountRecoveryResult<Blst> RecoverOutputs(const std::vector<CTxOut>& outs);
    bulletproofs_plus::AmountRecoveryResult<Blst> RecoverOutputsWithNonce(const std::vector<CTxOut>& outs, const Point& nonce);

    blsct::PrivateKey GetTokenKey(const uint256& tokenId) const;
    blsct::PrivateKey GetTokenKey(const blsct::PublicKey& tokenPublicKey) const { return GetTokenKey(tokenPublicKey.GetHash()); };

    /** SubAddress keypool */
    void LoadSubAddress(const CKeyID& hashId, const SubAddressIdentifier& index);
    bool AddSubAddress(const CKeyID& hashId, const SubAddressIdentifier& index);
    bool HaveSubAddress(const CKeyID& hashId) const EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);
    bool GetSubAddress(const CKeyID& hashId, SubAddress& address) const;
    bool GetSubAddressId(const CKeyID& hashId, SubAddressIdentifier& subAddId) const;
    void LoadSubAddressStr(const SubAddress& subAddress, const CKeyID& hashId);
    bool AddSubAddressStr(const SubAddress& subAddress, const CKeyID& hashId);
    bool HaveSubAddressStr(const SubAddress& subAddress) const;
    bool NewSubAddressPool(const int64_t& account = 0);
    bool TopUp(const unsigned int& size = 0);
    bool TopUpAccount(const int64_t& account, const unsigned int& size = 0);
    std::optional<wallet::WalletDestination> MarkUnusedSubAddress(const CTxOut& txout);
    std::optional<wallet::WalletDestination> MarkUnusedSubAddress(const CTxOut& txout, const BlstG1Point& expectedNonce);
    void ReserveSubAddressFromPool(const int64_t& account, int64_t& nIndex, SubAddressPool& keypool);
    void KeepSubAddress(const SubAddressIdentifier& id);
    void ReturnSubAddress(const SubAddressIdentifier& id);
    bool GetSubAddressFromPool(const int64_t& account, CKeyID& result, SubAddressIdentifier& id);
    int64_t GetOldestSubAddressPoolTime(const int64_t& account);
    int GetSubAddressPoolSize(const int64_t& account) const;

    bool OutputIsChange(const CTxOut& out) const;

    int64_t GetTimeFirstKey() const;

    //! Load the persisted birthday record (if any) during wallet open.
    void LoadWalletBirthday(int64_t birthday) { m_wallet_birthday = birthday; }

    /** Keypool has new keys */
    btcsignals::signal<void()>
        NotifyCanGetAddressesChanged;

    // Map from Key ID to key metadata.
    std::map<CKeyID, wallet::CKeyMetadata> mapKeyMetadata GUARDED_BY(cs_KeyStore);

    /** Prepends the wallet name in logging output to ease debugging in multi-wallet use cases */
    template <typename... Params>
    void WalletLogPrintf(std::string fmt, Params... parameters) const
    {
        LogPrintf(("%s " + fmt).c_str(), m_storage.GetDisplayName(), parameters...);
    };

    // Helper function to extract spending key from OP_BLSCHECKSIG script
    bool ExtractSpendingKeyFromScript(const CScript& script, blsct::PublicKey& spendingKey) const;

    // Extract all 48-byte BLS public keys from a script (for HTLC and other complex scripts)
    bool ExtractAllSpendingKeysFromScript(const CScript& script, std::vector<blsct::PublicKey>& spendingKeys) const;

    /** Watch-only script management */
    bool AddWatchOnly(const CScript& script, const std::optional<blsct::PublicKey>& recovery_nonce = std::nullopt);
    //! Whether any script is watched (e.g. imported with importblsctscript).
    bool HaveWatchOnly() const;
    void LoadWatchOnly(const CScript& script);
    void LoadWatchOnlyRecoveryNonce(const CScript& script, const blsct::PublicKey& nonce);
    std::optional<blsct::PublicKey> GetWatchOnlyRecoveryNonce(const CScript& script) const;
};
} // namespace blsct

#endif // NAVIO_BLSCT_WALLET_KEYMAN_H
