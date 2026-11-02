// Copyright (c) 2012-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <blsct/private_key.h>
#include <blsct/public_key.h>
#include <clientversion.h>
#include <hash.h>
#include <streams.h>
#include <uint256.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(walletdb_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(walletdb_readkeyvalue)
{
    /**
     * When ReadKeyValue() reads from either a "key" or "wkey" it first reads the DataStream into a
     * CPrivKey or CWalletKey respectively and then reads a hash of the pubkey and privkey into a uint256.
     * Wallets from 0.8 or before do not store the pubkey/privkey hash, trying to read the hash from old
     * wallets throws an exception, for backwards compatibility this read is wrapped in a try block to
     * silently fail. The test here makes sure the type of exception thrown from DataStream::read()
     * matches the type we expect, otherwise we need to update the "key"/"wkey" exception type caught.
     */
    DataStream ssValue{};
    uint256 dummy;
    BOOST_CHECK_THROW(ssValue >> dummy, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(walletdb_read_write_deadlock)
{
    // Exercises a db read write operation that shouldn't deadlock.
    for (const DatabaseFormat& db_format : DATABASE_FORMATS) {
        // Context setup
        DatabaseOptions options;
        options.require_format = db_format;
        DatabaseStatus status;
        bilingual_str error_string;
        std::unique_ptr<WalletDatabase> db = MakeDatabase(m_path_root / strprintf("wallet_%d_.dat", db_format).c_str(), options, status, error_string);
        BOOST_CHECK_EQUAL(status, DatabaseStatus::SUCCESS);

        std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", std::move(db)));
        wallet->m_keypool_size = 4;

        // Create legacy spkm
        LOCK(wallet->cs_wallet);
        auto legacy_spkm = wallet->GetOrCreateLegacyScriptPubKeyMan();
        BOOST_CHECK(legacy_spkm->SetupGeneration(true));
        wallet->Flush();

        // Now delete all records, which performs a read write operation.
        BOOST_CHECK(wallet->GetLegacyScriptPubKeyMan()->DeleteRecords());
    }
}

/** Read back the (private key, checksum) value WriteIC stored under `key`. */
static std::pair<blsct::PrivateKey, uint256> ReadBLSCTKeyRecord(const MockableDatabase& db, const std::string& type, const blsct::PublicKey& pubkey)
{
    DataStream key;
    key << std::make_pair(type, pubkey);
    const auto it = db.m_records.find(SerializeData{key.begin(), key.end()});
    BOOST_REQUIRE(it != db.m_records.end());
    DataStream value{it->second};
    std::pair<blsct::PrivateKey, uint256> record;
    value >> record.first >> record.second;
    return record;
}

BOOST_AUTO_TEST_CASE(walletdb_blsct_key_checksum)
{
    // The checksum stored next to a plain BLSCT key is the hash of the public
    // key bytes followed by the private scalar's bytes, so wallets written in
    // that form keep loading. Pin it to that concatenation, computed from the
    // scalar the key was built from.
    const BlstScalar scalar{BlstScalar::Rand()};
    const blsct::PrivateKey privkey{scalar};
    const blsct::PublicKey pubkey{privkey.GetPublicKey()};
    const auto concat_hash = [&](std::vector<unsigned char> pub_bytes) {
        const auto priv_bytes{scalar.GetVch()};
        pub_bytes.insert(pub_bytes.end(), priv_bytes.begin(), priv_bytes.end());
        return Hash(pub_bytes);
    };

    MockableDatabase db;
    WalletBatch batch{db};
    BOOST_REQUIRE(batch.WriteKey(pubkey, privkey, CKeyMetadata{}));
    const auto [key_priv, key_hash] = ReadBLSCTKeyRecord(db, DBKeys::BLSCTKEY, pubkey);
    BOOST_CHECK(key_priv == privkey);
    BOOST_CHECK_EQUAL(key_hash, concat_hash(pubkey.GetVch()));

    // The view key record hashes the public key's G1 point serialization.
    db.m_records.clear();
    BOOST_REQUIRE(batch.WriteViewKey(pubkey, privkey, CKeyMetadata{}));
    const auto [view_priv, view_hash] = ReadBLSCTKeyRecord(db, DBKeys::VIEWKEY, pubkey);
    BOOST_CHECK(view_priv == privkey);
    BOOST_CHECK_EQUAL(view_hash, concat_hash(pubkey.GetG1Point().GetVch()));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
