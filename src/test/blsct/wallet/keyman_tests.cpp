// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/rpc.h>
#include <blsct/wallet/txfactory.h>
#include <blsct/wallet/verification.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <txdb.h>
#include <wallet/receive.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(blsct_keyman_tests)

// TODO: Make sure that WALLET_FLAG_BLSCT is set for the mockable wallet
BOOST_FIXTURE_TEST_CASE(wallet_test, TestingSetup)
{
    auto wallet = std::make_unique<wallet::CWallet>(m_node.chain.get(), "", wallet::CreateMockableWalletDatabase());
    wallet->InitWalletFlags(wallet::WALLET_FLAG_BLSCT);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    blsct_km->SetHDSeed(MclScalar(uint256(uint64_t{1})));
    BOOST_CHECK(blsct_km->NewSubAddressPool());
    BOOST_CHECK(blsct_km->NewSubAddressPool(-1));

    std::vector<std::string> expectedAddresses = {
        "nav14h85k6mf4l5fu3j4v0nuuswjwrz5entvzcw9jl3s8uknsndu0pfzaze4992n36uq7hpcy8yeuu854p0gmhq4m2u0tf5znazc527cxy4j7c39qxlc89wg4nca8pazkecx0p6wmu3pwrma3ercgrk8s7k4759q2thyq5",
        "nav1kq8zphgry92d02j7sm460c8xv88avuxcqlxrl7unxva9c4uawuvskx3s3pd6g3nychcq0ksy0tlpmgyt35384dnqdtudafa00yrjpcsffef404xur6cegkm98llf5xptkj6napgqk6g9dpa0x24qe4cgaqj2j0wl9p",
        "nav1s48u8dtxseguw6s7ecewph2szrxwy3fzx47rzdtppgzrnxrp0p0peetjx5h2f6gpwy3ar65tmw4p39z30pzt0t6san07th0694pffc0f6dghnskfujfanzwjdzep8fn0ezdeg7ejmvulj8nymrzkw8wdvqc3mqvnpw",
        "nav1k34crux0s5urxtcndupcd37ehkakkz6da8n5ghmx388vfynhqa4k9zmrp8qmyw485ujvpkjwcasqhq5rqpxrkvhm0tg3ap3er8eycgwu5ew5xq5u84vzxsaqgc37ud67g5j9jvynlqacx78zl6l2flw82g02a3z4g5",
        "nav13qq8el3522u4jxd4e8y54du9d5fqlqlcmz8n90k8hc6e72dqky99ajgfarmd3puzx9zz9hazr99zrggharvuh9ulg9ugnu6nf5hfvq9mw03nv2g9xz9v2vnvn6uumrwxcv93ae54kuzjmz49g4mx0u2pzqftvrhu8f",
        "nav1kh6n54xfhq0nmsr8rrqsff8xtegr8hvsdsvn2sdtk3w25w9fkescwqeqlnasm9ngcr895ycxx4ave2m5crya7hgyydhsa66ct995lrvywpgseu8cq4yjwcjm7dkh367pg3dhtxnwsfsct7my5tzu0c8jwsst6luayt",
        "nav15gxjtgw289m82any2fn75gdh09cyte4c6qlzrms7wr4a4vyqdd8epl2qncrhspdflru3kcc4kdpzrrqtcvrq3qzxdjrh3l2lqr9v5jnjw22ut4axj9czcajj8pfyy0mm99n0q8088z99uame7ckrk8k3yvp7dxdw8q",
        "nav1j08knwnjcuukjl88vyt06c2h7unqjurflvtqaa9ljw08mz6swp2je7zg962u5qke9dc3cnhz3rkfdg0uhyw3zw6jk2akd08krzxqms74lcm9paapjygl3kglru3gaumy682qysl2hy6cgujqs9ugfxvqzcza5h00tj",
        "nav15vn8346nl5ttuu28w7dhwetq5vlu8tv3dgdqdhks769ye9gd9ssaszk5unwtejp6vftw82936k20m93sc4z9z29zz4f2rneexfw770ducywzxt3wp6vc7c3lhgxn2jxxufv74hwppcxd3prcn2yf2qgk6sg4u3f74j",
        "nav1kag0sqeuzz64stxmc5ztrafqvyx7lv4k09leasauyku5eg6zdsh23nyauzwrszyqysj02ecqmzkdrdym02w7u5y6ed7ptwe5adqyqufnqfj5hqve2et935gw8p8jculfnr66qpk8u86f35zaxs053920gsyneqtgdc"};

    for (size_t i = 0; i < 10; i++) {
        auto recvAddress = blsct::SubAddress(std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value()));
        BOOST_CHECK(recvAddress.GetString() == expectedAddresses[i]);
    }
}

// Regression test for a bug where GetSubAddressFromPool() derived the
// SubAddressIdentifier's address index by checking `account > -1` instead of
// `nIndex > -1`. For the special negative accounts (CHANGE_ACCOUNT = -1,
// STAKING_ACCOUNT = -2) that guard was always false, so every reservation was
// recorded under address index 0 regardless of the index actually reserved
// from the pool by ReserveSubAddressFromPool() — change/staking subaddresses
// never advanced past index 0.
BOOST_FIXTURE_TEST_CASE(get_subaddress_from_pool_advances_index_for_negative_accounts, TestingSetup)
{
    auto wallet = std::make_unique<wallet::CWallet>(m_node.chain.get(), "", wallet::CreateMockableWalletDatabase());
    wallet->InitWalletFlags(wallet::WALLET_FLAG_BLSCT);

    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_REQUIRE(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));

    for (const int64_t account : {blsct::CHANGE_ACCOUNT, blsct::STAKING_ACCOUNT}) {
        CKeyID keyId1, keyId2;
        blsct::SubAddressIdentifier id1, id2;

        BOOST_REQUIRE(blsct_km->GetSubAddressFromPool(account, keyId1, id1));
        BOOST_REQUIRE(blsct_km->GetSubAddressFromPool(account, keyId2, id2));

        BOOST_CHECK_EQUAL(id1.account, account);
        BOOST_CHECK_EQUAL(id2.account, account);

        // The bug forced both id1.address and id2.address to 0. Fixed
        // behaviour advances the index on each reservation.
        BOOST_CHECK_EQUAL(id1.address, uint64_t{0});
        BOOST_CHECK_EQUAL(id2.address, uint64_t{1});
        BOOST_CHECK(id1.address != id2.address);

        // Distinct indices must also yield distinct keys.
        BOOST_CHECK(keyId1 != keyId2);
    }
}

namespace {
// Set up a BLSCT wallet with a defined view key and a fresh subaddress keypool,
// ready for GetNewDestination()/IsMineMode().
std::unique_ptr<wallet::CWallet> MakeBLSCTWallet(interfaces::Chain* chain)
{
    auto wallet = std::make_unique<wallet::CWallet>(chain, "", wallet::CreateMockableWalletDatabase());
    wallet->InitWalletFlags(wallet::WALLET_FLAG_BLSCT);
    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();
    BOOST_REQUIRE(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));
    return wallet;
}

// Mirror the branch-key derivation used by the createblsctrawtransaction /
// importblsctscript atomic-swap paths: the blinded per-output spending pubkey
// baked into one HTLC branch of the script.
blsct::PublicKey DeriveBranchKey(const blsct::DoublePublicKey& dpk, const MclScalar& blindingKey)
{
    MclG1Point vk, sk;
    BOOST_REQUIRE(dpk.GetViewKey(vk));
    BOOST_REQUIRE(dpk.GetSpendKey(sk));
    auto rV = vk * blindingKey;
    return blsct::PublicKey(sk + blsct::PrivateKey(MclScalar(rV.GetHashWithSalt(0))).GetPoint());
}
} // namespace

// An atomic-swap HTLC output is blinded to a single address (address_a, the
// hashlock/redeem branch). The output is therefore cryptographically
// recognizable by exactly one party's view key: the swap initiator selling nav
// (address_b, the timelock/refund branch) can neither match the viewTag nor
// reconstruct its branch nonce from the output alone, so it is otherwise blind
// to its own refund output. createblsctrawtransaction closes this gap by
// auto-registering the HTLC script as watch-only with address_a's recovery
// nonce when the swap is built. This test reproduces that end state and asserts
// the refund initiator then (a) classifies the output as watch-only and (b)
// recovers the amount — WITHOUT a manual importblsctscript call.
BOOST_FIXTURE_TEST_CASE(htlc_watch_only_registration_detects_refund_output, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);

    auto wallet_a = MakeBLSCTWallet(m_node.chain.get()); // redeem branch (address_a) — output is blinded here
    auto wallet_b = MakeBLSCTWallet(m_node.chain.get()); // refund branch (address_b) — swap initiator
    auto wallet_c = MakeBLSCTWallet(m_node.chain.get()); // unrelated third party

    LOCK(wallet_a->cs_wallet);
    LOCK(wallet_b->cs_wallet);
    LOCK(wallet_c->cs_wallet);
    auto km_a = wallet_a->GetOrCreateBLSCTKeyMan();
    auto km_b = wallet_b->GetOrCreateBLSCTKeyMan();
    auto km_c = wallet_c->GetOrCreateBLSCTKeyMan();

    auto addr_a = std::get<blsct::DoublePublicKey>(km_a->GetNewDestination(0).value());
    auto addr_b = std::get<blsct::DoublePublicKey>(km_b->GetNewDestination(0).value());

    const MclScalar blindingKey(uint256(uint64_t{0x5eed})); // shared, known blinding key
    const std::vector<unsigned char> hash_bytes(32, 0x11);

    auto keyA = DeriveBranchKey(addr_a, blindingKey).GetVch();
    auto keyB = DeriveBranchKey(addr_b, blindingKey).GetVch();
    BOOST_REQUIRE_EQUAL(keyA.size(), blsct::PublicKey::SIZE);
    BOOST_REQUIRE_EQUAL(keyB.size(), blsct::PublicKey::SIZE);

    CScript htlc_script = blsct::BuildHTLCScript(hash_bytes, keyA, keyB, /*locktime=*/100);

    // Build the funding output exactly like the atomic_swap createblsctrawtransaction
    // path: blinded to address_a, HTLC script as scriptPubKey, spendingKey nullified.
    auto unsigned_output = blsct::CreateOutput(std::make_pair(addr_a, htlc_script), 42 * COIN, "swap", TokenId(), blindingKey);
    CTxOut txout = unsigned_output.out;
    txout.blsctData.spendingKey = MclG1Point();

    // Pre-condition: without registration, the refund initiator is blind to the
    // output — it is not the party the output is blinded to. (The redeem party,
    // address_a, still owns its branch subaddress and detects it.)
    BOOST_CHECK_EQUAL(km_b->IsMineMode(txout), wallet::ISMINE_NO);
    BOOST_CHECK_EQUAL(km_a->IsMineMode(txout), wallet::ISMINE_WATCH_ONLY);

    // The recovery nonce createblsctrawtransaction auto-registers for the script:
    // address_a's shared secret, which decrypts the amount for any participant.
    MclG1Point addr_a_view_key;
    BOOST_REQUIRE(addr_a.GetViewKey(addr_a_view_key));
    blsct::PublicKey recovery_nonce(addr_a_view_key * blindingKey);

    // Registering only on wallet_b models auto-registration firing on the
    // initiator's wallet as it builds the swap.
    BOOST_CHECK(km_b->AddWatchOnly(htlc_script, recovery_nonce));

    // Post-condition: the refund initiator now sees its own refund output as
    // watch-only, with no importblsctscript call.
    BOOST_CHECK_EQUAL(km_b->IsMineMode(txout), wallet::ISMINE_WATCH_ONLY);
    BOOST_CHECK(km_b->IsMine(txout));

    // ...and can recover the amount using the registered nonce.
    auto recovered = km_b->RecoverOutputsWithNonce({txout}, recovery_nonce.GetG1Point());
    BOOST_REQUIRE(recovered.is_completed);
    BOOST_REQUIRE(!recovered.amounts.empty());
    BOOST_CHECK_EQUAL(recovered.amounts[0].amount, 42 * COIN);

    // A wallet that never registered the script must not claim the output.
    BOOST_CHECK_EQUAL(km_c->IsMineMode(txout), wallet::ISMINE_NO);
    BOOST_CHECK(!km_c->IsMine(txout));
}

BOOST_AUTO_TEST_SUITE_END()
