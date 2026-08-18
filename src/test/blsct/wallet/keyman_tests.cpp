// Copyright (c) 2023 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/hdchain.h>
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

// A locked encrypted wallet must behave like a watch wallet for incoming BLSCT
// outputs: detection and amount recovery work (view key is stored in the
// clear), while spending-key derivation reports unavailable instead of
// throwing. Regression test for the AddToWallet crash where a bridged output
// arriving while the wallet was locked threw "GetSpendingKey: could not access
// the spend key" out of AppInit() and shut the node down.
BOOST_FIXTURE_TEST_CASE(locked_wallet_spending_key_unavailable_no_throw, TestingSetup)
{
    auto wallet = MakeBLSCTWallet(m_node.chain.get());
    LOCK(wallet->cs_wallet);
    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();

    auto dest = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());
    auto unsigned_output = blsct::CreateOutput(dest, 42 * COIN, "memo");
    const CTxOut& txout = unsigned_output.out;

    BOOST_REQUIRE(blsct_km->IsMine(txout));

    // Unencrypted wallet derives the spending key.
    blsct::PrivateKey key_before;
    BOOST_REQUIRE(blsct_km->GetSpendingKeyForOutput(txout, key_before));
    BOOST_REQUIRE(key_before.IsValid());

    BOOST_REQUIRE(wallet->EncryptWallet("passphrase"));
    BOOST_REQUIRE(wallet->Lock());
    BOOST_REQUIRE(wallet->IsLocked());

    // Locked: detection and amount recovery still work off the view key...
    BOOST_CHECK(blsct_km->IsMine(txout));
    auto recovered = blsct_km->RecoverOutputs({txout});
    BOOST_REQUIRE(recovered.is_completed);
    BOOST_REQUIRE(!recovered.amounts.empty());
    BOOST_CHECK_EQUAL(recovered.amounts[0].amount, 42 * COIN);

    // ...but spending-key derivation reports unavailable rather than throwing.
    blsct::PrivateKey key_locked;
    BOOST_CHECK(!blsct_km->GetSpendingKeyForOutput(txout, key_locked));
    BOOST_CHECK(!blsct_km->GetSpendingKeyForOutputWithCache(txout, key_locked));

    // Unlocked again: derivation recovers and matches the pre-encryption key.
    BOOST_REQUIRE(wallet->Unlock("passphrase"));
    blsct::PrivateKey key_after;
    BOOST_REQUIRE(blsct_km->GetSpendingKeyForOutputWithCache(txout, key_after));
    BOOST_CHECK(key_after.IsValid());
    BOOST_CHECK(key_after.GetScalar() == key_before.GetScalar());
}

// Locks down the one-time key derivation the deriveblsctonetimekey RPC exposes
// for externally constructed destinations (e.g. adaptor-swap outputs locked to
// a combined key that no wallet owns). An output paid to destination (V, S)
// with blinding key b carries ephemeralKey = b*G1 and one-time spending key
// S + H(b*V)*G1; the claimant, holding the view scalar v and the combined
// spend scalar s, must reconstruct the same key material from on-chain data
// alone: nonce = v*ephemeralKey, tweak = H(nonce), private key = s + tweak.
BOOST_FIXTURE_TEST_CASE(external_destination_one_time_key_derivation, TestingSetup)
{
    const MclScalar v(uint256(uint64_t{0x1111}));  // shared view scalar
    const MclScalar s1(uint256(uint64_t{0x2222})); // party 1 spend share
    const MclScalar s2(uint256(uint64_t{0x3333})); // party 2 spend share
    const auto V = blsct::PrivateKey(v).GetPoint();
    const auto S = blsct::PrivateKey(s1).GetPoint() + blsct::PrivateKey(s2).GetPoint();
    const blsct::DoublePublicKey dest(V, S);

    const MclScalar blindingKey(uint256(uint64_t{0x4444})); // sender-side only
    auto unsigned_output = blsct::CreateOutput(dest, 42 * COIN, "", TokenId(), blindingKey);
    const CTxOut& txout = unsigned_output.out;

    // Claimant side: everything below uses only (v, s1+s2) and on-chain data.
    const MclG1Point nonce = txout.blsctData.ephemeralKey * v;
    const MclScalar tweak(nonce.GetHashWithSalt(0));

    // tweak_point lets a claimant verify the output key by point addition.
    BOOST_CHECK(txout.blsctData.spendingKey == S + blsct::PrivateKey(tweak).GetPoint());

    // The full one-time private key signs for the output's spending key.
    const MclScalar one_time = s1 + s2 + tweak;
    BOOST_CHECK(blsct::PrivateKey(one_time).GetPoint() == txout.blsctData.spendingKey);

    // The view tag computed from the reconstructed nonce matches the output.
    HashWriter hasher{};
    hasher << nonce;
    BOOST_CHECK_EQUAL(hasher.GetHash().GetUint64(0) & 0xFFFF, txout.blsctData.viewTag);

    // The same nonce opens the range proof (amount recovery path).
    auto wallet = MakeBLSCTWallet(m_node.chain.get());
    LOCK(wallet->cs_wallet);
    auto km = wallet->GetOrCreateBLSCTKeyMan();
    auto recovered = km->RecoverOutputsWithNonce({txout}, nonce);
    BOOST_REQUIRE(recovered.is_completed);
    BOOST_REQUIRE(!recovered.amounts.empty());
    BOOST_CHECK_EQUAL(recovered.amounts[0].amount, 42 * COIN);
}

// A chain read back out of the wallet database has to equal the one that was
// written, so equality may only look at fields SERIALIZE_METHODS writes.
BOOST_FIXTURE_TEST_CASE(hdchain_survives_a_serialization_round_trip, BasicTestingSetup)
{
    const auto key_id = [](uint8_t byte) {
        const std::vector<unsigned char> bytes(uint160::size(), byte);
        return CKeyID(uint160(bytes));
    };

    blsct::HDChain chain;
    chain.seed_id = key_id(1);
    chain.spend_id = key_id(2);
    chain.view_id = key_id(3);
    chain.blinding_id = key_id(4);
    chain.token_id = key_id(5);
    chain.nSubAddressCounter[0] = 7;

    DataStream st{};
    st << chain;

    blsct::HDChain reloaded;
    st >> reloaded;

    BOOST_CHECK(chain == reloaded);
}

BOOST_AUTO_TEST_SUITE_END()
