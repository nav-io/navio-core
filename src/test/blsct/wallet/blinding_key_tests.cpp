// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/blinding_key.h>
#include <blsct/wallet/txfactory.h>
#include <blsct/wallet/verification.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <txdb.h>
#include <util/strencodings.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(blsct_blinding_key_tests)

namespace {

std::vector<unsigned char> RepeatedByte(unsigned char b)
{
    return std::vector<unsigned char>(32, b);
}

Outid OutidOfRepeatedByte(unsigned char b)
{
    uint256 h;
    std::fill(h.begin(), h.end(), b);
    return Outid::FromUint256(h);
}

//! A wallet with a BLSCT key manager seeded from `entropy`. Restoring the same
//! entropy into a second wallet is what a mnemonic-only restore amounts to as
//! far as blinding-key derivation is concerned.
struct SeededWallet {
    std::unique_ptr<wallet::CWallet> wallet;
    blsct::KeyMan* km{nullptr};
};

SeededWallet MakeWallet(interfaces::Chain* chain, const std::vector<unsigned char>& entropy)
{
    SeededWallet w;
    w.wallet = std::make_unique<wallet::CWallet>(chain, "", wallet::CreateMockableWalletDatabase());
    w.wallet->InitWalletFlags(wallet::WALLET_FLAG_BLSCT);
    LOCK(w.wallet->cs_wallet);
    w.km = w.wallet->GetOrCreateBLSCTKeyMan();
    BOOST_REQUIRE(w.km->SetupGeneration(entropy, blsct::IMPORT_MNEMONIC, true));
    return w;
}

} // namespace

// The normative vector from the shared specification
// (navio-hl-bridge docs/BLINDING-KEY-RECOVERY.md). navio-sdk tests the same
// two values. It pins the exact byte layout of the hashed material -- domain
// separator, seed, outid, big-endian counter, 91 bytes and nothing else -- and
// it is the only thing standing between the two implementations and a silent
// divergence that would surface years later as unrecoverable outputs.
//
// Both expected scalars happen to be below the group order, so the reduction
// is the identity here and this tests the layout rather than the reduction;
// the reduction is covered separately below.
BOOST_AUTO_TEST_CASE(normative_test_vector)
{
    const auto seed = RepeatedByte(0x01);
    const Outid outid = OutidOfRepeatedByte(0xab);

    BOOST_CHECK_EQUAL(blsct::BLINDING_KEY_DOMAIN.size(), 23U);
    BOOST_CHECK_EQUAL(blsct::BLINDING_KEY_MATERIAL_SIZE, 91U);

    BOOST_CHECK_EQUAL(
        HexStr(blsct::DeriveBlindingKey(seed, outid, 0).GetVch()),
        "6f57f45d6d6ceb748b859f3f7b16b08ee720cc91f947aab1ba4b3d825a5cb281");
    BOOST_CHECK_EQUAL(
        HexStr(blsct::DeriveBlindingKey(seed, outid, 1).GetVch()),
        "41d3910421dc8f3b19079bdd9d9f8769e3ed691fabe978dc6dd2aa0f4448e2c1");
}

// The scalar is the sha256 digest read big-endian and reduced mod the group
// order r. The normative vector cannot exercise that reduction (both of its
// digests are already below r), so check the wrap-around directly on the
// scalar type the derivation builds its result with.
BOOST_AUTO_TEST_CASE(modular_reduction)
{
    // 2^256 - 1, the largest 32-byte input, reduced mod r.
    BOOST_CHECK_EQUAL(
        HexStr(BlstScalar(std::vector<uint8_t>(32, 0xff)).GetVch()),
        "1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffd");

    // r itself reduces to zero, and r + 5 to 5.
    const auto r = ParseHex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
    const auto r_plus_5 = ParseHex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000006");
    BOOST_CHECK(BlstScalar(r).IsZero());
    BOOST_CHECK_EQUAL(
        HexStr(BlstScalar(r_plus_5).GetVch()),
        "0000000000000000000000000000000000000000000000000000000000000005");
}

BOOST_AUTO_TEST_CASE(derivation_is_deterministic_and_separated)
{
    const auto seed = RepeatedByte(0x07);
    const auto other_seed = RepeatedByte(0x08);
    const Outid outid = OutidOfRepeatedByte(0x11);
    const Outid other_outid = OutidOfRepeatedByte(0x12);

    const auto k = blsct::DeriveBlindingKey(seed, outid, 3);

    // Same inputs, same scalar -- every time.
    BOOST_CHECK(blsct::DeriveBlindingKey(seed, outid, 3) == k);
    BOOST_CHECK(blsct::DeriveBlindingKey(seed, outid, 3) == k);

    // Each of the three components separates the derivation.
    BOOST_CHECK(blsct::DeriveBlindingKey(seed, outid, 4) != k);
    BOOST_CHECK(blsct::DeriveBlindingKey(seed, other_outid, 3) != k);
    BOOST_CHECK(blsct::DeriveBlindingKey(other_seed, outid, 3) != k);

    // A seed of the wrong length is a programming error and fails loudly
    // rather than hashing something shorter into a valid-looking scalar. This
    // is the same "fail loudly" posture the (untestable, ~2^-255) zero-scalar
    // case gets inside DeriveBlindingKey.
    BOOST_CHECK_THROW(blsct::DeriveBlindingKey(std::vector<unsigned char>(31, 0x01), outid, 0), std::runtime_error);
    BOOST_CHECK_THROW(blsct::DeriveBlindingKey(std::vector<unsigned char>{}, outid, 0), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(recovery_matches_only_the_right_seed)
{
    const auto seed = RepeatedByte(0x21);
    const auto wrong_seed = RepeatedByte(0x22);
    const Outid outid = OutidOfRepeatedByte(0x33);

    std::vector<CTxIn> vin{CTxIn(COutPoint(outid))};

    const auto k = blsct::DeriveBlindingKey(seed, outid, 2);
    const BlstG1Point P = blsct::PrivateKey(k).GetPoint();

    const auto recovered = blsct::RecoverBlindingKey(seed, vin, P);
    BOOST_REQUIRE(recovered.has_value());
    BOOST_CHECK(*recovered == k);

    // A different seed never matches: the check is against the public point,
    // so a match is proof and a non-match is a clean refusal.
    BOOST_CHECK(!blsct::RecoverBlindingKey(wrong_seed, vin, P).has_value());

    // Neither does an unrelated input set.
    std::vector<CTxIn> other_vin{CTxIn(COutPoint(OutidOfRepeatedByte(0x34)))};
    BOOST_CHECK(!blsct::RecoverBlindingKey(seed, other_vin, P).has_value());

    // An ordinal past the search bound is out of reach by design; document
    // the bound by testing it.
    const auto beyond = blsct::DeriveBlindingKey(seed, outid, blsct::MAX_OUTPUT_SEARCH);
    BOOST_CHECK(!blsct::RecoverBlindingKey(seed, vin, blsct::PrivateKey(beyond).GetPoint()).has_value());
}

// The anchor input is not identifiable by position at recovery time -- BuildTx
// shuffles vin, and block aggregation merges every transaction's inputs into
// one vin -- so recovery tries them all. Put the real anchor last behind a
// crowd of strangers and it must still be found.
BOOST_AUTO_TEST_CASE(recovery_finds_a_non_leading_anchor)
{
    const auto seed = RepeatedByte(0x41);
    const Outid anchor = OutidOfRepeatedByte(0x55);

    std::vector<CTxIn> vin;
    for (unsigned char b = 0x60; b < 0x68; ++b) vin.emplace_back(COutPoint(OutidOfRepeatedByte(b)));
    vin.emplace_back(COutPoint(anchor));

    const auto k = blsct::DeriveBlindingKey(seed, anchor, 5);
    const auto recovered = blsct::RecoverBlindingKey(seed, vin, blsct::PrivateKey(k).GetPoint());
    BOOST_REQUIRE(recovered.has_value());
    BOOST_CHECK(*recovered == k);
}

namespace {

//! Fund `factory` with one coin and build a transaction paying `amount` to
//! `dest`. Mirrors blsct_txfactory_tests' createtransaction_test.
struct BuiltFixture {
    CCoinsViewDB base;
    Coin coin;
    COutPoint outpoint;
};

} // namespace

// The end-to-end property the whole feature exists for: a wallet that has been
// thrown away and rebuilt from its seed alone can still recover the blinding
// scalar of an output it created, produce a signature with it, and have that
// signature verify against the point on chain.
//
// It also covers the aggregation case in the same pass: the built transaction
// is folded into a larger synthetic one whose vin and vout carry a stranger's
// entries first, which is exactly what a block's merged transaction looks like
// to the sender afterwards.
BOOST_FIXTURE_TEST_CASE(recovery_after_seed_only_restore, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 23, .memory_only = true}, {}};

    const std::vector<unsigned char> entropy(32, 0x5a);

    auto sender = MakeWallet(m_node.chain.get(), entropy);
    LOCK(sender.wallet->cs_wallet);

    auto recvAddress = std::get<blsct::DoublePublicKey>(sender.km->GetNewDestination(0).value());

    const auto coin_txid = Txid::FromUint256(InsecureRand256());
    COutPoint outpoint{coin_txid};

    Coin coin;
    auto funding = blsct::CreateOutput(recvAddress, 1000 * COIN, "funding");
    coin.nHeight = 1;
    coin.out = funding.out;

    {
        CCoinsViewCache cache{&base, /*deterministic=*/true};
        cache.SetBestBlock(InsecureRand256());
        cache.AddCoin(outpoint, std::move(coin), true);
        BOOST_REQUIRE(cache.Flush());
    }
    CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};

    auto factory = blsct::TxFactory(sender.km);
    BOOST_REQUIRE(factory.AddInput(coins_view_cache, outpoint));
    factory.AddOutput(recvAddress, 900 * COIN, "payment");

    auto built = factory.BuildTx();
    BOOST_REQUIRE(built.has_value());

    TxValidationState tx_state;
    BOOST_CHECK(blsct::VerifyTx(CTransaction(built->tx), coins_view_cache, tx_state));

    // Every BLSCT output the factory produced reports its blinding scalar, and
    // each one really is the discrete log of the output's ephemeral key.
    size_t blsct_outputs = 0;
    for (const auto& out : built->tx.vout) {
        if (!out.HasBLSCTKeys()) continue;
        ++blsct_outputs;
        auto it = built->blindingKeys.find(out.GetHash());
        BOOST_REQUIRE(it != built->blindingKeys.end());
        BOOST_CHECK(blsct::PrivateKey(it->second).GetPoint() == out.blsctData.ephemeralKey);
    }
    // Recipient plus change.
    BOOST_CHECK_GE(blsct_outputs, 2U);

    // Now throw the wallet away and rebuild it from the seed alone.
    auto restored = MakeWallet(m_node.chain.get(), entropy);
    LOCK(restored.wallet->cs_wallet);

    // ... and give the transaction the shape a block leaves it in: aggregated
    // with a stranger's transaction, so both the output index and the position
    // of the anchor input have moved.
    CMutableTransaction aggregated;
    aggregated.vin.emplace_back(COutPoint(OutidOfRepeatedByte(0xee)));
    aggregated.vin.insert(aggregated.vin.end(), built->tx.vin.begin(), built->tx.vin.end());
    aggregated.vout.push_back(CTxOut(1, CScript(OP_RETURN)));
    aggregated.vout.insert(aggregated.vout.end(), built->tx.vout.begin(), built->tx.vout.end());
    std::reverse(aggregated.vout.begin(), aggregated.vout.end());

    size_t recovered_count = 0;
    for (const auto& out : aggregated.vout) {
        if (!out.HasBLSCTKeys()) continue;
        const auto recovered = restored.km->RecoverOutputBlindingKey(aggregated.vin, out);
        BOOST_REQUIRE(recovered.has_value());
        ++recovered_count;

        // Same scalar the builder used.
        BOOST_CHECK(*recovered == built->blindingKeys.at(out.GetHash()));

        // And a signature under it verifies against the point on chain, with
        // the message signed exactly as given.
        const std::string message{"navio-hl-refund/v1|test|0|note"};
        const blsct::Message msg(message.begin(), message.end());
        const auto sig = blsct::PrivateKey(*recovered).Sign(msg);
        const blsct::PublicKey pk{out.blsctData.ephemeralKey};
        BOOST_CHECK(pk.Verify(msg, sig));

        // A different message does not verify under the same signature.
        const std::string other{"navio-hl-refund/v1|test|0|other"};
        BOOST_CHECK(!pk.Verify(blsct::Message(other.begin(), other.end()), sig));
    }
    BOOST_CHECK_EQUAL(recovered_count, blsct_outputs);

    // A wallet built from a different seed refuses every one of them: the
    // match is against the on-chain point, so "not ours" is a clean no.
    auto stranger = MakeWallet(m_node.chain.get(), std::vector<unsigned char>(32, 0x5b));
    LOCK(stranger.wallet->cs_wallet);
    for (const auto& out : aggregated.vout) {
        if (!out.HasBLSCTKeys()) continue;
        BOOST_CHECK(!stranger.km->RecoverOutputBlindingKey(aggregated.vin, out).has_value());
    }

    // The fee output carries no BLSCT keys, so there is nothing to recover.
    for (const auto& out : aggregated.vout) {
        if (out.HasBLSCTKeys()) continue;
        BOOST_CHECK(!restored.km->RecoverOutputBlindingKey(aggregated.vin, out).has_value());
    }
}

// An explicitly supplied blinding key is the documented opt-out: the factory
// must use it verbatim rather than deriving, and such an output is then NOT
// recoverable -- which is also what every pre-existing output looks like.
BOOST_FIXTURE_TEST_CASE(explicit_blinding_key_opts_out_of_recovery, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 23, .memory_only = true}, {}};

    const std::vector<unsigned char> entropy(32, 0x7c);
    auto sender = MakeWallet(m_node.chain.get(), entropy);
    LOCK(sender.wallet->cs_wallet);

    auto recvAddress = std::get<blsct::DoublePublicKey>(sender.km->GetNewDestination(0).value());

    const auto coin_txid = Txid::FromUint256(InsecureRand256());
    COutPoint outpoint{coin_txid};
    Coin coin;
    coin.nHeight = 1;
    coin.out = blsct::CreateOutput(recvAddress, 1000 * COIN, "funding").out;
    {
        CCoinsViewCache cache{&base, /*deterministic=*/true};
        cache.SetBestBlock(InsecureRand256());
        cache.AddCoin(outpoint, std::move(coin), true);
        BOOST_REQUIRE(cache.Flush());
    }
    CCoinsViewCache coins_view_cache{&base, /*deterministic=*/true};

    const BlstScalar pinned = BlstScalar::Rand();

    auto factory = blsct::TxFactory(sender.km);
    BOOST_REQUIRE(factory.AddInput(coins_view_cache, outpoint));
    factory.AddOutput(recvAddress, 900 * COIN, "payment", TokenId(), blsct::NORMAL, 0,
                      /*fSubtractFeeFromAmount=*/false, pinned);

    auto built = factory.BuildTx();
    BOOST_REQUIRE(built.has_value());

    const BlstG1Point pinnedPoint = blsct::PrivateKey(pinned).GetPoint();
    bool found_pinned = false;
    for (const auto& out : built->tx.vout) {
        if (!out.HasBLSCTKeys()) continue;
        if (out.blsctData.ephemeralKey != pinnedPoint) continue;
        found_pinned = true;
        // Random and never derived from the seed, so recovery cannot find it.
        BOOST_CHECK(!sender.km->RecoverOutputBlindingKey(built->tx.vin, out).has_value());
    }
    BOOST_CHECK(found_pinned);

    // The change output, which the factory chose the key for, is still
    // recoverable: the opt-out is per-output.
    bool found_recoverable = false;
    for (const auto& out : built->tx.vout) {
        if (!out.HasBLSCTKeys()) continue;
        if (out.blsctData.ephemeralKey == pinnedPoint) continue;
        if (sender.km->RecoverOutputBlindingKey(built->tx.vin, out).has_value()) found_recoverable = true;
    }
    BOOST_CHECK(found_recoverable);
}

BOOST_AUTO_TEST_SUITE_END()
