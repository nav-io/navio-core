// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/blinding_key.h>
#include <blsct/wallet/txfactory.h>
#include <blsct/wallet/verification.h>
#include <crypto/sha256.h>
#include <test/util/logging.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <txdb.h>
#include <util/strencodings.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <atomic>
#include <optional>
#include <set>
#include <thread>
#include <vector>
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
// separator, seed, outid, big-endian ordinal, big-endian generation, 95 bytes
// and nothing else -- and
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
    BOOST_CHECK_EQUAL(blsct::BLINDING_KEY_MATERIAL_SIZE, 95U);

    BOOST_CHECK_EQUAL(
        HexStr(blsct::DeriveBlindingKey(seed, outid, 0, /*generation=*/0).GetVch()),
        "70ea97ae2ad8845dcf73f86bd510dc7aa4cd3e6cbeddf71e5101708866a074fa");
    BOOST_CHECK_EQUAL(
        HexStr(blsct::DeriveBlindingKey(seed, outid, 1, /*generation=*/0).GetVch()),
        "4b385dd6567923dab38680aa9120ed854bfc58a4d502f7a9113741c0aa4f6b91");
    // The generation is part of the preimage, not an afterthought appended to
    // a hash: a different generation is a different derivation.
    BOOST_CHECK_EQUAL(
        HexStr(blsct::DeriveBlindingKey(seed, outid, 0, /*generation=*/1).GetVch()),
        "63fd46abd3afbc6a1454d278fe175a1cbe186853ae3dc98c411d7a18116151ff");
}

// The reason the generation exists. k seeds `nonce = vk * k`, from which the
// range proof takes gamma and every blinding scalar, so deriving the same k
// for two DIFFERENT amounts reuses the prover's entire randomness and leaks
// the committed values. The derivation is otherwise a pure function of
// (seed, anchor, ordinal), and a wallet that rebuilds over the same inputs --
// abandon or evict and resend, coin selection being deterministic -- hits
// exactly that. The generation is what makes the second build differ.
BOOST_AUTO_TEST_CASE(generation_separates_rebuilds_of_one_anchor)
{
    const auto seed = RepeatedByte(0x21);
    const Outid anchor = OutidOfRepeatedByte(0x22);

    // Same anchor and ordinal, successive generations: all distinct.
    std::set<std::string> seen;
    for (uint32_t generation = 0; generation < blsct::MAX_GENERATION_SEARCH; ++generation) {
        const auto k = blsct::DeriveBlindingKey(seed, anchor, /*ordinal=*/0, generation);
        BOOST_CHECK_MESSAGE(seen.insert(HexStr(k.GetVch())).second,
                            "generation " << generation << " repeated an earlier scalar");
    }
    BOOST_CHECK_EQUAL(seen.size(), blsct::MAX_GENERATION_SEARCH);

    // And the generation does not merely permute the ordinals: (ordinal 1,
    // generation 0) and (ordinal 0, generation 1) are different derivations.
    BOOST_CHECK(blsct::DeriveBlindingKey(seed, anchor, 1, 0) !=
                blsct::DeriveBlindingKey(seed, anchor, 0, 1));
}

// Recovery has no access to the builder's counter after a seed-only restore,
// so it searches. Every generation inside the bound is found; the first one
// beyond it is not, which is the documented cost of the bound rather than a
// wrong key -- a miss, never a false match.
BOOST_AUTO_TEST_CASE(recovery_searches_generations)
{
    const auto seed = RepeatedByte(0x31);
    const Outid anchor = OutidOfRepeatedByte(0x32);

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint(anchor));

    for (const uint32_t generation : {0u, 1u, 7u, blsct::MAX_GENERATION_SEARCH - 1}) {
        const auto k = blsct::DeriveBlindingKey(seed, anchor, /*ordinal=*/2, generation);
        const auto recovered = blsct::RecoverBlindingKey(seed, tx.vin, blsct::PrivateKey(k).GetPoint(), anchor);
        BOOST_REQUIRE_MESSAGE(recovered.has_value(), "generation " << generation << " was not recovered");
        BOOST_CHECK(*recovered == k);
    }

    const auto beyond = blsct::DeriveBlindingKey(seed, anchor, 2, blsct::MAX_GENERATION_SEARCH);
    BOOST_CHECK(!blsct::RecoverBlindingKey(seed, tx.vin, blsct::PrivateKey(beyond).GetPoint(), anchor).has_value());
}

// signblsctoutput signs this digest, never the caller's bytes. The layout is
// normative and shared with navio-sdk, so it is pinned the same way the
// derivation is.
BOOST_AUTO_TEST_CASE(output_auth_digest_vector)
{
    BOOST_CHECK_EQUAL(blsct::OUTPUT_AUTH_DOMAIN.size(), 26U);

    // Single sha256 over the domain followed by the raw message bytes -- the
    // same construction the key derivation uses, not Bitcoin's sha256d.
    const auto sha256_of = [](const std::string& in) {
        uint256 out;
        CSHA256().Write(reinterpret_cast<const unsigned char*>(in.data()), in.size()).Finalize(out.begin());
        return out;
    };
    const std::string domain{blsct::OUTPUT_AUTH_DOMAIN};
    BOOST_CHECK_EQUAL(blsct::OutputAuthDigest("").GetHex(), sha256_of(domain).GetHex());
    BOOST_CHECK_EQUAL(blsct::OutputAuthDigest("navio-hl-refund/v1|abc|0|note").GetHex(),
                      sha256_of(domain + "navio-hl-refund/v1|abc|0|note").GetHex());

    // Distinct messages give distinct digests, and the domain is really part
    // of the preimage: a message that spells the domain out itself does not
    // collide with the empty message.
    BOOST_CHECK(blsct::OutputAuthDigest("a") != blsct::OutputAuthDigest("b"));
    BOOST_CHECK(blsct::OutputAuthDigest(std::string{blsct::OUTPUT_AUTH_DOMAIN}) !=
                blsct::OutputAuthDigest(""));
}

// The reason the digest exists: consensus verifies a signature under an
// output's ephemeralKey -- the same point signblsctoutput signs with -- over
// that output's 32-byte hash. If the RPC signed caller-chosen bytes, a caller
// could pass an out_hash as the "message" and get a consensus-valid output
// signature back. Hashing means the signed value is always a sha256 output, so
// hitting a chosen out_hash needs a preimage.
BOOST_AUTO_TEST_CASE(output_auth_digest_is_not_a_chosen_hash)
{
    const uint256 target = OutidOfRepeatedByte(0xcd).ToUint256();

    // The obvious oracle attempt: hand the RPC the 32 raw bytes of the hash it
    // wants signed. What gets signed is not those bytes.
    const std::string as_message(reinterpret_cast<const char*>(target.begin()), target.size());
    BOOST_CHECK(blsct::OutputAuthDigest(as_message) != target);

    // And the digest is 32 bytes, so it is the same shape as an out_hash --
    // the separation is preimage resistance, not a length mismatch.
    BOOST_CHECK_EQUAL(blsct::OutputAuthDigest(as_message).size(), target.size());
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

    const auto k = blsct::DeriveBlindingKey(seed, outid, 3, /*generation=*/0);

    // Same inputs, same scalar -- every time.
    BOOST_CHECK(blsct::DeriveBlindingKey(seed, outid, 3, /*generation=*/0) == k);
    BOOST_CHECK(blsct::DeriveBlindingKey(seed, outid, 3, /*generation=*/0) == k);

    // Each of the three components separates the derivation.
    BOOST_CHECK(blsct::DeriveBlindingKey(seed, outid, 4, /*generation=*/0) != k);
    BOOST_CHECK(blsct::DeriveBlindingKey(seed, other_outid, 3, /*generation=*/0) != k);
    BOOST_CHECK(blsct::DeriveBlindingKey(other_seed, outid, 3, /*generation=*/0) != k);

    // A seed of the wrong length is a programming error and fails loudly
    // rather than hashing something shorter into a valid-looking scalar. This
    // is the same "fail loudly" posture the (untestable, ~2^-255) zero-scalar
    // case gets inside DeriveBlindingKey.
    BOOST_CHECK_THROW(blsct::DeriveBlindingKey(std::vector<unsigned char>(31, 0x01), outid, 0, /*generation=*/0), std::runtime_error);
    BOOST_CHECK_THROW(blsct::DeriveBlindingKey(std::vector<unsigned char>{}, outid, 0, /*generation=*/0), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(recovery_matches_only_the_right_seed)
{
    const auto seed = RepeatedByte(0x21);
    const auto wrong_seed = RepeatedByte(0x22);
    const Outid outid = OutidOfRepeatedByte(0x33);

    std::vector<CTxIn> vin{CTxIn(COutPoint(outid))};

    const auto k = blsct::DeriveBlindingKey(seed, outid, 2, /*generation=*/0);
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
    const auto beyond = blsct::DeriveBlindingKey(seed, outid, blsct::MAX_OUTPUT_SEARCH, /*generation=*/0);
    BOOST_CHECK(!blsct::RecoverBlindingKey(seed, vin, blsct::PrivateKey(beyond).GetPoint()).has_value());
}

// The anchor is the lexicographically smallest outid of the sender's own
// inputs, comparing the 32 bytes in INTERNAL order -- not the reversed order
// GetHex() displays, and not any position, since BuildTx shuffles vin and
// aggregation splices in strangers' inputs.
BOOST_AUTO_TEST_CASE(canonical_anchor_is_order_independent)
{
    const Outid low = OutidOfRepeatedByte(0x02);
    const Outid mid = OutidOfRepeatedByte(0x77);
    const Outid high = OutidOfRepeatedByte(0xfe);

    const std::vector<COutPoint> ascending{COutPoint(low), COutPoint(mid), COutPoint(high)};
    const std::vector<COutPoint> descending{COutPoint(high), COutPoint(mid), COutPoint(low)};
    const std::vector<COutPoint> jumbled{COutPoint(mid), COutPoint(high), COutPoint(low)};

    for (const auto& set : {ascending, descending, jumbled}) {
        const auto anchor = blsct::CanonicalAnchor(set);
        BOOST_REQUIRE(anchor.has_value());
        BOOST_CHECK(anchor->ToUint256() == low.ToUint256());
    }

    // Empty set, no anchor.
    BOOST_CHECK(!blsct::CanonicalAnchor({}).has_value());

    // Internal order, not display order. These two differ in the first and
    // last internal byte, so the two orderings disagree about which is
    // smaller; the internal one must win.
    uint256 a_bytes, b_bytes;
    std::fill(a_bytes.begin(), a_bytes.end(), 0x40);
    std::fill(b_bytes.begin(), b_bytes.end(), 0x40);
    a_bytes.begin()[0] = 0x01;  // smaller internally, and internally FIRST
    b_bytes.begin()[31] = 0x00; // smaller in display order (reversed -> leads)
    const auto anchor = blsct::CanonicalAnchor(
        {COutPoint(Outid::FromUint256(a_bytes)), COutPoint(Outid::FromUint256(b_bytes))});
    BOOST_REQUIRE(anchor.has_value());
    BOOST_CHECK(anchor->ToUint256() == a_bytes);
}

// The canonical anchor is the fast path, but the scan over every input is the
// fallback that must stay: a caller that cannot say which inputs are its own
// (a partial rescan, say) still recovers, just more slowly. Put the real
// anchor last behind a crowd of strangers, give no canonical hint, and it must
// still be found.
BOOST_AUTO_TEST_CASE(recovery_finds_a_non_leading_anchor)
{
    const auto seed = RepeatedByte(0x41);
    const Outid anchor = OutidOfRepeatedByte(0x55);

    std::vector<CTxIn> vin;
    for (unsigned char b = 0x60; b < 0x68; ++b) vin.emplace_back(COutPoint(OutidOfRepeatedByte(b)));
    vin.emplace_back(COutPoint(anchor));

    const auto k = blsct::DeriveBlindingKey(seed, anchor, 5, /*generation=*/0);
    const BlstG1Point P = blsct::PrivateKey(k).GetPoint();

    // No hint: the fallback scan finds it.
    const auto recovered = blsct::RecoverBlindingKey(seed, vin, P);
    BOOST_REQUIRE(recovered.has_value());
    BOOST_CHECK(*recovered == k);

    // Correct hint: same answer, reached on the fast path.
    const auto hinted = blsct::RecoverBlindingKey(seed, vin, P, anchor);
    BOOST_REQUIRE(hinted.has_value());
    BOOST_CHECK(*hinted == k);

    // WRONG hint: must not break recovery. This is the whole reason the
    // fallback is kept -- a bad anchor costs time and nothing else, because
    // the match is against P.
    const auto misled = blsct::RecoverBlindingKey(seed, vin, P, OutidOfRepeatedByte(0x99));
    BOOST_REQUIRE(misled.has_value());
    BOOST_CHECK(*misled == k);

    // A hint for an input that is not in vin at all, and whose ordinals do not
    // match either, still ends in a clean refusal rather than a false key.
    const auto other = blsct::DeriveBlindingKey(seed, OutidOfRepeatedByte(0x7f), 0, /*generation=*/0);
    BOOST_CHECK(!blsct::RecoverBlindingKey(seed, vin, blsct::PrivateKey(other).GetPoint(), anchor).has_value());
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

    // The builder keyed every one of them on the CANONICAL anchor: the
    // smallest outid among the inputs the transaction actually spends. Check
    // it directly against the derivation rather than trusting the search --
    // the search would also succeed on a non-canonical anchor via its
    // fallback, so only this pins the rule the two implementations share.
    {
        std::vector<COutPoint> own;
        for (const auto& in : built->tx.vin) own.push_back(in.prevout);
        const auto canonical = blsct::CanonicalAnchor(own);
        BOOST_REQUIRE(canonical.has_value());

        const auto seed = sender.km->GetBlindingSeed();
        BOOST_REQUIRE(seed.has_value());

        for (const auto& [output_hash, k] : built->blindingKeys) {
            bool matched = false;
            for (uint32_t counter = 0; counter < blsct::MAX_OUTPUT_SEARCH && !matched; ++counter) {
                if (blsct::DeriveBlindingKey(*seed, *canonical, counter, /*generation=*/0) == k) matched = true;
            }
            BOOST_CHECK_MESSAGE(matched, "output " + output_hash.ToString() + " was not derived from the canonical anchor");
        }
    }

    // Now throw the wallet away and rebuild it from the seed alone.
    auto restored = MakeWallet(m_node.chain.get(), entropy);
    LOCK(restored.wallet->cs_wallet);

    // ... and give the transaction the shape a block leaves it in: aggregated
    // with a stranger's transaction, so both the output index and the position
    // of the anchor input have moved.
    CMutableTransaction aggregated;
    aggregated.vin.emplace_back(COutPoint(OutidOfRepeatedByte(0xee)));
    aggregated.vin.insert(aggregated.vin.end(), built->tx.vin.begin(), built->tx.vin.end());
    aggregated.vout.emplace_back(1, CScript(OP_RETURN));
    aggregated.vout.insert(aggregated.vout.end(), built->tx.vout.begin(), built->tx.vout.end());
    std::reverse(aggregated.vout.begin(), aggregated.vout.end());

    size_t recovered_count = 0;
    for (const auto& out : aggregated.vout) {
        if (!out.HasBLSCTKeys()) continue;
        // No own-input hint: the fallback scan has to cope with a
        // stranger's input sitting at index 0.
        const auto recovered = restored.km->RecoverOutputBlindingKey(aggregated.vin, out);
        BOOST_REQUIRE(recovered.has_value());
        ++recovered_count;

        // With the own-input set -- what the RPC passes -- the canonical
        // anchor takes the fast path to the same scalar.
        std::vector<COutPoint> own;
        for (const auto& in : built->tx.vin) own.push_back(in.prevout);
        const auto fast = restored.km->RecoverOutputBlindingKey(aggregated.vin, out, own);
        BOOST_REQUIRE(fast.has_value());
        BOOST_CHECK(*fast == *recovered);

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

// The wallet-level half of the rebuild defence: the counter the derivation is
// keyed on is claimed once per build, never repeats for an anchor, and is
// independent per anchor.
BOOST_FIXTURE_TEST_CASE(blinding_generation_is_claimed_once_and_never_repeats, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    auto w = MakeWallet(m_node.chain.get(), std::vector<unsigned char>(32, 0x41));
    LOCK(w.wallet->cs_wallet);

    const Outid anchor = OutidOfRepeatedByte(0x42);
    const Outid other = OutidOfRepeatedByte(0x43);

    // Successive claims on one anchor hand out successive generations. This is
    // what makes an abandon-and-resend over the same inputs derive a different
    // scalar instead of reusing the first build's.
    std::set<uint32_t> claimed;
    for (int i = 0; i < 8; ++i) {
        const auto generation = w.km->ReserveBlindingGeneration(anchor);
        BOOST_REQUIRE(generation.has_value());
        BOOST_CHECK_MESSAGE(claimed.insert(*generation).second,
                            "generation " << *generation << " was handed out twice");
    }
    BOOST_CHECK_EQUAL(claimed.size(), 8U);
    BOOST_CHECK_EQUAL(*claimed.begin(), 0U);

    // Anchors are counted independently: a fresh input set starts at 0 rather
    // than inheriting another anchor's count.
    const auto first_other = w.km->ReserveBlindingGeneration(other);
    BOOST_REQUIRE(first_other.has_value());
    BOOST_CHECK_EQUAL(*first_other, 0U);

    // And the scalars those generations produce really are distinct, which is
    // the property the whole mechanism exists for.
    const auto seed = w.km->GetBlindingSeed();
    BOOST_REQUIRE(seed.has_value());
    std::set<std::string> scalars;
    for (const uint32_t generation : claimed) {
        scalars.insert(HexStr(blsct::DeriveBlindingKey(*seed, anchor, /*ordinal=*/0, generation).GetVch()));
    }
    BOOST_CHECK_EQUAL(scalars.size(), claimed.size());
}

// Recovery only searches generations below MAX_GENERATION_SEARCH, so once an
// anchor has used them all the counter must stop handing out derived
// generations: the caller then falls back to a random key, which is exactly
// as unrecoverable but no longer pretends otherwise.
BOOST_FIXTURE_TEST_CASE(blinding_generation_stops_at_search_bound, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    auto w = MakeWallet(m_node.chain.get(), std::vector<unsigned char>(32, 0x41));
    LOCK(w.wallet->cs_wallet);

    const Outid anchor = OutidOfRepeatedByte(0x44);
    for (uint32_t i = 0; i < blsct::MAX_GENERATION_SEARCH; ++i) {
        const auto generation = w.km->ReserveBlindingGeneration(anchor);
        BOOST_REQUIRE(generation.has_value());
        BOOST_CHECK_EQUAL(*generation, i);
    }

    // Every generation recovery can find is spent; further claims fail, and
    // keep failing rather than wrapping round to a generation already used.
    BOOST_CHECK(!w.km->ReserveBlindingGeneration(anchor).has_value());
    BOOST_CHECK(!w.km->ReserveBlindingGeneration(anchor).has_value());

    // The bound is per anchor.
    const auto other = w.km->ReserveBlindingGeneration(OutidOfRepeatedByte(0x45));
    BOOST_REQUIRE(other.has_value());
    BOOST_CHECK_EQUAL(*other, 0U);
}

// The claim is a read-modify-write of the counter with a database write in the
// middle. KeyMan must make it atomic on its own: callers serialise through
// cs_wallet today, but KeyMan cannot name that lock, so nothing would catch a
// new caller that does not. Concurrent claims without cs_wallet must still
// never hand one generation out twice.
BOOST_FIXTURE_TEST_CASE(blinding_generation_claims_are_atomic, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    auto w = MakeWallet(m_node.chain.get(), std::vector<unsigned char>(32, 0x41));

    // Every thread claims on every anchor in the same order, so each anchor
    // sees THREADS claims racing; many anchors give the race many chances.
    constexpr uint32_t THREADS{8};
    constexpr uint32_t ANCHORS{256};
    static_assert(THREADS <= blsct::MAX_GENERATION_SEARCH);

    std::vector<Outid> anchors;
    for (uint32_t a = 0; a < ANCHORS; ++a) {
        uint256 h;
        std::fill(h.begin(), h.end(), 0x46);
        std::copy_n(reinterpret_cast<const unsigned char*>(&a), sizeof(a), h.begin());
        anchors.push_back(Outid::FromUint256(h));
    }

    std::vector<std::vector<std::optional<uint32_t>>> results(THREADS);
    std::atomic<bool> start{false};
    std::vector<std::thread> threads;
    threads.reserve(results.size());
    for (auto& result : results) {
        threads.emplace_back([&w, &anchors, &result, &start] {
            while (!start) std::this_thread::yield();
            for (const Outid& anchor : anchors) {
                result.push_back(w.km->ReserveBlindingGeneration(anchor));
            }
        });
    }
    start = true;
    for (auto& thread : threads) thread.join();

    // Each anchor handed out generations 0..THREADS-1, each exactly once.
    for (uint32_t a = 0; a < ANCHORS; ++a) {
        std::set<uint32_t> claimed;
        for (const auto& result : results) {
            BOOST_REQUIRE_EQUAL(result.size(), ANCHORS);
            BOOST_REQUIRE(result[a].has_value());
            BOOST_CHECK_MESSAGE(claimed.insert(*result[a]).second,
                                "anchor " << a << ": generation " << *result[a] << " was handed out twice");
        }
        BOOST_CHECK_EQUAL(claimed.size(), THREADS);
        BOOST_CHECK_EQUAL(*claimed.rbegin(), THREADS - 1);
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

// Recovery only searches ordinals below MAX_OUTPUT_SEARCH, so the factory must
// not derive a key for an output past it: such a key would only look
// recoverable. Queue one output more than the bound allows (plus change, which
// continues the ordinal sequence) and check that ordinals below the bound
// still derive while the ones past it fall back to random keys.
BOOST_FIXTURE_TEST_CASE(output_ordinal_past_search_bound_is_not_derived, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 23, .memory_only = true}, {}};

    auto sender = MakeWallet(m_node.chain.get(), std::vector<unsigned char>(32, 0x6d));
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

    auto factory = blsct::TxFactory(sender.km);
    BOOST_REQUIRE(factory.AddInput(coins_view_cache, outpoint));
    for (uint32_t i = 0; i <= blsct::MAX_OUTPUT_SEARCH; ++i) {
        factory.AddOutput(recvAddress, 10 * COIN, "payment");
    }

    auto built = factory.BuildTx();
    BOOST_REQUIRE(built.has_value());

    std::vector<COutPoint> own;
    for (const auto& in : built->tx.vin) own.push_back(in.prevout);
    const auto canonical = blsct::CanonicalAnchor(own);
    BOOST_REQUIRE(canonical.has_value());
    const auto seed = sender.km->GetBlindingSeed();
    BOOST_REQUIRE(seed.has_value());

    // Map each built scalar back to the ordinal it was derived on, if any.
    // This is the first build on a fresh anchor, so the generation is 0.
    const auto derived_ordinal = [&](const BlstScalar& k) -> std::optional<uint32_t> {
        for (uint32_t ordinal = 0; ordinal <= blsct::MAX_OUTPUT_SEARCH + 1; ++ordinal) {
            if (blsct::DeriveBlindingKey(*seed, *canonical, ordinal, /*generation=*/0) == k) return ordinal;
        }
        return std::nullopt;
    };

    std::set<uint32_t> derived;
    size_t random_keys = 0;
    for (const auto& out : built->tx.vout) {
        if (!out.HasBLSCTKeys()) continue;
        const BlstScalar& k = built->blindingKeys.at(out.GetHash());
        const auto ordinal = derived_ordinal(k);
        const bool recoverable = sender.km->RecoverOutputBlindingKey(built->tx.vin, out, own).has_value();
        if (ordinal) {
            derived.insert(*ordinal);
            // Everything the factory derived, recovery finds again.
            BOOST_CHECK_MESSAGE(recoverable, "ordinal " << *ordinal << " was derived but is not recoverable");
        } else {
            ++random_keys;
            BOOST_CHECK(!recoverable);
        }
    }

    // The last ordinal recovery searches still derives...
    BOOST_CHECK(derived.contains(blsct::MAX_OUTPUT_SEARCH - 1));
    // ...and the first one it does not search never does.
    BOOST_CHECK(!derived.contains(blsct::MAX_OUTPUT_SEARCH));
    BOOST_CHECK_EQUAL(derived.size(), blsct::MAX_OUTPUT_SEARCH);
    // The over-bound recipient and the change output behind it.
    BOOST_CHECK_EQUAL(random_keys, 2U);
    // The build reports exactly those, so the wallet can say so once.
    BOOST_CHECK_EQUAL(built->pastSearchBoundOutputs, random_keys);
}

// Swap halves (BuildUnbalancedHalf) materialize queued outputs the same way
// BuildTx does, so an output queued past MAX_OUTPUT_SEARCH gets a random key
// there too. The half reports how many, and the wallet logs it once per half
// it returns -- not once per attempt BuildHalfAddingSpares discards.
BOOST_FIXTURE_TEST_CASE(swap_half_reports_outputs_past_search_bound, TestingSetup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    auto sender = MakeWallet(m_node.chain.get(), RepeatedByte(0x6e));
    LOCK(sender.wallet->cs_wallet);

    const auto recvAddress = std::get<blsct::DoublePublicKey>(sender.km->GetNewDestination(0).value());
    const auto change = std::get<blsct::DoublePublicKey>(sender.km->GetNewDestination(-1).value());
    // One output per ordinal recovery searches, plus the first one it does not.
    const CAmount payment = 10 * COIN;
    const CAmount pay_amount = (blsct::MAX_OUTPUT_SEARCH + 1) * payment;

    const auto coin = [](CAmount amount) {
        return blsct::InputCandidates{amount, BlstScalar::Rand(), blsct::PrivateKey(BlstScalar::Rand()), TokenId(), COutPoint{Txid::FromUint256(InsecureRand256())}, false};
    };
    const auto fill = [&](blsct::TxFactory& factory, const blsct::InputCandidates& in) {
        factory.blsct::TxFactoryBase::AddInput(in.amount, in.gamma, in.spendingKey, in.token_id, in.outpoint);
        for (uint32_t i = 0; i <= blsct::MAX_OUTPUT_SEARCH; ++i) {
            factory.AddOutput(recvAddress, payment, "payment");
        }
    };

    // The half reports the over-bound output; change and the received output
    // take explicit random keys and are not counted.
    {
        auto factory = blsct::TxFactory(sender.km);
        fill(factory, coin(pay_amount));
        size_t past = 0;
        const auto half = factory.blsct::TxFactoryBase::BuildUnbalancedHalf(
            change, blsct::SubAddress(recvAddress), TokenId(), pay_amount, TokenId(), payment,
            /*nBLSCTDefaultFee=*/0, /*additionalFee=*/0, &past);
        BOOST_REQUIRE(half.has_value());
        BOOST_CHECK_EQUAL(past, 1U);
    }

    // The wallet logs it once for the half BuildHalfAddingSpares returns: the
    // first attempt is short of funds and fails, the spare makes the second
    // build.
    {
        auto factory = blsct::TxFactory(sender.km);
        fill(factory, coin(pay_amount - 1));
        const std::vector<blsct::InputCandidates> spares{coin(pay_amount)};
        size_t builds = 0;
        size_t logged = 0;
        {
            DebugLogHelper count_logs{"more outputs than the recovery search bound", [&](const std::string* line) {
                                          if (line) ++logged;
                                          return false;
                                      }};
            const auto half = factory.BuildHalfAddingSpares(spares, /*first_spare=*/0, [&] {
                ++builds;
                return factory.BuildUnbalancedHalf(change, blsct::SubAddress(recvAddress), TokenId(), pay_amount,
                                                   TokenId(), payment, /*nBLSCTDefaultFee=*/0);
            });
            BOOST_REQUIRE(half.has_value());
        }
        BOOST_CHECK_EQUAL(builds, 2U);
        BOOST_CHECK_EQUAL(logged, 1U);
    }
}

BOOST_AUTO_TEST_SUITE_END()
