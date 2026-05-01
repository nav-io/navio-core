// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests that invalid / tampered PoPS (Proof of Stake) blocks are rejected by
// consensus verification. Complements pos_chain_tests.cpp (happy path) and
// pops_hardening_tests.cpp (primitives).

#include <arith_uint256.h>
#include <blsct/pos/helpers.h>
#include <blsct/pos/pos.h>
#include <blsct/pos/proof.h>
#include <blsct/pos/proof_logic.h>
#include <blsct/wallet/txfactory.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>

namespace wallet {

// Build a PoS-valid block by grinding nTime until Create/Verify accepts it.
static bool BuildValidPoSBlock(
    CCoinsViewCache& view,
    const CBlockIndex* pindexPrev,
    CBlock& block,
    const MclScalar& value,
    const MclScalar& gamma,
    const Consensus::Params& params,
    int max_grinds = 10000)
{
    for (int i = 0; i < max_grinds; ++i) {
        block.posProof = blsct::ProofOfStakeLogic::Create(view, value, gamma, pindexPrev, block, params);
        if (blsct::ProofOfStakeLogic::Verify(view, pindexPrev, block, params)) {
            return true;
        }
        block.nTime += 1;
    }
    return false;
}

BOOST_FIXTURE_TEST_SUITE(pos_consensus_tests, WalletTestingSetup)

BOOST_FIXTURE_TEST_CASE(invalid_pos_proof_is_rejected, TestBLSCTChain100Setup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    CCoinsViewDB base{{.path = "test_cons", .cache_bytes = 1 << 23, .memory_only = true}, {}};

    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet.InitWalletFlags(wallet::WALLET_FLAG_BLSCT);
    LOCK(wallet.cs_wallet);
    auto blsct_km = wallet.GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));
    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    // Two staked outputs so the set-mem proof has enough members (Verify
    // rejects blocks whose staked-commitment set is < 2).
    auto out1 = blsct::CreateOutput(
        recvAddress, 1000 * COIN, "a", TokenId(), Scalar::Rand(),
        blsct::CreateTransactionType::STAKED_COMMITMENT, 999 * COIN);
    auto out2 = blsct::CreateOutput(
        recvAddress, 1000 * COIN, "b", TokenId(), Scalar::Rand(),
        blsct::CreateTransactionType::STAKED_COMMITMENT, 999 * COIN);

    Coin coin1;
    coin1.nHeight = 1;
    coin1.out = out1.out;
    Coin coin2;
    coin2.nHeight = 1;
    coin2.out = out2.out;

    COutPoint outpoint1{Txid::FromUint256(InsecureRand256())};
    COutPoint outpoint2{Txid::FromUint256(InsecureRand256())};

    CCoinsViewCache view{&base, /*deterministic=*/true};
    view.AddCoin(outpoint1, std::move(coin1), true);
    view.AddCoin(outpoint2, std::move(coin2), true);

    // pindexPrev needs a stable block hash and chain-work context. Use a
    // standalone CBlockIndex pointing at a random hash — ProofOfStake uses
    // prev->GetBlockHash() for the set-mem proof randomness seed only.
    CBlockIndex index;
    const uint256 randomHash{InsecureRand256()};
    index.phashBlock = &randomHash;
    index.nHeight = 1;
    index.nBits = 0x207fffff;
    index.nTime = 1700000000;
    index.nStakeModifier = 0xdeadbeefULL;

    const auto& params = m_node.chainman->GetConsensus();

    CBlock block;
    block.nTime = index.nTime + 1;
    block.nBits = 0x207fffff;
    BOOST_REQUIRE(BuildValidPoSBlock(view, &index, block, out1.value, out1.gamma, params));

    // Sanity: the freshly-built block must pass verification.
    BOOST_CHECK(blsct::ProofOfStakeLogic::Verify(view, &index, block, params));

    // ---- mutation 1: swap pindexPrev for one with a different stake modifier.
    // The set-mem-proof Fiat-Shamir seed is derived from pindexPrev; any
    // divergence from the grinded context must invalidate the proof.
    {
        CBlockIndex index_alt;
        const uint256 altHash{InsecureRand256()};
        index_alt.phashBlock = &altHash;
        index_alt.nHeight = index.nHeight;
        index_alt.nBits = index.nBits;
        index_alt.nTime = index.nTime;
        index_alt.nStakeModifier = index.nStakeModifier ^ 1ULL;
        BOOST_CHECK(!blsct::ProofOfStakeLogic::Verify(view, &index_alt, block, params));
    }

    // ---- mutation 3: corrupt setMemProof by zeroing one of its G1 points.
    {
        CBlock mutated = block;
        mutated.posProof.setMemProof.phi = MclG1Point();
        BOOST_CHECK(!blsct::ProofOfStakeLogic::Verify(view, &index, mutated, params));
    }

    // ---- mutation 3: corrupt rangeProof by zeroing A_wip.
    {
        CBlock mutated = block;
        mutated.posProof.rangeProof.A_wip = MclG1Point();
        BOOST_CHECK(!blsct::ProofOfStakeLogic::Verify(view, &index, mutated, params));
    }

    // ---- mutation 4: corrupt rangeProof by perturbing a scalar.
    {
        CBlock mutated = block;
        mutated.posProof.rangeProof.r_prime = mutated.posProof.rangeProof.r_prime + MclScalar(1);
        BOOST_CHECK(!blsct::ProofOfStakeLogic::Verify(view, &index, mutated, params));
    }

    // ---- mutation 5: staked-commitment set of size < 2 is rejected outright.
    {
        CCoinsViewCache view_sparse{&base, /*deterministic=*/true};
        // Re-add only ONE staked commitment; Verify requires at least two.
        Coin coin_solo;
        coin_solo.nHeight = 1;
        auto out_solo = blsct::CreateOutput(
            recvAddress, 1000 * COIN, "c", TokenId(), Scalar::Rand(),
            blsct::CreateTransactionType::STAKED_COMMITMENT, 999 * COIN);
        coin_solo.out = out_solo.out;
        view_sparse.AddCoin(COutPoint{Txid::FromUint256(InsecureRand256())},
                            std::move(coin_solo), true);
        BOOST_CHECK(!blsct::ProofOfStakeLogic::Verify(view_sparse, &index, block, params));
    }
}

BOOST_FIXTURE_TEST_CASE(wrong_kernel_hash_is_rejected, TestBLSCTChain100Setup)
{
    // The consensus path in validation.cpp computes kernel_hash once and
    // passes it into ProofOfStakeLogic::Verify. Feeding a bogus kernel hash
    // to the overload must reject the block even if the rest of the proof
    // is well-formed.
    SeedInsecureRand(SeedRand::ZEROS);
    CCoinsViewDB base{{.path = "test_kh", .cache_bytes = 1 << 23, .memory_only = true}, {}};

    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet.InitWalletFlags(wallet::WALLET_FLAG_BLSCT);
    LOCK(wallet.cs_wallet);
    auto blsct_km = wallet.GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));
    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    auto out1 = blsct::CreateOutput(
        recvAddress, 1000 * COIN, "a", TokenId(), Scalar::Rand(),
        blsct::CreateTransactionType::STAKED_COMMITMENT, 999 * COIN);
    auto out2 = blsct::CreateOutput(
        recvAddress, 1000 * COIN, "b", TokenId(), Scalar::Rand(),
        blsct::CreateTransactionType::STAKED_COMMITMENT, 999 * COIN);

    Coin coin1;
    coin1.nHeight = 1;
    coin1.out = out1.out;
    Coin coin2;
    coin2.nHeight = 1;
    coin2.out = out2.out;

    CCoinsViewCache view{&base, /*deterministic=*/true};
    view.AddCoin(COutPoint{Txid::FromUint256(InsecureRand256())}, std::move(coin1), true);
    view.AddCoin(COutPoint{Txid::FromUint256(InsecureRand256())}, std::move(coin2), true);

    CBlockIndex index;
    const uint256 randomHash{InsecureRand256()};
    index.phashBlock = &randomHash;
    index.nHeight = 1;
    index.nBits = 0x207fffff;
    index.nTime = 1700000000;
    index.nStakeModifier = 0xdeadbeefULL;

    const auto& params = m_node.chainman->GetConsensus();

    CBlock block;
    block.nTime = index.nTime + 1;
    block.nBits = 0x207fffff;
    BOOST_REQUIRE(BuildValidPoSBlock(view, &index, block, out1.value, out1.gamma, params));

    // Stock overload (recomputes kernel hash internally) accepts.
    BOOST_CHECK(blsct::ProofOfStakeLogic::Verify(view, &index, block, params));

    // Precomputed-kernel overload with the real hash accepts.
    const uint256 good_kh = blsct::CalculateKernelHash(&index, block, params);
    BOOST_CHECK(blsct::ProofOfStakeLogic::Verify(view, &index, block, params, good_kh));

    // Precomputed-kernel overload with a radically different hash rejects —
    // proves that the consensus fast-path hoisted by ConnectBlock cannot be
    // made to skip validation by handing in a wrong pre-computed value.
    // Flip every byte so the derived min_value jumps far outside the range
    // the proof was grinded for; the range proof must fail.
    uint256 bad_kh;
    for (size_t i = 0; i < 32; ++i) bad_kh.data()[i] = static_cast<uint8_t>(good_kh.data()[i] ^ 0xff);
    BOOST_CHECK(!blsct::ProofOfStakeLogic::Verify(view, &index, block, params, bad_kh));
}

// Regression: under realistic difficulty plus non-zero accumulated chain work,
// the proof a staker constructs over RPC must verify under the consensus
// kernel hash. The bug this guards against is a staker-only regression seen
// on testnet (147190-testnet) where every block was rejected with
// `bad-blsct-pos-proof`: the proof construction path used
// `CalculateKernelHash(prev_time, modifier, time)` (no chain-work binding),
// while the consensus path used
// `CalculateKernelHashWithChainWork(prev_time, modifier, prev_chain_work, time)`,
// so the bulletproofs+ range proof's `Scalar(min_value)` seed differed and the
// proof never verified. At trivial difficulty (`nBits = 0x207fffff`) both
// hashes degenerate to `min_value == 0` and the seed mismatch is masked,
// which is why pos_chain_tests.cpp/StakedCommitment did not catch this. We
// pick a tighter `nBits` that forces a non-zero `min_value`, and a non-zero
// `nChainWork`, so the two formulas observably disagree.
BOOST_FIXTURE_TEST_CASE(staker_proof_verifies_under_consensus_at_real_difficulty, TestBLSCTChain100Setup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    CCoinsViewDB base{{.path = "test_real_diff", .cache_bytes = 1 << 23, .memory_only = true}, {}};

    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet.InitWalletFlags(wallet::WALLET_FLAG_BLSCT);
    LOCK(wallet.cs_wallet);
    auto blsct_km = wallet.GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));
    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    auto out1 = blsct::CreateOutput(
        recvAddress, 1000 * COIN, "a", TokenId(), Scalar::Rand(),
        blsct::CreateTransactionType::STAKED_COMMITMENT, 999 * COIN);
    auto out2 = blsct::CreateOutput(
        recvAddress, 1000 * COIN, "b", TokenId(), Scalar::Rand(),
        blsct::CreateTransactionType::STAKED_COMMITMENT, 999 * COIN);

    Coin coin1; coin1.nHeight = 1; coin1.out = out1.out;
    Coin coin2; coin2.nHeight = 1; coin2.out = out2.out;

    CCoinsViewCache view{&base, /*deterministic=*/true};
    view.AddCoin(COutPoint{Txid::FromUint256(InsecureRand256())}, std::move(coin1), true);
    view.AddCoin(COutPoint{Txid::FromUint256(InsecureRand256())}, std::move(coin2), true);

    // 0x1f00ffff puts target ≈ 2^240, so for a uniformly random kernel hash
    // (~2^255) the resulting min_value lands around 2^15..2^17 sat — well
    // below the 1000 * COIN ≈ 1e11 sat staked value, so grinding nTime can
    // find a satisfying kernel quickly, while still being far enough from
    // zero that a kernel-hash mismatch produces an observably different
    // min_value seed.
    const uint32_t kRealNBits = 0x1f00ffff;

    CBlockIndex index;
    const uint256 randomHash{InsecureRand256()};
    index.phashBlock = &randomHash;
    index.nHeight = 1;
    index.nBits = kRealNBits;
    index.nTime = 1700000000;
    index.nStakeModifier = 0xdeadbeefULL;
    // Non-zero accumulated chain work: distinguishes the chain-work-bound
    // kernel hash from the legacy (no chain-work) kernel hash.
    index.nChainWork = arith_uint256{static_cast<uint64_t>(1) << 40};

    const auto& params = m_node.chainman->GetConsensus();
    BOOST_REQUIRE(params.fPoPSHardened);

    CBlock block;
    block.nTime = index.nTime + 1;
    block.nBits = kRealNBits;

    // Sanity check that the difficulty is genuinely non-trivial: with
    // probability ~1, the chain-work-bound and legacy kernel hashes feed
    // different non-zero min_values.
    const uint256 kh_legacy = blsct::CalculateKernelHash(index.nTime, index.nStakeModifier, block.nTime, /*hardened=*/true);
    const uint256 kh_consensus = blsct::CalculateKernelHash(&index, block, params);
    BOOST_REQUIRE(kh_legacy != kh_consensus);
    const uint64_t mv_legacy = blsct::ProofOfStake::SaturateToU64(blsct::ProofOfStake::CalculateMinValue(kh_legacy, kRealNBits));
    const uint64_t mv_consensus = blsct::ProofOfStake::SaturateToU64(blsct::ProofOfStake::CalculateMinValue(kh_consensus, kRealNBits));
    BOOST_REQUIRE(mv_legacy != 0);
    BOOST_REQUIRE(mv_consensus != 0);
    BOOST_REQUIRE(mv_legacy != mv_consensus);

    // The actual regression: with the buggy Create path, BuildValidPoSBlock
    // never converges (Verify rejects every grind because the kernel hash
    // disagrees). After the fix, the loop succeeds within a few iterations
    // because Create binds chain work the same way Verify does.
    BOOST_REQUIRE(BuildValidPoSBlock(view, &index, block, out1.value, out1.gamma, params, /*max_grinds=*/2000));
    BOOST_CHECK(blsct::ProofOfStakeLogic::Verify(view, &index, block, params));
}

// Reproduces the second half of the staker bug: navio-staker hard-codes
//     hardened = (chain_type != ChainType::TESTNET);
// The chain configures `fPoPSHardened` independently. If those two booleans
// disagree (which currently happens on testnet, where chainparams now sets
// `fPoPSHardened = true` but the staker still treats testnet as un-hardened),
// the staker's proof is computed against the wrong kernel hash and consensus
// rejects it. This test asserts that a proof built with the wrong `hardened`
// flag is rejected by the consensus path — i.e. the staker MUST source the
// flag from consensus, not derive it from the chain type.
BOOST_FIXTURE_TEST_CASE(staker_proof_with_wrong_hardened_flag_is_rejected, TestBLSCTChain100Setup)
{
    SeedInsecureRand(SeedRand::ZEROS);
    CCoinsViewDB base{{.path = "test_hardened_flag", .cache_bytes = 1 << 23, .memory_only = true}, {}};

    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet.InitWalletFlags(wallet::WALLET_FLAG_BLSCT);
    LOCK(wallet.cs_wallet);
    auto blsct_km = wallet.GetOrCreateBLSCTKeyMan();
    BOOST_CHECK(blsct_km->SetupGeneration({}, blsct::IMPORT_MASTER_KEY, true));
    auto recvAddress = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(0).value());

    auto out1 = blsct::CreateOutput(
        recvAddress, 1000 * COIN, "a", TokenId(), Scalar::Rand(),
        blsct::CreateTransactionType::STAKED_COMMITMENT, 999 * COIN);
    auto out2 = blsct::CreateOutput(
        recvAddress, 1000 * COIN, "b", TokenId(), Scalar::Rand(),
        blsct::CreateTransactionType::STAKED_COMMITMENT, 999 * COIN);
    Coin coin1; coin1.nHeight = 1; coin1.out = out1.out;
    Coin coin2; coin2.nHeight = 1; coin2.out = out2.out;
    CCoinsViewCache view{&base, /*deterministic=*/true};
    view.AddCoin(COutPoint{Txid::FromUint256(InsecureRand256())}, std::move(coin1), true);
    view.AddCoin(COutPoint{Txid::FromUint256(InsecureRand256())}, std::move(coin2), true);

    // Tight enough that BucketTime() vs raw-time produces a different
    // min_value seed (otherwise both hardened/legacy hashes would yield
    // min_value == 0 and the bug would not manifest).
    const uint32_t kRealNBits = 0x1f00ffff;

    CBlockIndex index;
    const uint256 randomHash{InsecureRand256()};
    index.phashBlock = &randomHash;
    index.nHeight = 1;
    index.nBits = kRealNBits;
    // Pick a non-bucket-aligned time so BucketTime(t) != t observably.
    index.nTime = 1700000003;
    index.nStakeModifier = 0xdeadbeefULL;
    index.nChainWork = arith_uint256{1};

    const auto& params = m_node.chainman->GetConsensus();
    BOOST_REQUIRE(params.fPoPSHardened);

    CBlock block;
    // Pick a non-bucket-aligned block time too.
    block.nTime = index.nTime + 7;
    block.nBits = kRealNBits;

    // Build the staked_commitments / eta_phi exactly the way the staker
    // does (this mirrors `GetBlockProposal` in src/navio-staker.cpp).
    auto staked_commitments = view.GetStakedCommitments().GetElements(
        block.GetBlockHeader().GetHash(), params.nStakedCommitmentLimit);
    BOOST_REQUIRE(staked_commitments.Size() >= 2);
    const auto eta_fiat_shamir = blsct::CalculateSetMemProofRandomness(&index);
    const auto eta_phi = blsct::CalculateSetMemProofGeneratorSeed(&index, block);
    const auto next_target = blsct::GetNextTargetRequired(&index, &block, params);
    BOOST_REQUIRE_EQUAL(next_target, kRealNBits);

    // Construct a proof with the WRONG hardened flag (false) on a chain
    // where consensus expects hardening (true) — exactly what the testnet
    // staker is doing today. The proof must be rejected by consensus.
    block.posProof = blsct::ProofOfStake(
        staked_commitments, eta_fiat_shamir, eta_phi,
        out1.value, out1.gamma,
        index.nTime, index.nStakeModifier, block.nTime, next_target,
        /*hardened=*/false);
    BOOST_CHECK(!blsct::ProofOfStakeLogic::Verify(view, &index, block, params));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
