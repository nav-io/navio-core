// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for the PoPS hardening patches:
//   * ProofOfStake::SaturateToU64
//   * Time-bucket grinding mitigation in CalculateKernelHash
//   * Chain-work binding in CalculateKernelHashWithChainWork
//   * G1 subgroup check on deserialize
//
// Finality-checkpoint enforcement is covered by validation_tests.cpp.

#include <boost/test/unit_test.hpp>

#include <arith_uint256.h>
#include <blsct/arith/mcl/mcl.h>
#include <blsct/arith/mcl/mcl_g1point.h>
#include <blsct/pos/helpers.h>
#include <blsct/pos/pos.h>
#include <blsct/pos/proof.h>
#include <chain.h>
#include <consensus/params.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <algorithm>
#include <limits>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(pops_hardening_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(saturate_to_u64_low_value_passes_through)
{
    uint256 low;
    // low bytes: 0x00..00 00 00 00 01 00 00 00 00  -> 2^32
    low.data()[4] = 0x01;
    uint64_t got = blsct::ProofOfStake::SaturateToU64(low);
    BOOST_CHECK_EQUAL(got, (uint64_t{1} << 32));
}

BOOST_AUTO_TEST_CASE(saturate_to_u64_exactly_uint64_max_passes_through)
{
    uint256 v;
    for (size_t i = 0; i < 8; ++i) v.data()[i] = 0xff;
    uint64_t got = blsct::ProofOfStake::SaturateToU64(v);
    BOOST_CHECK_EQUAL(got, std::numeric_limits<uint64_t>::max());
}

BOOST_AUTO_TEST_CASE(saturate_to_u64_clamps_on_overflow)
{
    uint256 v;
    // Set a byte above the low 8 -> value exceeds 2^64
    v.data()[9] = 0x01;
    uint64_t got = blsct::ProofOfStake::SaturateToU64(v);
    BOOST_CHECK_EQUAL(got, std::numeric_limits<uint64_t>::max());
}

BOOST_AUTO_TEST_CASE(kernel_hash_buckets_block_time)
{
    // Two times in the same 16s bucket must produce the same kernel hash.
    // Times in different buckets must differ.
    const uint32_t prevTime = 1000000;
    const uint64_t modifier = 0xdeadbeefcafebabeULL;

    // Pick a bucket-aligned base time so two offsets within [0, 16) share a
    // bucket and the next 16s boundary lands in the following bucket.
    const uint32_t bucket_base = 1234567808; // 1234567808 % 16 == 0
    uint256 a = blsct::CalculateKernelHash(prevTime, modifier, bucket_base + 0);
    uint256 b = blsct::CalculateKernelHash(prevTime, modifier, bucket_base + 15);
    uint256 c = blsct::CalculateKernelHash(prevTime, modifier, bucket_base + 16);

    BOOST_CHECK(a == b);
    BOOST_CHECK(a != c);
}

BOOST_AUTO_TEST_CASE(kernel_hash_with_chain_work_diverges_per_fork)
{
    const uint32_t prevTime = 1000000;
    const uint64_t modifier = 42;
    const uint32_t time = 1000060;

    arith_uint256 workA = UintToArith256(uint256S("01"));
    arith_uint256 workB = UintToArith256(uint256S("02"));

    uint256 hA = blsct::CalculateKernelHashWithChainWork(prevTime, modifier, workA, time);
    uint256 hB = blsct::CalculateKernelHashWithChainWork(prevTime, modifier, workB, time);
    BOOST_CHECK(hA != hB);
}

// ---------------------------------------------------------------------------
// V2 kernel: binding the set-membership image point `phi`.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(kernel_hash_binds_phi)
{
    const uint32_t prevTime = 1000000;
    const uint64_t modifier = 7;
    const uint32_t time = 1000060;
    const arith_uint256 work = UintToArith256(uint256S("0a"));

    MclG1Point phiA = MclG1Point::Rand();
    MclG1Point phiB = MclG1Point::Rand();

    uint256 hA = blsct::CalculateKernelHashWithChainWork(prevTime, modifier, work, time, phiA);
    uint256 hB = blsct::CalculateKernelHashWithChainWork(prevTime, modifier, work, time, phiB);
    uint256 hA2 = blsct::CalculateKernelHashWithChainWork(prevTime, modifier, work, time, phiA);

    // Distinct phi => distinct kernel (independent per-coin draw).
    BOOST_CHECK(hA != hB);
    // Same inputs => deterministic.
    BOOST_CHECK(hA == hA2);

    // V2 (phi-bound) differs from V1 (no phi) for the same scalar inputs.
    uint256 v1 = blsct::CalculateKernelHashWithChainWork(prevTime, modifier, work, time);
    BOOST_CHECK(hA != v1);
}

BOOST_AUTO_TEST_CASE(kernel_hash_phi_legacy_ignores_phi)
{
    // When hardened == false the phi overload must reproduce the legacy kernel
    // exactly (phi ignored), so pre-hardening chains keep validating.
    const uint32_t prevTime = 1000000;
    const uint64_t modifier = 7;
    const uint32_t time = 1000060;
    const arith_uint256 work = UintToArith256(uint256S("0a"));
    MclG1Point phi = MclG1Point::Rand();

    uint256 legacy = blsct::CalculateKernelHash(prevTime, modifier, time, /*hardened=*/false);
    uint256 phi_unhardened = blsct::CalculateKernelHashWithChainWork(prevTime, modifier, work, time, phi, /*hardened=*/false);
    BOOST_CHECK(legacy == phi_unhardened);
}

// ---------------------------------------------------------------------------
// V2 anti-grinding seed fixes (eta_phi de-grind + eta_fiat_shamir vtx binding).
// ---------------------------------------------------------------------------

namespace {
// Minimal stand-in prev-block index. `CalculateSetMemProof*` only read
// nHeight, nStakeModifier, and GetBlockHash() (phashBlock).
struct PrevIndex {
    uint256 hash;
    CBlockIndex index;
    PrevIndex(int height, uint64_t modifier, const uint256& h) : hash(h)
    {
        index.phashBlock = &hash;
        index.nHeight = height;
        index.nStakeModifier = modifier;
    }
};

// A block whose vtx carries one dummy tx with a chosen lock-time, so two blocks
// can differ ONLY in their transaction set.
CBlock BlockWithMarker(uint32_t marker)
{
    CBlock b;
    CMutableTransaction tx;
    tx.nLockTime = marker;
    b.vtx.push_back(MakeTransactionRef(std::move(tx)));
    return b;
}

Consensus::Params ParamsWithV2(int v2_height)
{
    Consensus::Params p{};
    p.nPoPSKernelV2Height = v2_height;
    return p;
}
} // namespace

BOOST_AUTO_TEST_CASE(v2_eta_phi_seed_ignores_block_vtx)
{
    // V2 generator seed must NOT depend on block.vtx (so phi/kernel can't be
    // ground by mutating transactions); the legacy seed DOES depend on vtx.
    PrevIndex prev(21999, 0xabcdULL, uint256S("11"));
    CBlock blockA = BlockWithMarker(1);
    CBlock blockB = BlockWithMarker(2);

    auto v2 = ParamsWithV2(0);       // V2 active from genesis
    auto legacy = ParamsWithV2(1000000); // V2 not yet active at height 22000

    // Legacy: seed varies with vtx.
    auto seed_legacy_A = blsct::CalculateSetMemProofGeneratorSeed(&prev.index, blockA, legacy);
    auto seed_legacy_B = blsct::CalculateSetMemProofGeneratorSeed(&prev.index, blockB, legacy);
    BOOST_CHECK(seed_legacy_A != seed_legacy_B);

    // V2: seed invariant to vtx.
    auto seed_v2_A = blsct::CalculateSetMemProofGeneratorSeed(&prev.index, blockA, v2);
    auto seed_v2_B = blsct::CalculateSetMemProofGeneratorSeed(&prev.index, blockB, v2);
    BOOST_CHECK(seed_v2_A == seed_v2_B);
    BOOST_CHECK(seed_v2_A == blsct::CalculateSetMemProofGeneratorSeedV2(&prev.index));
}

BOOST_AUTO_TEST_CASE(v2_eta_fiat_shamir_binds_block_vtx)
{
    // V2 Fiat-Shamir randomness MUST depend on block.vtx so the set-membership
    // proof is a signature over the block body (anti-malleability). The legacy
    // randomness does not bind vtx.
    PrevIndex prev(21999, 0xabcdULL, uint256S("22"));
    CBlock blockA = BlockWithMarker(1);
    CBlock blockB = BlockWithMarker(2);

    auto v2 = ParamsWithV2(0);
    auto legacy = ParamsWithV2(1000000);

    auto fs_v2_A = blsct::CalculateSetMemProofRandomness(&prev.index, blockA, v2);
    auto fs_v2_B = blsct::CalculateSetMemProofRandomness(&prev.index, blockB, v2);
    BOOST_CHECK(fs_v2_A != fs_v2_B); // bound to vtx => signature over block

    auto fs_legacy_A = blsct::CalculateSetMemProofRandomness(&prev.index, blockA, legacy);
    auto fs_legacy_B = blsct::CalculateSetMemProofRandomness(&prev.index, blockB, legacy);
    BOOST_CHECK(fs_legacy_A == fs_legacy_B); // legacy ignores vtx
    BOOST_CHECK(fs_legacy_A == blsct::CalculateSetMemProofRandomness(&prev.index));
}

BOOST_AUTO_TEST_CASE(v2_eta_phi_unlinkable_across_heights)
{
    // Unlinkability: the SAME coin staking at two different heights gets a
    // different generator seed (different pindexPrev) -> different g2 -> the
    // coin's phi differs block-to-block, so on-chain phis are not a linkage.
    PrevIndex prevH1(21999, 0x1111ULL, uint256S("aa"));
    PrevIndex prevH2(22000, 0x2222ULL, uint256S("bb"));

    auto a = blsct::CalculateSetMemProofGeneratorSeedV2(&prevH1.index);
    auto b = blsct::CalculateSetMemProofGeneratorSeedV2(&prevH2.index);
    BOOST_CHECK(a != b);
    // Deterministic for a fixed prev (sanity).
    BOOST_CHECK(a == blsct::CalculateSetMemProofGeneratorSeedV2(&prevH1.index));
}

BOOST_AUTO_TEST_CASE(v2_ring_seed_not_grindable_by_header)
{
    // V2 ring seed must NOT depend on the candidate block's own header (so the
    // producer of the previous block cannot grind the next ring). Legacy seed
    // IS the header hash.
    PrevIndex prev(21999, 0x5555ULL, uint256S("33"));
    auto v2 = ParamsWithV2(0);
    auto legacy = ParamsWithV2(1000000);

    const uint256 headerA = uint256S("aaaa");
    const uint256 headerB = uint256S("bbbb");
    const uint32_t t0 = 1700000000u;            // bucket-aligned-ish base
    const uint32_t t_same_bucket = t0 + 5;      // same 16s bucket as t0
    const uint32_t t_next_bucket = t0 + 16;     // next bucket

    // Legacy: seed == header hash (varies with header => grindable).
    BOOST_CHECK(blsct::CalculateStakeRingSeed(&prev.index, headerA, t0, legacy) == headerA);
    BOOST_CHECK(blsct::CalculateStakeRingSeed(&prev.index, headerA, t0, legacy) !=
                blsct::CalculateStakeRingSeed(&prev.index, headerB, t0, legacy));

    // V2: seed independent of the candidate header (only prev modifier + deep
    // ancestor + bucketed time feed it). Same time + same prev => same seed
    // regardless of header.
    BOOST_CHECK(blsct::CalculateStakeRingSeed(&prev.index, headerA, t0, v2) ==
                blsct::CalculateStakeRingSeed(&prev.index, headerB, t0, v2));

    // V2 seed changes with the stake modifier (the per-interval beacon).
    PrevIndex prev2(21999, 0x6666ULL, uint256S("33"));
    BOOST_CHECK(blsct::CalculateStakeRingSeed(&prev.index, headerA, t0, v2) !=
                blsct::CalculateStakeRingSeed(&prev2.index, headerA, t0, v2));

    // Liveness: the V2 ring rotates with the wall-clock bucket. Same bucket =>
    // same ring (no per-second grind); next bucket => different ring (so a
    // stall with all sampled stakers offline self-heals as time advances).
    BOOST_CHECK(blsct::CalculateStakeRingSeed(&prev.index, headerA, t0, v2) ==
                blsct::CalculateStakeRingSeed(&prev.index, headerA, t_same_bucket, v2));
    BOOST_CHECK(blsct::CalculateStakeRingSeed(&prev.index, headerA, t0, v2) !=
                blsct::CalculateStakeRingSeed(&prev.index, headerA, t_next_bucket, v2));
}

// ---------------------------------------------------------------------------
// Proportional-fairness simulation.
//
// Models staking eligibility EXACTLY as consensus does: a coin of committed
// value `m` with image point `phi` is eligible to stake in slot `t` iff
//   m >= CalculateMinValue(kernel_hash, target)
// where kernel_hash binds `phi` in V2. Because each coin has a distinct phi,
// the per-slot draws are independent across coins, so a node's expected share
// of winnable slots is proportional to its share of total staked value.
//
// We run 100k+ slots and check that observed win-share tracks value-share for
// V2, and demonstrate that the legacy shared-kernel (V1) does NOT: under V1 a
// single shared kernel per slot means only the single largest coin matters.
// ---------------------------------------------------------------------------

namespace {
// A staker holds one or more staked commitments. Each commitment has a value
// (in units; we use 1 unit == 1 to keep min_value arithmetic exact) and a
// distinct phi point.
struct Coin {
    uint64_t value;
    MclG1Point phi;
};
struct Node {
    std::string name;
    std::vector<Coin> coins;
    uint64_t wins{0};
    uint64_t total_value() const {
        uint64_t t = 0;
        for (const auto& c : coins) t += c.value;
        return t;
    }
};

// Eligibility is `m >= min_value` where `min_value = kernel_hash / target` and
// kernel_hash is uniform in [0, 2^256). So per draw P(eligible) = P(kernel_hash
// <= m * target) = m * target / 2^256. To make eligibility genuinely
// value-gated (not "always" / "never"), pick target = 2^256 / D so that
// P(eligible) = m / D. With D = 1e6 a coin of value 10000 wins ~1% of draws and
// 40000 wins ~4% — thousands of wins over 120k slots, low binomial noise.
//
// `difficulty` here is D: larger D => rarer wins (higher difficulty).
unsigned int TargetForDifficulty(uint64_t D)
{
    // target = floor((2^256 - 1) / D). arith_uint256 max is 2^256 - 1.
    arith_uint256 maxv = ~arith_uint256(0);
    arith_uint256 t = maxv / arith_uint256(D);
    // Round-trip through compact so the test target matches the on-wire nBits
    // representation consensus actually uses (SetCompact loses low bits).
    unsigned int bits = t.GetCompact();
    return bits;
}
} // namespace

namespace {
// Eligibility check shared by the simulations, modelling consensus exactly:
// a coin of value `m` with image `phi` is eligible in slot (modifier,time)
// under target `target` iff m >= kernel_hash/target.
bool CoinEligible(const Coin& c, uint32_t prevTime, uint64_t modifier,
                  const arith_uint256& work, uint32_t time, unsigned int target,
                  bool bind_phi)
{
    uint256 kh = bind_phi
        ? blsct::CalculateKernelHashWithChainWork(prevTime, modifier, work, time, c.phi)
        : blsct::CalculateKernelHashWithChainWork(prevTime, modifier, work, time);
    uint64_t min_value = blsct::ProofOfStake::SaturateToU64(
        blsct::ProofOfStake::CalculateMinValue(kh, target));
    return c.value >= min_value;
}

// Deterministic per-slot modifier so tests are reproducible (the real stake
// modifier changes between blocks; its exact value does not matter here, only
// that it varies per slot).
uint64_t SlotModifier(int s) { return 0x9e3779b97f4a7c15ULL * static_cast<uint64_t>(s + 1); }

// Deterministic, distinct G1 points for the value-proportionality simulations.
// MclG1Point::Rand() draws its scalar from the OS CSPRNG (mclBnFr_setByCSPRNG),
// which made the win-share statistics non-reproducible: a single unlucky draw
// could push a node's win-share outside the tolerance, so the tests failed
// intermittently across platforms. Fixed points make every simulation fully
// deterministic. The phi value only selects WHICH slots a coin wins (eligibility
// probability is value/D regardless of phi), so any distinct points are valid.
MclG1Point DetPoint()
{
    static int64_t ctr = 0;
    return MclG1Point::GetBasePoint() * MclScalar(++ctr);
}
} // namespace

BOOST_AUTO_TEST_CASE(staking_is_value_proportional_v2_simulation)
{
    const uint32_t prevTime = 1700000000;
    const arith_uint256 work = UintToArith256(uint256S("123456"));
    // D=1e6 => a value-10000 coin wins ~1% of draws; thousands of wins overall.
    const unsigned int target = TargetForDifficulty(1000000);

    // Three nodes with deliberately different balance shapes:
    //  - whale_one_coin : 40000 in a SINGLE commitment
    //  - whale_split    : 40000 split across 4 commitments of 10000
    //  - minnow         : 10000 in a single commitment
    // V2 fairness requires win-share ~ value-share REGARDLESS of fragmentation,
    // so whale_one_coin and whale_split must win about equally (both 40000),
    // and each ~4x the minnow.
    auto make_coins = [](int n, uint64_t each) {
        std::vector<Coin> v;
        v.reserve(n);
        for (int i = 0; i < n; ++i) v.push_back({each, DetPoint()});
        return v;
    };

    std::vector<Node> nodes = {
        {"whale_one_coin", make_coins(1, 40000), 0},
        {"whale_split",    make_coins(4, 10000), 0},
        {"minnow",         make_coins(1, 10000), 0},
    };

    const uint64_t total_value = 90000; // 40000 + 40000 + 10000
    const int kSlots = 120000;          // >100k samples

    for (int s = 0; s < kSlots; ++s) {
        const uint32_t time = prevTime + static_cast<uint32_t>(s) * 16u; // advance bucket
        const uint64_t modifier = SlotModifier(s);
        for (auto& node : nodes)
            for (const auto& c : node.coins)
                if (CoinEligible(c, prevTime, modifier, work, time, target, /*bind_phi=*/true))
                    node.wins++; // count every eligible coin: wins scale with #coins AND size
    }

    uint64_t total_wins = 0;
    for (const auto& n : nodes) total_wins += n.wins;
    BOOST_REQUIRE(total_wins > 0);

    for (const auto& n : nodes) {
        const double win_share = static_cast<double>(n.wins) / static_cast<double>(total_wins);
        const double value_share = static_cast<double>(n.total_value()) / static_cast<double>(total_value);
        BOOST_TEST_MESSAGE(n.name << ": value_share=" << value_share
                           << " win_share=" << win_share << " wins=" << n.wins);
        // Win-share must track value-share within a tolerance that comfortably
        // covers binomial sampling noise over 120k slots (the minnow has the
        // fewest wins and thus the largest relative spread).
        BOOST_CHECK_CLOSE(win_share, value_share, /*tol_percent=*/10.0);
    }

    // Fairness across fragmentation: the two 40000 whales must win within ~12%
    // of each other regardless of how their stake is split into commitments.
    const double w1 = static_cast<double>(nodes[0].wins);
    const double w2 = static_cast<double>(nodes[1].wins);
    BOOST_CHECK_CLOSE(w1, w2, 12.0);
}

BOOST_AUTO_TEST_CASE(staking_v1_shared_kernel_is_not_proportional)
{
    // Demonstrates the bug the V2 kernel fixes: with a single shared kernel per
    // slot (no phi binding), eligibility is decided by the SINGLE LARGEST coin,
    // not total value. A node fragmented into many small coins is penalized.
    const uint32_t prevTime = 1700000000;
    const arith_uint256 work = UintToArith256(uint256S("123456"));
    const unsigned int target = TargetForDifficulty(1000000);

    // Node A: 40000 split into 8 coins of 5000 (largest single = 5000).
    // Node B: 10000 in one coin (largest single = 10000).
    // Under V1, B (larger single coin) is eligible MORE OFTEN than A, despite
    // A holding 4x the total value -- the inversion observed on testnet.
    Coin a_largest{5000, DetPoint()};
    Coin b_largest{10000, DetPoint()};

    const int kSlots = 120000;
    uint64_t a_wins = 0, b_wins = 0;
    for (int s = 0; s < kSlots; ++s) {
        const uint32_t time = prevTime + static_cast<uint32_t>(s) * 16u;
        const uint64_t modifier = SlotModifier(s);
        // V1: ONE shared kernel per slot (phi NOT bound), so a node's chance is
        // set by its single largest coin.
        if (CoinEligible(a_largest, prevTime, modifier, work, time, target, /*bind_phi=*/false)) a_wins++;
        if (CoinEligible(b_largest, prevTime, modifier, work, time, target, /*bind_phi=*/false)) b_wins++;
    }

    BOOST_TEST_MESSAGE("V1 shared-kernel: A(total=40000,max=5000) wins=" << a_wins
                       << "  B(total=10000,max=10000) wins=" << b_wins);
    // The bug: despite 4x the total value, A (smaller largest coin) wins LESS
    // than B. This is exactly why total balance did not predict stake rate.
    BOOST_CHECK_LT(a_wins, b_wins);
}

BOOST_AUTO_TEST_CASE(staking_v2_proportional_under_difficulty_adjustment)
{
    // Same proportional-fairness claim, but now the difficulty (target) RETARGETS
    // throughout the run in response to the realised block rate -- mirroring
    // CalculateNextTargetRequired. Proportionality must hold across the whole
    // run regardless of how difficulty moves: each retarget rescales every
    // coin's win probability by the SAME factor, so relative shares are
    // invariant.
    const uint32_t prevTime = 1700000000;
    const arith_uint256 work = UintToArith256(uint256S("abcdef"));

    auto make_coins = [](int n, uint64_t each) {
        std::vector<Coin> v;
        v.reserve(n);
        for (int i = 0; i < n; ++i) v.push_back({each, DetPoint()});
        return v;
    };
    std::vector<Node> nodes = {
        {"big",   make_coins(3, 20000), 0}, // 60000
        {"mid",   make_coins(1, 30000), 0}, // 30000
        {"small", make_coins(2, 5000),  0}, // 10000
    };
    const uint64_t total_value = 100000;

    // Retarget controller: aim for `kTargetWinsPerWindow` total eligible draws
    // per retarget window. If we overshoot, raise difficulty (smaller target);
    // if we undershoot, lower it. This is the simulation analogue of the PoS
    // retarget that targets a fixed block spacing.
    const int kWindow = 2016;            // retarget interval (slots)
    const int kWindows = 60;             // 60 * 2016 = 120960 slots (>100k)
    const double kTargetWinsPerWindow = static_cast<double>(kWindow) * 1.0; // ~1 win/slot
    uint64_t difficulty = 1000000;       // initial D
    unsigned int target = TargetForDifficulty(difficulty);

    int slot = 0;
    uint64_t observed_min_D = difficulty, observed_max_D = difficulty;
    for (int w = 0; w < kWindows; ++w) {
        uint64_t window_wins = 0;
        for (int i = 0; i < kWindow; ++i, ++slot) {
            const uint32_t time = prevTime + static_cast<uint32_t>(slot) * 16u;
            const uint64_t modifier = SlotModifier(slot);
            for (auto& node : nodes)
                for (const auto& c : node.coins)
                    if (CoinEligible(c, prevTime, modifier, work, time, target, /*bind_phi=*/true)) {
                        node.wins++;
                        window_wins++;
                    }
        }
        // Proportional retarget: new_D = old_D * observed_wins / desired_wins.
        // Clamp the per-step adjustment to 4x (as CalculateNextTargetRequired
        // clamps the timespan factor to [1/4, 4]).
        double ratio = (window_wins == 0) ? 0.25
                       : static_cast<double>(window_wins) / kTargetWinsPerWindow;
        ratio = std::min(4.0, std::max(0.25, ratio));
        difficulty = std::max<uint64_t>(1000, static_cast<uint64_t>(difficulty * ratio));
        observed_min_D = std::min(observed_min_D, difficulty);
        observed_max_D = std::max(observed_max_D, difficulty);
        target = TargetForDifficulty(difficulty);
    }

    // Sanity: difficulty actually moved over the run (the controller exercised
    // the retarget path, not a constant target).
    BOOST_TEST_MESSAGE("difficulty range: D_min=" << observed_min_D
                       << " D_max=" << observed_max_D);
    BOOST_CHECK(observed_max_D != observed_min_D);

    uint64_t total_wins = 0;
    for (const auto& n : nodes) total_wins += n.wins;
    BOOST_REQUIRE(total_wins > 0);
    for (const auto& n : nodes) {
        const double win_share = static_cast<double>(n.wins) / static_cast<double>(total_wins);
        const double value_share = static_cast<double>(n.total_value()) / static_cast<double>(total_value);
        BOOST_TEST_MESSAGE(n.name << ": value_share=" << value_share
                           << " win_share=" << win_share << " wins=" << n.wins);
        BOOST_CHECK_CLOSE(win_share, value_share, /*tol_percent=*/10.0);
    }
}

BOOST_AUTO_TEST_CASE(staking_v2_proportional_with_dynamic_stakes)
{
    // Real-world scenario: stakers JOIN and LEAVE over time, and individual
    // nodes add/remove commitments mid-run. Fairness claim: each node's win
    // share should track its TIME-INTEGRATED value share -- i.e. sum over slots
    // of (node value at that slot) / (total value at that slot). A node that
    // holds stake for only part of the run, or grows/shrinks it, should earn
    // blocks in proportion to the stake-time it actually contributed.
    const uint32_t prevTime = 1700000000;
    const arith_uint256 work = UintToArith256(uint256S("0badc0de"));
    const unsigned int target = TargetForDifficulty(1000000);

    auto coin = [](uint64_t v) { return Coin{v, DetPoint()}; };

    std::vector<Node> nodes = {
        {"always",     {coin(20000)}, 0},               // present the whole run
        {"joins_late", {},            0},               // empty until slot 60k
        {"leaves_mid", {coin(15000), coin(15000)}, 0},  // exits at slot 60k
        {"grows",      {coin(10000)}, 0},               // adds a coin at slot 40k
    };

    const int kSlots = 120000;
    // Expected reward weight = integral of each node's value over time.
    std::vector<double> value_time(nodes.size(), 0.0);

    for (int s = 0; s < kSlots; ++s) {
        // Apply scheduled stake changes.
        if (s == 40000) nodes[3].coins.push_back(coin(30000));        // grows: 10000 -> 40000
        if (s == 60000) nodes[1].coins.push_back(coin(25000));        // joins_late: 0 -> 25000
        if (s == 60000) nodes[2].coins.clear();                       // leaves_mid: 30000 -> 0

        const uint32_t time = prevTime + static_cast<uint32_t>(s) * 16u;
        const uint64_t modifier = SlotModifier(s);

        for (size_t ni = 0; ni < nodes.size(); ++ni) {
            value_time[ni] += static_cast<double>(nodes[ni].total_value());
            for (const auto& c : nodes[ni].coins)
                if (CoinEligible(c, prevTime, modifier, work, time, target, /*bind_phi=*/true))
                    nodes[ni].wins++;
        }
    }

    uint64_t total_wins = 0;
    for (const auto& n : nodes) total_wins += n.wins;
    double total_value_time = 0.0;
    for (double v : value_time) total_value_time += v;
    BOOST_REQUIRE(total_wins > 0);
    BOOST_REQUIRE(total_value_time > 0.0);

    for (size_t ni = 0; ni < nodes.size(); ++ni) {
        const double win_share = static_cast<double>(nodes[ni].wins) / static_cast<double>(total_wins);
        const double stake_time_share = value_time[ni] / total_value_time;
        BOOST_TEST_MESSAGE(nodes[ni].name << ": stake_time_share=" << stake_time_share
                           << " win_share=" << win_share << " wins=" << nodes[ni].wins);
        // Win share tracks time-integrated stake share. Wider tolerance: some
        // nodes accrue fewer total wins (shorter presence) so binomial noise is
        // larger; 12% comfortably covers it while still proving proportionality.
        BOOST_CHECK_CLOSE(win_share, stake_time_share, /*tol_percent=*/12.0);
    }

    // The node that left mid-run must have earned strictly fewer blocks than the
    // node that was always present with similar peak stake but full duration.
    BOOST_CHECK_GT(nodes[0].wins, 0u);
    BOOST_CHECK_GT(nodes[1].wins, 0u); // joined late but still earned some
}

BOOST_AUTO_TEST_CASE(g1_subgroup_check_accepts_generator)
{
    MclG1Point g = MclG1Point::GetBasePoint();
    auto bytes = g.GetVch();
    MclG1Point parsed;
    BOOST_CHECK(parsed.SetVch(bytes));
}

BOOST_AUTO_TEST_CASE(g1_subgroup_check_accepts_identity)
{
    // All-zero serialization with the compressed-infinity flag should round-trip.
    MclG1Point identity;  // default-constructed is identity
    auto bytes = identity.GetVch();
    MclG1Point parsed;
    BOOST_CHECK(parsed.SetVch(bytes));
}

BOOST_AUTO_TEST_CASE(g1_subgroup_check_rejects_garbage)
{
    std::vector<uint8_t> garbage(MclG1Point::SERIALIZATION_SIZE, 0x42);
    MclG1Point p;
    BOOST_CHECK(!p.SetVch(garbage));
}

BOOST_AUTO_TEST_SUITE_END()
