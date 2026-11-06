// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/pos/pos.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <headerssync.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <validation.h>
#include <vector>

#include <boost/test/unit_test.hpp>

struct HeadersGeneratorSetup : public RegTestingSetup {
    /** Search for a nonce to meet (regtest) proof of work */
    void FindProofOfWork(CBlockHeader& starting_header);
    /**
     * Generate headers in a chain that build off a given starting hash, using
     * the given nVersion, advancing time by 1 second from the starting
     * prev_time, and with a fixed merkle root hash.
     */
    void GenerateHeaders(std::vector<CBlockHeader>& headers, size_t count,
            const uint256& starting_hash, int nVersion, int prev_time,
            const uint256& merkle_root, uint32_t nBits);
};

void HeadersGeneratorSetup::FindProofOfWork(CBlockHeader& starting_header)
{
    while (!CheckProofOfWork(starting_header.GetHash(), starting_header.nBits, Params().GetConsensus())) {
        ++(starting_header.nNonce);
    }
}

void HeadersGeneratorSetup::GenerateHeaders(std::vector<CBlockHeader>& headers,
        size_t count, const uint256& starting_hash, const int nVersion, int prev_time,
        const uint256& merkle_root, const uint32_t nBits)
{
    uint256 prev_hash = starting_hash;

    while (headers.size() < count) {
        headers.emplace_back();
        CBlockHeader& next_header = headers.back();;
        next_header.nVersion = nVersion;
        next_header.hashPrevBlock = prev_hash;
        next_header.hashMerkleRoot = merkle_root;
        next_header.nTime = prev_time+1;
        next_header.nBits = nBits;

        FindProofOfWork(next_header);
        prev_hash = next_header.GetHash();
        prev_time = next_header.nTime;
    }
    return;
}

BOOST_FIXTURE_TEST_SUITE(headers_sync_chainwork_tests, HeadersGeneratorSetup)

// In this test, we construct two sets of headers from genesis, one with
// sufficient proof of work and one without.
// 1. We deliver the first set of headers and verify that the headers sync state
//    updates to the REDOWNLOAD phase successfully.
// 2. Then we deliver the second set of headers and verify that they fail
//    processing (presumably due to commitments not matching).
// 3. Finally, we verify that repeating with the first set of headers in both
//    phases is successful.
BOOST_AUTO_TEST_CASE(headers_sync_state)
{
    std::vector<CBlockHeader> first_chain;
    std::vector<CBlockHeader> second_chain;

    std::unique_ptr<HeadersSyncState> hss;

    const int target_blocks = 15000;
    arith_uint256 chain_work = target_blocks*2;

    // Generate headers for two different chains (using differing merkle roots
    // to ensure the headers are different).
    GenerateHeaders(first_chain, target_blocks-1, Params().GenesisBlock().GetHash(),
            Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
            ArithToUint256(0), Params().GenesisBlock().nBits);

    GenerateHeaders(second_chain, target_blocks-2, Params().GenesisBlock().GetHash(),
            Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
            ArithToUint256(1), Params().GenesisBlock().nBits);

    const CBlockIndex* chain_start = WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(Params().GenesisBlock().GetHash()));
    std::vector<CBlockHeader> headers_batch;

    // Feed the first chain to HeadersSyncState, by delivering 1 header
    // initially and then the rest.
    headers_batch.insert(headers_batch.end(), std::next(first_chain.begin()), first_chain.end());

    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders({first_chain.front()}, true);
    // Pretend the first header is still "full", so we don't abort.
    auto result = hss->ProcessNextHeaders(headers_batch, true);

    // This chain should look valid, and we should have met the proof-of-work
    // requirement.
    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    // Try to sneakily feed back the second chain.
    result = hss->ProcessNextHeaders(second_chain, true);
    BOOST_CHECK(!result.success); // foiled!
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Now try again, this time feeding the first chain twice.
    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders(first_chain, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    result = hss->ProcessNextHeaders(first_chain, true);
    BOOST_CHECK(result.success);
    BOOST_CHECK(!result.request_more);
    // All headers should be ready for acceptance:
    BOOST_CHECK(result.pow_validated_headers.size() == first_chain.size());
    // Nothing left for the sync logic to do:
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Finally, verify that just trying to process the second chain would not
    // succeed (too little work)
    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);
     // Pretend just the first message is "full", so we don't abort.
    (void)hss->ProcessNextHeaders({second_chain.front()}, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);

    headers_batch.clear();
    headers_batch.insert(headers_batch.end(), std::next(second_chain.begin(), 1), second_chain.end());
    // Tell the sync logic that the headers message was not full, implying no
    // more headers can be requested. For a low-work-chain, this should causes
    // the sync to end with no headers for acceptance.
    result = hss->ProcessNextHeaders(headers_batch, false);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);
    BOOST_CHECK(result.pow_validated_headers.empty());
    BOOST_CHECK(!result.request_more);
    // Nevertheless, no validation errors should have been detected with the
    // chain:
    BOOST_CHECK(result.success);
}

// A low-work mainnet headers chain crossing a proof-of-stake retarget stays in
// presync: the retarget is a permitted difficulty transition.
BOOST_AUTO_TEST_CASE(headers_sync_pos_retarget)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    const int retarget_height{150};
    BOOST_REQUIRE(retarget_height > consensus.nLastPOWHeight);
    BOOST_REQUIRE_EQUAL(retarget_height % consensus.DifficultyAdjustmentIntervalPos(), 0);

    // Mainnet's nBits before and at that retarget.
    CBlockHeader start_header;
    start_header.nTime = 1700000000;
    start_header.nBits = 0x1f00ffff;
    CBlockIndex chain_start{start_header};
    chain_start.nHeight = retarget_height - 1;
    const uint256 start_hash{chain_start.GetBlockHeader().GetHash()};
    chain_start.phashBlock = &start_hash;

    std::vector<CBlockHeader> headers(2);
    headers[0].hashPrevBlock = start_hash;
    headers[0].nTime = start_header.nTime + 1;
    headers[0].nBits = 0x1e3fffc0;
    headers[1].hashPrevBlock = headers[0].GetHash();
    headers[1].nTime = headers[0].nTime + 1;
    headers[1].nBits = headers[0].nBits;

    HeadersSyncState hss{0, consensus, &chain_start, /*minimum_required_work=*/~arith_uint256{0}};
    const auto result{hss.ProcessNextHeaders(headers, /*full_headers_message=*/true)};
    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(hss.GetState() == HeadersSyncState::State::PRESYNC);
}

namespace {
//! Recent mainnet proof-of-stake nBits, and its average block spacing.
constexpr uint32_t MAINNET_POS_NBITS{0x1a1a1c79};
constexpr int64_t MAINNET_POS_SPACING{130};

//! Appends a block index entry on `prev` (none for a genesis).
CBlockIndex* AddIndex(std::vector<std::unique_ptr<CBlockIndex>>& store, CBlockIndex* prev, uint32_t time, uint32_t nbits)
{
    CBlockHeader header;
    header.nTime = time;
    header.nBits = nbits;
    auto& index{store.emplace_back(std::make_unique<CBlockIndex>(header))};
    index->pprev = prev;
    index->nHeight = prev ? prev->nHeight + 1 : 0;
    index->nChainWork = (prev ? prev->nChainWork : arith_uint256{0}) + GetBlockProof(*index);
    index->BuildSkip();
    return index.get();
}

//! A chain on mainnet's rules: PoW blocks at the PoW limit up to
//! nLastPOWHeight, then `pos_blocks` proof-of-stake blocks at recent mainnet
//! difficulty and spacing.
CBlockIndex* BuildMainnetLikeChain(std::vector<std::unique_ptr<CBlockIndex>>& store, const Consensus::Params& consensus, int pos_blocks)
{
    const uint32_t pow_nbits{UintToArith256(consensus.powLimit).GetCompact()};
    CBlockIndex* tip{AddIndex(store, nullptr, 1700000000, pow_nbits)};
    while (tip->nHeight < consensus.nLastPOWHeight) tip = AddIndex(store, tip, tip->nTime + 600, pow_nbits);
    for (int i = 0; i < pos_blocks; ++i) tip = AddIndex(store, tip, tip->nTime + MAINNET_POS_SPACING, MAINNET_POS_NBITS);
    return tip;
}

//! Free headers built on `fork`, the i-th (from 1) timestamped time_of(i),
//! each at the target the proof-of-stake retarget gives. Records where the
//! chain passes the anti-DoS threshold (the tip's work less
//! ANTI_DOS_FORK_DEPTH of its blocks), where it overtakes the tip, and where
//! `limit` first refuses it. Stops after max_headers or once time_of passes
//! `end_time`.
struct FakeChain {
    int headers{0};
    int passes_threshold_at{-1};
    int overtakes_at{-1};
    int refused_at{-1};
    double claimed_tip_blocks{0}; // its work since the fork, in tip blocks
};
template <typename TimeOf>
FakeChain BuildFakeChain(CBlockIndex* fork, const CBlockIndex& tip, const Consensus::Params& consensus,
                         const HeadersWorkRateLimit& limit, int64_t now, TimeOf time_of, int max_headers, int64_t end_time)
{
    std::vector<std::unique_ptr<CBlockIndex>> store;
    const arith_uint256 tip_proof{GetBlockProof(tip)};
    const arith_uint256 threshold{tip.nChainWork - tip_proof * 144};
    FakeChain fake;
    CBlockIndex* last{fork};
    for (int i = 1; i <= max_headers && time_of(i) <= end_time; ++i) {
        CBlockHeader next;
        next.nTime = time_of(i);
        last = AddIndex(store, last, next.nTime, blsct::GetNextTargetRequired(last, &next, consensus));
        fake.headers = i;
        const arith_uint256 work{last->nChainWork - fork->nChainWork};
        if (fake.passes_threshold_at < 0 && last->nChainWork >= threshold) fake.passes_threshold_at = i;
        if (fake.overtakes_at < 0 && last->nChainWork > tip.nChainWork) fake.overtakes_at = i;
        if (fake.refused_at < 0 && !limit.Allows(*fork, work, last->nTime, now)) fake.refused_at = i;
        fake.claimed_tip_blocks = (work / tip_proof).getdouble();
    }
    return fake;
}
} // namespace

// The rate limit lets honest proof-of-stake headers through, bursts included,
// and refuses a free chain whose packed timestamps ramp its difficulty.
BOOST_AUTO_TEST_CASE(headers_work_rate_limit)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    std::vector<std::unique_ptr<CBlockIndex>> store;
    CBlockIndex* tip{BuildMainnetLikeChain(store, consensus, 400)};
    const HeadersWorkRateLimit limit{tip, consensus};
    BOOST_REQUIRE(limit.IsActive());
    const arith_uint256 proof{GetBlockProof(*tip)};
    const int64_t now{tip->GetBlockTime()};

    // Not enough proof-of-stake history, or a chain without BLSCT: no limit.
    BOOST_CHECK(!HeadersWorkRateLimit(tip->GetAncestor(consensus.nLastPOWHeight + 299), consensus).IsActive());
    BOOST_CHECK(!HeadersWorkRateLimit(nullptr, consensus).IsActive());
    auto no_blsct{consensus};
    no_blsct.fBLSCT = false;
    BOOST_CHECK(!HeadersWorkRateLimit(tip, no_blsct).IsActive());

    // A full batch of honest headers, and a burst of 100 blocks in 100 s.
    BOOST_CHECK(limit.Allows(*tip, proof * 2000, now + 2000 * MAINNET_POS_SPACING, now + 2000 * MAINNET_POS_SPACING));
    BOOST_CHECK(limit.Allows(*tip, proof * 100, now + 100, now));
    // Four times our rate over the span plus the slack is the most allowed.
    const int64_t span{2000 * MAINNET_POS_SPACING};
    const arith_uint256 our_work{tip->nChainWork - tip->GetAncestor(tip->nHeight - 300)->nChainWork};
    const int64_t our_seconds{tip->GetBlockTime() - tip->GetAncestor(tip->nHeight - 300)->GetBlockTime()};
    const arith_uint256 cap{our_work * 4 / arith_uint256{static_cast<uint64_t>(our_seconds)} * arith_uint256{static_cast<uint64_t>(span + consensus.nPosTargetTimespan)}};
    BOOST_CHECK(limit.Allows(*tip, cap, now + span, now + span));
    BOOST_CHECK(!limit.Allows(*tip, cap + 1, now + span, now + span));
    // Timestamps past MAX_FUTURE_BLOCK_TIME buy no time.
    BOOST_CHECK(!limit.Allows(*tip, cap, now + span, now + span - MAX_FUTURE_BLOCK_TIME - 1));
    // Headers built on the proof-of-work part are not limited.
    BOOST_CHECK(limit.Allows(*tip->GetAncestor(consensus.nLastPOWHeight), proof * 1000000, now, now));

    // A free chain with packed timestamps is refused before it can pass the
    // anti-DoS threshold on a deep fork.
    CBlockIndex* fork{tip->GetAncestor(tip->nHeight - 300)};
    const auto fake{BuildFakeChain(fork, *tip, consensus, limit, now, [&](int i) { return fork->nTime + i; }, 2000, now + MAX_FUTURE_BLOCK_TIME)};
    BOOST_REQUIRE(fake.passes_threshold_at > 0);
    BOOST_REQUIRE(fake.refused_at > 0);
    BOOST_CHECK_LT(fake.refused_at, fake.passes_threshold_at);
}

// Presync aborts at the first header of a chain that claims work too fast.
BOOST_AUTO_TEST_CASE(headers_sync_work_rate)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    std::vector<std::unique_ptr<CBlockIndex>> store;
    CBlockIndex* tip{BuildMainnetLikeChain(store, consensus, 400)};
    std::vector<uint256> hashes;
    hashes.reserve(store.size());
    for (auto& index : store) index->phashBlock = &hashes.emplace_back(index->GetBlockHeader().GetHash());
    CBlockIndex* fork{tip->GetAncestor(tip->nHeight - 300)};

    // Packed timestamps, with each retarget as the proof-of-stake rule gives.
    std::vector<std::unique_ptr<CBlockIndex>> fake_store;
    std::vector<CBlockHeader> headers;
    CBlockIndex* last{fork};
    for (int i = 1; i <= 300; ++i) {
        CBlockHeader next;
        next.hashPrevBlock = last == fork ? fork->GetBlockHash() : headers.back().GetHash();
        next.nTime = fork->nTime + i;
        next.nBits = blsct::GetNextTargetRequired(last, &next, consensus);
        headers.push_back(next);
        last = AddIndex(fake_store, last, next.nTime, next.nBits);
    }

    const auto sync = [&](const HeadersWorkRateLimit& limit) {
        HeadersSyncState hss{0, consensus, fork, /*minimum_required_work=*/~arith_uint256{0}, limit};
        return hss.ProcessNextHeaders(headers, /*full_headers_message=*/true).success;
    };
    BOOST_CHECK(sync(HeadersWorkRateLimit{}));
    BOOST_CHECK(!sync(HeadersWorkRateLimit{tip, consensus}));
}

// What free proof-of-stake headers can do to a mainnet node, with and without
// the rate limit: run with --log_level=message to print the figures. Checks
// that a packed chain is refused before it overtakes the tip or, from a deep
// fork, before it passes the anti-DoS threshold.
BOOST_AUTO_TEST_CASE(headers_work_rate_figures)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    std::vector<std::unique_ptr<CBlockIndex>> store;
    CBlockIndex* tip{BuildMainnetLikeChain(store, consensus, 2500)};
    const HeadersWorkRateLimit limit{tip, consensus};
    const int64_t now{tip->GetBlockTime()};
    const int64_t end{now + MAX_FUTURE_BLOCK_TIME};
    BOOST_TEST_MESSAGE("sizeof(CBlockIndex)=" << sizeof(CBlockIndex));
    for (const int depth : {0, 144, 2000}) {
        CBlockIndex* fork{tip->GetAncestor(tip->nHeight - depth)};
        const auto packed{BuildFakeChain(fork, *tip, consensus, limit, now, [&](int i) { return fork->nTime + i; }, 3000, end)};
        const auto paced{BuildFakeChain(fork, *tip, consensus, limit, now, [&](int i) { return fork->nTime + 120 * i; }, 1000000, end)};
        BOOST_TEST_MESSAGE("fork depth " << depth << ": MTP bound on headers a chain may hold " << 6 * (end - fork->GetBlockTime()));
        BOOST_TEST_MESSAGE("  packed 1s: threshold at " << packed.passes_threshold_at << ", overtakes at " << packed.overtakes_at
                           << ", refused at " << packed.refused_at << ", " << packed.headers << " headers claim " << packed.claimed_tip_blocks << " tip blocks");
        BOOST_TEST_MESSAGE("  paced 120s to now+2h: threshold at " << paced.passes_threshold_at << ", overtakes at " << paced.overtakes_at
                           << ", refused at " << paced.refused_at << ", " << paced.headers << " headers claim " << paced.claimed_tip_blocks << " tip blocks");
        BOOST_CHECK_GT(packed.refused_at, 0);
        if (depth > 0) BOOST_CHECK_LT(packed.refused_at, packed.overtakes_at);
        if (depth > 144) BOOST_CHECK_LT(packed.refused_at, packed.passes_threshold_at);
    }
}

BOOST_AUTO_TEST_SUITE_END()
