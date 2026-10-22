// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/pir.h>

#include <chain.h>
#include <chainparams.h>
#include <hash.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <streams.h>
#include <util/thread.h>
#include <validation.h>

#include <limits>
#include <numeric>

namespace node {

uint256 PirEpochSeed(const uint256& genesis_hash, uint32_t epoch)
{
    return (HashWriter{} << std::string{"navio/simplepir/A/v1"} << genesis_hash << epoch).GetHash();
}

std::vector<uint8_t> EncodeOutputRecord(const CTxOut& out)
{
    std::vector<uint8_t> record(PIR_RECORD_BYTES, 0);
    DataStream ss;
    ss << out;
    if (ss.size() > PIR_RECORD_BYTES - PIR_RECORD_HEADER) {
        record[0] = PIR_RECORD_OVERSIZED;
        return record;
    }
    record[0] = PIR_RECORD_OUTPUT;
    record[1] = ss.size() & 0xff;
    record[2] = ss.size() >> 8;
    std::memcpy(record.data() + PIR_RECORD_HEADER, ss.data(), ss.size());
    return record;
}

std::optional<CTxOut> DecodeOutputRecord(Span<const uint8_t> record)
{
    if (record.size() < PIR_RECORD_HEADER || record[0] != PIR_RECORD_OUTPUT) return std::nullopt;
    const size_t len{size_t{record[1]} | size_t{record[2]} << 8};
    if (len > record.size() - PIR_RECORD_HEADER) return std::nullopt;
    try {
        DataStream ss{record.subspan(PIR_RECORD_HEADER, len)};
        CTxOut out;
        ss >> out;
        if (!ss.empty()) return std::nullopt;
        return out;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

void AppendBlockRecords(const CBlock& block, std::vector<std::vector<uint8_t>>& out)
{
    // Same selection and order as BuildBlockOutKeys.
    for (const auto& tx : block.vtx) {
        for (const CTxOut& txout : tx->vout) {
            if (!txout.HasBLSCTKeys()) continue;
            out.push_back(EncodeOutputRecord(txout));
        }
    }
}

void PirBudget::Refill(NodeClock::time_point now)
{
    if (now > m_last) {
        const double secs{std::chrono::duration<double>(now - m_last).count()};
        m_tokens = std::min(double(m_capacity), m_tokens + secs * double(m_per_second));
    }
    m_last = now;
}

bool PirBudget::TryConsume(uint64_t cost, NodeClock::time_point now)
{
    Refill(now);
    if (m_tokens < double(cost)) return false;
    m_tokens -= double(cost);
    return true;
}

void PirBudget::Charge(uint64_t cost, NodeClock::time_point now)
{
    Refill(now);
    m_tokens -= double(cost);
}

bool PirBudget::InDebt(NodeClock::time_point now)
{
    Refill(now);
    return m_tokens < 0;
}

PirServer::PirServer(ChainstateManager& chainman, const Options& opts)
    : m_chainman{chainman},
      m_opts{opts},
      m_genesis{chainman.GetParams().GenesisBlock().GetHash()},
      m_global_budget{PIR_GLOBAL_BUDGET, PIR_GLOBAL_BUDGET / 16, PIR_GLOBAL_BUDGET, NodeClock::now()}
{
    Assert(opts.epoch_blocks > 0 && opts.epoch_blocks <= MAX_PIR_EPOCH_BLOCKS);
    Assert(opts.max_epochs > 0);
    m_thread = std::thread{&util::TraceThread, "pirbuild", [this] { BuildThread(); }};
}

PirServer::~PirServer()
{
    {
        LOCK(m_mutex);
        m_interrupt = true;
    }
    m_queue_cv.notify_all();
    m_thread.join();
}

PirBudget& PirServer::PeerBudget(int64_t peer, NodeClock::time_point now)
{
    auto it{m_peer_budgets.find(peer)};
    if (it == m_peer_budgets.end()) {
        it = m_peer_budgets.emplace(peer, PirBudget{m_opts.peer_budget, m_opts.peer_budget / 8, m_opts.peer_budget / PIR_PEER_START_DIVISOR, now}).first;
    }
    return it->second;
}

void PirServer::ForgetPeer(int64_t peer)
{
    LOCK(m_budget_mutex);
    m_peer_budgets.erase(peer);
}

void PirServer::SyncWithBuilds()
{
    WAIT_LOCK(m_mutex, lock);
    m_idle_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_interrupt || (m_queue.empty() && !m_building); });
}

PirServer::EpochRef PirServer::Lookup(uint32_t epoch)
{
    LOCK(m_mutex);
    auto it{std::find_if(m_epochs.begin(), m_epochs.end(), [&](const auto& e) { return e->epoch == epoch; })};
    if (it == m_epochs.end()) return nullptr;
    m_epochs.splice(m_epochs.begin(), m_epochs, it);
    return m_epochs.front();
}

PirServer::Status PirServer::RequestBuild(int64_t peer, uint32_t epoch, const uint256& tip)
{
    LOCK(m_mutex);
    if (const auto it{m_failed.find(epoch)}; it != m_failed.end() && it->second == tip) return Status::UNAVAILABLE;
    if (m_building == epoch || std::find(m_queue.begin(), m_queue.end(), epoch) != m_queue.end()) return Status::BUSY;
    if (m_queue.size() >= m_opts.max_epochs) return Status::BUSY;
    {
        LOCK(m_budget_mutex);
        const auto now{NodeClock::now()};
        if (!PeerBudget(peer, now).TryConsume(m_opts.peer_budget / PIR_BUILD_CHARGE_DIVISOR, now)) return Status::BUSY;
    }
    m_queue.push_back(epoch);
    m_queue_cv.notify_one();
    return Status::BUSY;
}

void PirServer::BuildThread()
{
    while (true) {
        uint32_t epoch;
        EpochRef base;
        {
            WAIT_LOCK(m_mutex, lock);
            m_building.reset();
            if (m_queue.empty()) m_idle_cv.notify_all();
            m_queue_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(m_mutex) { return m_interrupt || !m_queue.empty(); });
            if (m_interrupt) {
                m_idle_cv.notify_all();
                return;
            }
            epoch = m_queue.front();
            m_queue.pop_front();
            m_building = epoch;
            const auto it{std::find_if(m_epochs.begin(), m_epochs.end(), [&](const auto& e) { return e->epoch == epoch; })};
            if (it != m_epochs.end()) base = *it;
        }

        EpochRef built;
        uint256 tip;
        const BuildResult result{Build(epoch, base, built, tip)};

        LOCK(m_mutex);
        if (result == BuildResult::BUILT) {
            const auto it{std::find_if(m_epochs.begin(), m_epochs.end(), [&](const auto& e) { return e->epoch == epoch; })};
            if (it != m_epochs.end()) m_epochs.erase(it);
            m_epochs.push_front(std::move(built));
            while (m_epochs.size() > m_opts.max_epochs) m_epochs.pop_back();
            m_failed.erase(epoch);
        } else if (result == BuildResult::FAILED) {
            m_failed[epoch] = tip;
        }
    }
}

PirServer::BuildResult PirServer::Build(uint32_t epoch, const EpochRef& base, EpochRef& out, uint256& tip)
{
    const uint64_t start{uint64_t{epoch} * m_opts.epoch_blocks};

    // Which blocks to add, and whether the cached version is a prefix of the
    // active chain that can be extended.
    std::vector<const CBlockIndex*> todo;
    bool extend{false};
    {
        LOCK(::cs_main);
        const CChain& chain{m_chainman.ActiveChain()};
        tip = chain.Tip()->GetBlockHash();
        if (start > uint64_t(chain.Height())) return BuildResult::CURRENT; // the chain shrank; nothing to serve
        const uint32_t end{uint32_t(std::min<uint64_t>(start + m_opts.epoch_blocks - 1, chain.Height()))};
        uint32_t from{uint32_t(start)};
        if (base && base->end_height <= end) {
            const CBlockIndex* anchor{chain[base->end_height]};
            if (anchor && anchor->GetBlockHash() == base->anchor_hash) {
                extend = true;
                from = base->end_height + 1;
            }
        }
        if (extend && from > end) return BuildResult::CURRENT;
        for (uint32_t h = from; h <= end; ++h) {
            const CBlockIndex* pindex{chain[h]};
            if (!(pindex->nStatus & BLOCK_HAVE_DATA)) {
                LogPrintf("pir: cannot build epoch %u: no data for block %s\n", epoch, pindex->GetBlockHash().ToString());
                return BuildResult::FAILED;
            }
            todo.push_back(pindex);
        }
    }

    std::vector<std::vector<uint8_t>> records;
    std::vector<uint32_t> counts;
    for (const CBlockIndex* pindex : todo) {
        if (m_interrupt) return BuildResult::INTERRUPTED;
        CBlock block;
        if (!m_chainman.m_blockman.ReadBlockFromDisk(block, *pindex)) {
            LogPrintf("pir: cannot build epoch %u: failed to read block %s\n", epoch, pindex->GetBlockHash().ToString());
            return BuildResult::FAILED;
        }
        const size_t before{records.size()};
        AppendBlockRecords(block, records);
        counts.push_back(records.size() - before);
    }

    // Refuse an epoch too large for one database (about 29M records with the
    // default record size); ComputeHint and ExtendHint require a valid shape.
    const uint32_t old_records{extend ? base->db.GetParams().num_records : 0};
    const uint64_t total{uint64_t{old_records} + records.size()};
    const uint32_t k{pir::ChooseRecordsPerCol(uint32_t(std::min<uint64_t>(total, std::numeric_limits<uint32_t>::max())))};
    if (total > std::numeric_limits<uint32_t>::max() || !pir::Params{PIR_RECORD_BYTES, uint32_t(total), k}.IsValid()) {
        LogPrintf("pir: cannot build epoch %u: %u records are more than one database holds; lower -pirepochblocks\n", epoch, total);
        return BuildResult::FAILED;
    }

    // Build into a new snapshot. If the cached version keeps its shape, copy
    // it and extend its hint; otherwise start over with the new shape.
    auto next{std::make_shared<PirEpoch>()};
    const size_t hint_size{size_t{PIR_RECORD_BYTES} * k * pir::LWE_N};
    const bool keep{extend && base->db.GetParams().records_per_col == k && base->hint.size() == hint_size};
    if (keep) {
        *next = *base;
    } else {
        next->epoch = epoch;
        next->start_height = uint32_t(start);
        next->seed = PirEpochSeed(m_genesis, epoch);
        next->db = pir::Database{PIR_RECORD_BYTES, k};
        if (extend) next->block_counts = base->block_counts;
        if (total > 0) next->hint.assign(hint_size, 0);
    }
    next->db.Reserve(uint32_t(total));
    // Append and hash in chunks so that shutdown does not wait for a whole build.
    constexpr size_t CHUNK{4096};
    const auto add{[&](size_t count, const auto& record_at) {
        for (size_t i = 0; i < count;) {
            if (m_interrupt) return false;
            const uint32_t before{next->db.GetParams().num_records};
            for (const size_t stop{std::min(count, i + CHUNK)}; i < stop; ++i) next->db.Append(record_at(i));
            pir::ExtendHint(next->hint, next->db, next->seed, before);
        }
        return true;
    }};
    if (extend && !keep && !add(old_records, [&](size_t i) { return base->db.Record(uint32_t(i)); })) return BuildResult::INTERRUPTED;
    if (!add(records.size(), [&](size_t i) { return Span<const uint8_t>{records[i]}; })) return BuildResult::INTERRUPTED;
    next->block_counts.insert(next->block_counts.end(), counts.begin(), counts.end());
    next->end_height = todo.back()->nHeight;
    next->anchor_hash = todo.back()->GetBlockHash();
    LogPrint(BCLog::NET, "pir: epoch %u now at height %u with %u records\n", epoch, next->end_height, total);
    out = std::move(next);
    return BuildResult::BUILT;
}

PirServer::Status PirServer::GetHint(int64_t peer, uint32_t epoch, std::vector<PirHintMsg>& out)
{
    {
        LOCK(m_budget_mutex);
        if (m_global_budget.InDebt(NodeClock::now())) return Status::BUSY;
    }
    const EpochRef e{Lookup(epoch)};
    bool current;
    uint256 tip;
    {
        LOCK(::cs_main);
        const CChain& chain{m_chainman.ActiveChain()};
        const uint64_t start{uint64_t{epoch} * m_opts.epoch_blocks};
        if (start > uint64_t(chain.Height())) return Status::INVALID;
        const uint32_t end{uint32_t(std::min<uint64_t>(start + m_opts.epoch_blocks - 1, chain.Height()))};
        current = e && e->end_height == end && chain[end]->GetBlockHash() == e->anchor_hash;
        tip = chain.Tip()->GetBlockHash();
    }
    if (!current) return RequestBuild(peer, epoch, tip);

    const pir::Params params{e->db.GetParams()};
    const uint64_t cost{params.num_records == 0 ? 0 : params.HintBytes()};
    {
        LOCK(m_budget_mutex);
        const auto now{NodeClock::now()};
        if (!PeerBudget(peer, now).TryConsume(cost, now)) return Status::OVER_BUDGET;
    }

    const uint32_t slots{params.num_records == 0 ? 1 : params.records_per_col};
    const size_t slot_words{size_t{params.record_bytes} * pir::LWE_N};
    out.clear();
    for (uint32_t slot = 0; slot < slots; ++slot) {
        PirHintMsg& msg{out.emplace_back()};
        msg.epoch = epoch;
        msg.epoch_blocks = m_opts.epoch_blocks;
        msg.start_height = e->start_height;
        msg.anchor_hash = e->anchor_hash;
        msg.block_counts = e->block_counts;
        msg.seed = e->seed;
        msg.record_bytes = params.record_bytes;
        msg.num_records = params.num_records;
        msg.records_per_col = params.records_per_col;
        msg.slot = slot;
        if (params.num_records > 0) {
            msg.hint.assign(e->hint.begin() + slot * slot_words, e->hint.begin() + (slot + 1) * slot_words);
        }
    }
    return Status::OK;
}

PirServer::Status PirServer::Answer(int64_t peer, const PirQueryMsg& query, PirReplyMsg& out)
{
    {
        LOCK(m_budget_mutex);
        if (m_global_budget.InDebt(NodeClock::now())) return Status::BUSY;
    }
    const uint64_t start{uint64_t{query.epoch} * m_opts.epoch_blocks};
    const EpochRef e{Lookup(query.epoch)};
    uint32_t anchor_height;
    bool usable;
    uint256 tip;
    {
        LOCK(::cs_main);
        const CBlockIndex* pindex{m_chainman.m_blockman.LookupBlockIndex(query.anchor_hash)};
        if (!pindex || uint64_t(pindex->nHeight) < start || uint64_t(pindex->nHeight) >= start + m_opts.epoch_blocks) {
            return Status::INVALID;
        }
        const CChain& chain{m_chainman.ActiveChain()};
        if (!chain.Contains(pindex)) return Status::STALE;
        anchor_height = pindex->nHeight;
        // The cached version serves the query if it reaches the anchor and is
        // still on the active chain (then so is everything up to the anchor).
        const CBlockIndex* end{e ? chain[e->end_height] : nullptr};
        usable = end && anchor_height <= e->end_height && end->GetBlockHash() == e->anchor_hash;
        tip = chain.Tip()->GetBlockHash();
    }
    if (!usable) return RequestBuild(peer, query.epoch, tip);

    const uint32_t prefix_blocks{anchor_height - e->start_height + 1};
    const uint64_t num_records{std::accumulate(e->block_counts.begin(), e->block_counts.begin() + prefix_blocks, uint64_t{0})};
    if (query.num_records != num_records) return Status::INVALID;
    const pir::Params params{PIR_RECORD_BYTES, query.num_records, pir::ChooseRecordsPerCol(query.num_records)};
    if (query.query.size() != params.Cols()) return Status::INVALID;
    // Columns are only stable under appends while records_per_col stays the same.
    if (params.records_per_col != e->db.GetParams().records_per_col) return Status::STALE;

    const uint64_t cost{params.DatabaseBytes()};
    {
        LOCK(m_budget_mutex);
        const auto now{NodeClock::now()};
        if (!PeerBudget(peer, now).TryConsume(cost, now)) return Status::OVER_BUDGET;
        m_global_budget.Charge(cost, now);
    }

    // The scan runs on the snapshot, with no lock held.
    auto answer{pir::Answer(e->db, query.query, query.num_records)};
    if (!answer) return Status::STALE;
    out.epoch = query.epoch;
    out.anchor_hash = query.anchor_hash;
    out.answer = std::move(*answer);
    return Status::OK;
}

bool PirEpochClient::AddHint(const PirHintMsg& msg)
{
    if (msg.status != PIR_STATUS_OK) return false;
    const pir::Params params{msg.GetParams()};
    if (!params.IsValid() || params.records_per_col != pir::ChooseRecordsPerCol(params.num_records)) return false;
    if (msg.epoch_blocks == 0 || msg.epoch_blocks > MAX_PIR_EPOCH_BLOCKS) return false;
    if (uint64_t{msg.epoch} * msg.epoch_blocks != msg.start_height) return false;
    if (msg.block_counts.empty() || msg.block_counts.size() > msg.epoch_blocks) return false;
    if (std::accumulate(msg.block_counts.begin(), msg.block_counts.end(), uint64_t{0}) != params.num_records) return false;
    if (msg.seed != PirEpochSeed(m_genesis, msg.epoch)) return false;
    const size_t slot_words{size_t{params.record_bytes} * pir::LWE_N};
    if (params.num_records == 0 ? (msg.slot != 0 || !msg.hint.empty()) : (msg.slot >= params.records_per_col || msg.hint.size() != slot_words)) {
        return false;
    }

    if (m_have_slot.empty()) {
        m_info = msg;
        m_info.hint.clear();
        m_have_slot.assign(params.num_records == 0 ? 1 : params.records_per_col, false);
        m_hint.assign(params.num_records == 0 ? 0 : size_t{params.Rows()} * pir::LWE_N, 0);
    } else if (msg.epoch != m_info.epoch || msg.epoch_blocks != m_info.epoch_blocks || msg.anchor_hash != m_info.anchor_hash ||
               msg.block_counts != m_info.block_counts || !(params == m_info.GetParams())) {
        return false;
    }
    std::copy(msg.hint.begin(), msg.hint.end(), m_hint.begin() + msg.slot * slot_words);
    m_have_slot[msg.slot] = true;
    return true;
}

bool PirEpochClient::Complete() const
{
    return !m_have_slot.empty() && std::all_of(m_have_slot.begin(), m_have_slot.end(), [](bool b) { return b; });
}

std::optional<uint32_t> PirEpochClient::IndexOf(uint32_t height, uint32_t pos) const
{
    if (!Complete() || height < m_info.start_height) return std::nullopt;
    const uint32_t offset{height - m_info.start_height};
    if (offset >= m_info.block_counts.size() || pos >= m_info.block_counts[offset]) return std::nullopt;
    return std::accumulate(m_info.block_counts.begin(), m_info.block_counts.begin() + offset, uint32_t{0}) + pos;
}

std::optional<PirQueryMsg> PirEpochClient::MakeQuery(uint32_t index, pir::SecretRng& rng, pir::QueryState& state) const
{
    if (!Complete()) return std::nullopt;
    auto query{pir::MakeQuery(m_info.GetParams(), m_info.seed, index, rng, state)};
    if (!query) return std::nullopt;
    PirQueryMsg msg;
    msg.epoch = m_info.epoch;
    msg.anchor_hash = m_info.anchor_hash;
    msg.num_records = m_info.num_records;
    msg.query = std::move(*query);
    return msg;
}

std::optional<std::vector<uint8_t>> PirEpochClient::Decode(const pir::QueryState& state, const PirReplyMsg& reply) const
{
    if (!Complete() || reply.status != PIR_STATUS_OK || reply.epoch != m_info.epoch || reply.anchor_hash != m_info.anchor_hash) return std::nullopt;
    if (!(state.params == m_info.GetParams())) return std::nullopt;
    return pir::Decode(state, m_hint, reply.answer);
}

} // namespace node
