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
#include <validation.h>

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
      m_global_budget{PIR_GLOBAL_BUDGET, PIR_GLOBAL_BUDGET / 16, NodeClock::now()}
{
    Assert(opts.epoch_blocks > 0 && opts.epoch_blocks <= MAX_PIR_EPOCH_BLOCKS);
    Assert(opts.max_epochs > 0);
}

PirBudget& PirServer::PeerBudget(int64_t peer, NodeClock::time_point now)
{
    auto it{m_peer_budgets.find(peer)};
    if (it == m_peer_budgets.end()) {
        it = m_peer_budgets.emplace(peer, PirBudget{m_opts.peer_budget, m_opts.peer_budget / 8, now}).first;
    }
    return it->second;
}

void PirServer::ForgetPeer(int64_t peer)
{
    LOCK(m_mutex);
    m_peer_budgets.erase(peer);
}

PirEpoch* PirServer::Update(uint32_t epoch, Status& status)
{
    const uint64_t start{uint64_t{epoch} * m_opts.epoch_blocks};

    // Find the cached epoch and make it the most recently used.
    auto it{std::find_if(m_epochs.begin(), m_epochs.end(), [&](const auto& e) { return e->epoch == epoch; })};
    if (it != m_epochs.end()) m_epochs.splice(m_epochs.begin(), m_epochs, it);
    PirEpoch* cached{it != m_epochs.end() ? m_epochs.front().get() : nullptr};

    std::vector<const CBlockIndex*> todo;
    bool rebuild{false};
    {
        LOCK(::cs_main);
        const CChain& chain{m_chainman.ActiveChain()};
        if (start > uint64_t(chain.Height())) {
            status = Status::INVALID;
            return nullptr;
        }
        const uint32_t end{uint32_t(std::min<uint64_t>(start + m_opts.epoch_blocks - 1, chain.Height()))};
        uint32_t from{uint32_t(start)};
        if (cached && !cached->block_counts.empty()) {
            const CBlockIndex* anchor{chain[cached->end_height]};
            if (cached->end_height <= end && anchor && anchor->GetBlockHash() == cached->anchor_hash) {
                from = cached->end_height + 1;
            } else {
                rebuild = true;
            }
        }
        for (uint32_t h = from; h <= end; ++h) {
            const CBlockIndex* pindex{chain[h]};
            if (!(pindex->nStatus & BLOCK_HAVE_DATA)) {
                status = Status::UNAVAILABLE;
                return nullptr;
            }
            todo.push_back(pindex);
        }
    }
    if (cached && !rebuild && todo.empty()) return cached;

    // Read the new blocks before touching the cached epoch.
    std::vector<std::vector<uint8_t>> records;
    std::vector<uint32_t> counts;
    for (const CBlockIndex* pindex : todo) {
        CBlock block;
        if (!m_chainman.m_blockman.ReadBlockFromDisk(block, *pindex)) {
            LogPrint(BCLog::NET, "pir: failed to read block %s\n", pindex->GetBlockHash().ToString());
            status = Status::UNAVAILABLE;
            return nullptr;
        }
        const size_t before{records.size()};
        AppendBlockRecords(block, records);
        counts.push_back(records.size() - before);
    }

    if (!cached || rebuild) {
        if (!cached) {
            m_epochs.push_front(std::make_unique<PirEpoch>());
            while (m_epochs.size() > m_opts.max_epochs) m_epochs.pop_back();
        }
        cached = m_epochs.front().get();
        *cached = PirEpoch{};
        cached->epoch = epoch;
        cached->start_height = uint32_t(start);
        cached->seed = PirEpochSeed(m_genesis, epoch);
        LogPrint(BCLog::NET, "pir: building epoch %u\n", epoch);
    }

    const uint32_t old_records{cached->db.GetParams().num_records};
    cached->db.Reserve(old_records + records.size());
    for (const auto& r : records) cached->db.Append(r);
    cached->block_counts.insert(cached->block_counts.end(), counts.begin(), counts.end());
    cached->end_height = todo.back()->nHeight;
    cached->anchor_hash = todo.back()->GetBlockHash();

    const uint32_t num_records{cached->db.GetParams().num_records};
    m_global_budget.Charge(uint64_t{num_records - old_records} * PIR_RECORD_BYTES * PIR_HINT_WORK_FACTOR, NodeClock::now());
    const uint32_t k{pir::ChooseRecordsPerCol(num_records)};
    if (num_records == 0) {
        cached->hint.clear();
    } else if (k != cached->db.GetParams().records_per_col || cached->hint.size() != size_t{PIR_RECORD_BYTES} * k * pir::LWE_N) {
        cached->db.SetRecordsPerCol(k);
        cached->hint = pir::ComputeHint(cached->db, cached->seed);
    } else {
        pir::ExtendHint(cached->hint, cached->db, cached->seed, old_records);
    }
    LogPrint(BCLog::NET, "pir: epoch %u now at height %u with %u records\n", epoch, cached->end_height, num_records);
    return cached;
}

PirServer::Status PirServer::GetHint(int64_t peer, uint32_t epoch, std::vector<PirHintMsg>& out)
{
    LOCK(m_mutex);
    const auto now{NodeClock::now()};
    if (m_global_budget.InDebt(now)) return Status::BUSY;
    Status status{Status::OK};
    const PirEpoch* e{Update(epoch, status)};
    if (!e) return status;

    const pir::Params params{e->db.GetParams()};
    const uint64_t cost{params.num_records == 0 ? 0 : params.HintBytes()};
    if (!PeerBudget(peer, now).TryConsume(cost, now)) return Status::OVER_BUDGET;

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
    LOCK(m_mutex);
    const auto now{NodeClock::now()};
    if (m_global_budget.InDebt(now)) return Status::BUSY;

    const uint64_t start{uint64_t{query.epoch} * m_opts.epoch_blocks};
    uint32_t anchor_height;
    {
        LOCK(::cs_main);
        const CBlockIndex* pindex{m_chainman.m_blockman.LookupBlockIndex(query.anchor_hash)};
        if (!pindex || uint64_t(pindex->nHeight) < start || uint64_t(pindex->nHeight) >= start + m_opts.epoch_blocks) {
            return Status::INVALID;
        }
        if (!m_chainman.ActiveChain().Contains(pindex)) return Status::STALE;
        anchor_height = pindex->nHeight;
    }

    Status status{Status::OK};
    const PirEpoch* e{Update(query.epoch, status)};
    if (!e) return status;
    // The anchor was in the active chain above; if it is past the epoch data
    // now, the chain changed in between.
    if (anchor_height > e->end_height) return Status::STALE;

    const uint32_t prefix_blocks{anchor_height - e->start_height + 1};
    const uint64_t num_records{std::accumulate(e->block_counts.begin(), e->block_counts.begin() + prefix_blocks, uint64_t{0})};
    if (query.num_records != num_records) return Status::INVALID;
    const pir::Params params{PIR_RECORD_BYTES, query.num_records, pir::ChooseRecordsPerCol(query.num_records)};
    if (query.query.size() != params.Cols()) return Status::INVALID;
    // Columns are only stable under appends while records_per_col stays the same.
    if (params.records_per_col != e->db.GetParams().records_per_col) return Status::STALE;

    const uint64_t cost{params.DatabaseBytes()};
    if (!PeerBudget(peer, now).TryConsume(cost, now)) return Status::OVER_BUDGET;
    m_global_budget.Charge(cost, now);

    auto answer{pir::Answer(e->db, query.query, query.num_records)};
    if (!answer) return Status::STALE;
    out.epoch = query.epoch;
    out.anchor_hash = query.anchor_hash;
    out.answer = std::move(*answer);
    return Status::OK;
}

bool PirEpochClient::AddHint(const PirHintMsg& msg)
{
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

std::optional<PirQueryMsg> PirEpochClient::MakeQuery(uint32_t index, FastRandomContext& rng, pir::QueryState& state) const
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
    if (!Complete() || reply.epoch != m_info.epoch || reply.anchor_hash != m_info.anchor_hash) return std::nullopt;
    if (!(state.params == m_info.GetParams())) return std::nullopt;
    return pir::Decode(state, m_hint, reply.answer);
}

} // namespace node
