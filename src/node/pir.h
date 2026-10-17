// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_PIR_H
#define BITCOIN_NODE_PIR_H

#include <pir/simplepir.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <span.h>
#include <sync.h>
#include <uint256.h>
#include <util/time.h>

#include <algorithm>
#include <bit>
#include <chrono>
#include <cstdint>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <vector>

class CBlock;
class ChainstateManager;

/**
 * Private fetch of BLSCT output data for light wallets (PROTOTYPE).
 *
 * getoutkeys lets a light wallet find its outputs without revealing them,
 * but it then needs each output's range proof to recover amount, memo and
 * blinding factor, and asking for those by hash tells the server which
 * outputs are the wallet's. Here the server instead holds the outputs as
 * SimplePIR databases (see pir/simplepir.h) and the wallet retrieves an
 * output's record with a query the server cannot link to it.
 *
 * Epochs. The outputs that getoutkeys reports (every output carrying BLSCT
 * keys, in chain order) are split by height into epochs of epoch_blocks
 * blocks: epoch e holds the outputs of heights [e * epoch_blocks,
 * (e + 1) * epoch_blocks). Each epoch is its own database, so appending
 * blocks only grows the last epoch, which the hint follows incrementally.
 * A client maps an outkeys entry (block height, position in the block's
 * outputs) to (epoch, index) using the per-block output counts in pirhint.
 * A reorg can only change epochs that contain the fork point; the server
 * rebuilds such an epoch from scratch.
 */
namespace node {

/** Bytes per record: fits every BLSCT output without a staking or other long script. */
static constexpr uint32_t PIR_RECORD_BYTES{1152};
/** Record kinds (first byte of a record). */
static constexpr uint8_t PIR_RECORD_OUTPUT{1};     //!< [kind][uint16 len][CTxOut][zero padding]
static constexpr uint8_t PIR_RECORD_OVERSIZED{2};  //!< output did not fit; fetch it some other way
static constexpr uint32_t PIR_RECORD_HEADER{3};

/** Default -pirepochblocks. At 2 outputs per block this is ~2^14.3 records. */
static constexpr uint32_t DEFAULT_PIR_EPOCH_BLOCKS{10080};
/** Epoch sizes above this are refused (block_counts must fit a message). */
static constexpr uint32_t MAX_PIR_EPOCH_BLOCKS{100000};
/** Default -pirmaxepochs: epochs kept in memory. */
static constexpr uint32_t DEFAULT_PIR_MAX_EPOCHS{4};

/**
 * Work budget. A query costs one full scan of the epoch database and a hint
 * costs its size in bytes sent, so both are charged in bytes. Each peer has
 * a token bucket (burst DEFAULT_PIR_PEER_BUDGET, refilled at 1/8 of that per
 * second) and a peer that exceeds it is disconnected: a client knows the cost
 * of each request from the pirhint it holds and can pace itself.
 * Building or extending a hint costs LWE_N multiply-adds per database byte
 * against one for a scan, so it is charged as PIR_HINT_WORK_FACTOR scanned
 * bytes per byte added, to a global bucket shared by all peers (burst
 * PIR_GLOBAL_BUDGET, refilled at 1/16 of that per second) that queries are
 * also charged to; while it is in debt new requests are ignored.
 */
static constexpr uint64_t DEFAULT_PIR_PEER_BUDGET{uint64_t{1} << 30};
static constexpr uint64_t PIR_GLOBAL_BUDGET{uint64_t{16} << 30};
static constexpr uint64_t PIR_HINT_WORK_FACTOR{pir::LWE_N};

/** Serialize a vector<uint32_t> as a compact size and little-endian words, in bulk. */
struct PirWords {
    template <typename Stream>
    void Ser(Stream& s, const std::vector<uint32_t>& v) const
    {
        WriteCompactSize(s, v.size());
        if constexpr (std::endian::native == std::endian::little) {
            s.write(AsBytes(Span{v}));
        } else {
            for (uint32_t w : v) ser_writedata32(s, w);
        }
    }
    template <typename Stream>
    void Unser(Stream& s, std::vector<uint32_t>& v) const
    {
        const uint64_t n{ReadCompactSize(s, /*range_check=*/false)};
        v.clear();
        // Grow as data arrives, so a large claimed size cannot allocate
        // more than the message holds.
        constexpr uint64_t CHUNK{1 << 18};
        while (v.size() < n) {
            const size_t old{v.size()};
            const size_t add{size_t(std::min<uint64_t>(CHUNK, n - old))};
            v.resize(old + add);
            if constexpr (std::endian::native == std::endian::little) {
                s.read(AsWritableBytes(Span{v}.subspan(old, add)));
            } else {
                for (size_t i = old; i < old + add; ++i) v[i] = ser_readdata32(s);
            }
        }
    }
};

/** getpirhint: request the hint of one epoch. */
struct PirHintRequest {
    uint32_t epoch{0};
    SERIALIZE_METHODS(PirHintRequest, obj) { READWRITE(obj.epoch); }
};

/**
 * pirhint: one per slot (records_per_col of them; one for an empty epoch),
 * each carrying the epoch description and the hint rows of its slot.
 */
struct PirHintMsg {
    uint32_t epoch{0};
    uint32_t epoch_blocks{0};
    uint32_t start_height{0};
    //! Last block the epoch data covers; names this version of the epoch.
    uint256 anchor_hash;
    //! Records per block, for heights start_height onwards up to the anchor.
    std::vector<uint32_t> block_counts;
    uint256 seed;
    uint32_t record_bytes{0};
    uint32_t num_records{0};
    uint32_t records_per_col{1};
    uint32_t slot{0};
    //! Hint rows [slot * record_bytes, (slot + 1) * record_bytes), LWE_N words each; empty if num_records is 0.
    std::vector<uint32_t> hint;

    pir::Params GetParams() const { return {record_bytes, num_records, records_per_col}; }

    SERIALIZE_METHODS(PirHintMsg, obj)
    {
        READWRITE(obj.epoch, obj.epoch_blocks, obj.start_height, obj.anchor_hash, obj.block_counts,
                  obj.seed, obj.record_bytes, obj.num_records, obj.records_per_col, obj.slot,
                  Using<PirWords>(obj.hint));
    }
};

/** pirquery: a query against the first num_records records of an epoch version. */
struct PirQueryMsg {
    uint32_t epoch{0};
    uint256 anchor_hash;
    uint32_t num_records{0};
    std::vector<uint32_t> query;

    SERIALIZE_METHODS(PirQueryMsg, obj)
    {
        READWRITE(obj.epoch, obj.anchor_hash, obj.num_records, Using<PirWords>(obj.query));
    }
};

/** pirreply: the answer to a pirquery, in request order; empty answer: the anchor was reorganised away. */
struct PirReplyMsg {
    uint32_t epoch{0};
    uint256 anchor_hash;
    std::vector<uint32_t> answer;

    SERIALIZE_METHODS(PirReplyMsg, obj)
    {
        READWRITE(obj.epoch, obj.anchor_hash, Using<PirWords>(obj.answer));
    }
};

/** The public matrix seed of an epoch: fixed by the chain, so a server cannot pick a trapdoored A. */
uint256 PirEpochSeed(const uint256& genesis_hash, uint32_t epoch);

/** Encode an output as a record of PIR_RECORD_BYTES. */
std::vector<uint8_t> EncodeOutputRecord(const CTxOut& out);
/** The output in a record of kind PIR_RECORD_OUTPUT, or std::nullopt. */
std::optional<CTxOut> DecodeOutputRecord(Span<const uint8_t> record);
/** Append the records of a block's outputs that getoutkeys reports, in the same order. */
void AppendBlockRecords(const CBlock& block, std::vector<std::vector<uint8_t>>& out);

/** Token bucket in bytes. */
class PirBudget
{
public:
    PirBudget(uint64_t capacity, uint64_t per_second, NodeClock::time_point now)
        : m_capacity{capacity}, m_per_second{per_second}, m_tokens{double(capacity)}, m_last{now} {}
    /** Take cost if available. */
    bool TryConsume(uint64_t cost, NodeClock::time_point now);
    /** Take cost unconditionally (may go into debt). */
    void Charge(uint64_t cost, NodeClock::time_point now);
    bool InDebt(NodeClock::time_point now);

private:
    void Refill(NodeClock::time_point now);
    uint64_t m_capacity;
    uint64_t m_per_second;
    double m_tokens;
    NodeClock::time_point m_last;
};

/** One epoch's database and hint at its latest version. */
struct PirEpoch {
    uint32_t epoch{0};
    uint32_t start_height{0};
    uint32_t end_height{0};
    uint256 anchor_hash;
    std::vector<uint32_t> block_counts;
    uint256 seed;
    pir::Database db{PIR_RECORD_BYTES};
    pir::Hint hint;
};

/**
 * Server side: keeps the most recently used epochs in memory, brings them up
 * to the active chain on use, answers queries and accounts for work.
 * All methods are thread-safe; in practice they are called from the message
 * handler thread.
 */
class PirServer
{
public:
    struct Options {
        uint32_t epoch_blocks{DEFAULT_PIR_EPOCH_BLOCKS};
        uint32_t max_epochs{DEFAULT_PIR_MAX_EPOCHS};
        uint64_t peer_budget{DEFAULT_PIR_PEER_BUDGET};
    };

    enum class Status {
        OK,
        STALE,        //!< anchor no longer in the active chain (reply with an empty answer)
        BUSY,         //!< global budget exhausted (ignore the request)
        OVER_BUDGET,  //!< peer exceeded its budget (disconnect)
        INVALID,      //!< malformed request (disconnect)
        UNAVAILABLE,  //!< block data could not be read (ignore)
    };

    PirServer(ChainstateManager& chainman, const Options& opts);

    uint32_t EpochBlocks() const { return m_opts.epoch_blocks; }

    /** Build the pirhint messages for an epoch. */
    Status GetHint(int64_t peer, uint32_t epoch, std::vector<PirHintMsg>& out) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Answer a pirquery. */
    Status Answer(int64_t peer, const PirQueryMsg& query, PirReplyMsg& out) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    /** Drop a disconnected peer's budget. */
    void ForgetPeer(int64_t peer) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    /** The epoch brought up to the active chain; nullptr if it starts above the tip. */
    PirEpoch* Update(uint32_t epoch, Status& status) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    PirBudget& PeerBudget(int64_t peer, NodeClock::time_point now) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    ChainstateManager& m_chainman;
    const Options m_opts;
    const uint256 m_genesis;
    Mutex m_mutex;
    //! Cached epochs, most recently used first.
    std::list<std::unique_ptr<PirEpoch>> m_epochs GUARDED_BY(m_mutex);
    std::map<int64_t, PirBudget> m_peer_budgets GUARDED_BY(m_mutex);
    PirBudget m_global_budget GUARDED_BY(m_mutex);
};

/**
 * Client side of one epoch: assembles the pirhint messages, checks the seed,
 * maps outkeys positions to record indices, builds queries and decodes
 * replies. Used by tests and benchmarks; a light wallet would do the same.
 */
class PirEpochClient
{
public:
    explicit PirEpochClient(const uint256& genesis_hash) : m_genesis{genesis_hash} {}

    /** Add one pirhint; false if it is inconsistent with the ones before or with the chain. */
    bool AddHint(const PirHintMsg& msg);
    /** Whether every slot of the hint has arrived. */
    bool Complete() const;
    const PirHintMsg& Info() const { return m_info; }

    /** Record index of the output at position pos of the block at height, if in this epoch version. */
    std::optional<uint32_t> IndexOf(uint32_t height, uint32_t pos) const;
    /** Query for record index; rng as for pir::MakeQuery. */
    std::optional<PirQueryMsg> MakeQuery(uint32_t index, FastRandomContext& rng, pir::QueryState& state) const;
    /** The record's bytes, if the reply matches the query and decodes. */
    std::optional<std::vector<uint8_t>> Decode(const pir::QueryState& state, const PirReplyMsg& reply) const;

private:
    const uint256 m_genesis;
    PirHintMsg m_info;
    std::vector<bool> m_have_slot;
    pir::Hint m_hint;
};

} // namespace node

#endif // BITCOIN_NODE_PIR_H
