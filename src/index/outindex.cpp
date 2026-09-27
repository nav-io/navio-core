// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/outindex.h>

#include <common/args.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <util/check.h>
#include <validation.h>

#include <map>

constexpr uint8_t DB_OUTINDEX{'o'};

std::unique_ptr<OutIndex> g_outindex;

/** Access to the output index database (indexes/outindex/) */
class OutIndex::DB : public BaseIndex::DB
{
public:
    explicit DB(size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    bool ReadEntry(const uint256& out_id, OutIndexEntry& entry) const
    {
        return Read(std::make_pair(DB_OUTINDEX, out_id), entry);
    }

    static void WriteEntry(CDBBatch& batch, const uint256& out_id, const OutIndexEntry& entry)
    {
        batch.Write(std::make_pair(DB_OUTINDEX, out_id), entry);
    }

    static void EraseEntry(CDBBatch& batch, const uint256& out_id)
    {
        batch.Erase(std::make_pair(DB_OUTINDEX, out_id));
    }
};

OutIndex::DB::DB(size_t n_cache_size, bool f_memory, bool f_wipe) :
    BaseIndex::DB(gArgs.GetDataDirNet() / "indexes" / "outindex", n_cache_size, f_memory, f_wipe)
{}

OutIndex::OutIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory, bool f_wipe)
    : BaseIndex(std::move(chain), "outindex"), m_db(std::make_unique<OutIndex::DB>(n_cache_size, f_memory, f_wipe))
{}

OutIndex::~OutIndex() = default;

bool OutIndex::CustomAppend(const interfaces::BlockInfo& block)
{
    const CBlock& data{*Assert(block.data)};

    // Outputs created or touched by this block. An output may be created and
    // spent within the same block, so spends consult this map before the
    // database, which does not yet hold this block's writes.
    std::map<uint256, OutIndexEntry> touched;

    for (uint32_t tx_pos = 0; tx_pos < data.vtx.size(); ++tx_pos) {
        const CTransaction& tx{*data.vtx[tx_pos]};

        if (!tx.IsCoinBase()) {
            for (uint32_t in_pos = 0; in_pos < tx.vin.size(); ++in_pos) {
                const uint256& out_id{tx.vin[in_pos].prevout.hash.ToUint256()};
                auto it{touched.find(out_id)};
                if (it == touched.end()) {
                    OutIndexEntry entry;
                    if (!m_db->ReadEntry(out_id, entry)) {
                        // Every input spends an output an earlier block (or
                        // this one) created. The entry can only be missing if
                        // two blocks created the same output id and the later
                        // one was disconnected; the index keeps one entry per
                        // id, so there is nothing left to mark.
                        LogPrint(BCLog::COINDB, "%s: spent output %s not in index (block %s)\n",
                                 __func__, out_id.ToString(), block.hash.ToString());
                        continue;
                    }
                    it = touched.emplace(out_id, entry).first;
                }
                it->second.spent = OutIndexEntry::Spend{block.height, tx_pos, in_pos};
            }
        }

        for (uint32_t out_pos = 0; out_pos < tx.vout.size(); ++out_pos) {
            OutIndexEntry entry;
            entry.height = block.height;
            entry.tx_pos = tx_pos;
            entry.out_pos = out_pos;
            touched[tx.vout[out_pos].GetHash()] = entry;
        }
    }

    CDBBatch batch(*m_db);
    for (const auto& [out_id, entry] : touched) {
        DB::WriteEntry(batch, out_id, entry);
    }
    return m_db->WriteBatch(batch);
}

bool OutIndex::CustomRewind(const interfaces::BlockKey& current_tip, const interfaces::BlockKey& new_tip)
{
    LOCK(cs_main);
    const CBlockIndex* iter_tip{m_chainstate->m_blockman.LookupBlockIndex(current_tip.hash)};
    const CBlockIndex* new_tip_index{m_chainstate->m_blockman.LookupBlockIndex(new_tip.hash)};

    // Undo one block at a time, newest first, so each block sees the index as
    // it stood right after that block was appended.
    do {
        CBlock block;
        if (!m_chainstate->m_blockman.ReadBlockFromDisk(block, *iter_tip)) {
            return error("%s: Failed to read block %s from disk",
                         __func__, iter_tip->GetBlockHash().ToString());
        }

        std::map<uint256, std::optional<OutIndexEntry>> touched; // nullopt = erase
        auto load = [&](const uint256& out_id) -> std::optional<OutIndexEntry>& {
            auto it{touched.find(out_id)};
            if (it == touched.end()) {
                OutIndexEntry entry;
                std::optional<OutIndexEntry> value;
                if (m_db->ReadEntry(out_id, entry)) value = entry;
                it = touched.emplace(out_id, value).first;
            }
            return it->second;
        };

        // Walk the block backwards so an output created and spent in the same
        // block has its spend cleared before its creation is removed.
        for (size_t tx_pos = block.vtx.size(); tx_pos-- > 0;) {
            const CTransaction& tx{*block.vtx[tx_pos]};

            for (const CTxOut& out : tx.vout) {
                auto& entry{load(out.GetHash())};
                // Only remove an entry this block wrote.
                if (entry && entry->height == iter_tip->nHeight) entry.reset();
            }

            if (tx.IsCoinBase()) continue;
            for (const CTxIn& in : tx.vin) {
                auto& entry{load(in.prevout.hash.ToUint256())};
                if (entry && entry->spent && entry->spent->height == iter_tip->nHeight) {
                    entry->spent.reset();
                }
            }
        }

        CDBBatch batch(*m_db);
        for (const auto& [out_id, entry] : touched) {
            if (entry) {
                DB::WriteEntry(batch, out_id, *entry);
            } else {
                DB::EraseEntry(batch, out_id);
            }
        }
        if (!m_db->WriteBatch(batch)) return false;

        iter_tip = iter_tip->GetAncestor(iter_tip->nHeight - 1);
    } while (new_tip_index != iter_tip);

    return true;
}

BaseIndex::DB& OutIndex::GetDB() const { return *m_db; }

std::optional<OutIndexEntry> OutIndex::FindOutput(const uint256& out_id) const
{
    OutIndexEntry entry;
    if (!m_db->ReadEntry(out_id, entry)) return std::nullopt;
    return entry;
}
