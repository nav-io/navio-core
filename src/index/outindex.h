// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INDEX_OUTINDEX_H
#define BITCOIN_INDEX_OUTINDEX_H

#include <index/base.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <optional>

static constexpr bool DEFAULT_OUTINDEX{false};

/**
 * Where an output sits in the active chain and, once a block spends it, where
 * that spend sits. Positions are indices into the block's vtx, the
 * transaction's vout and the spending transaction's vin respectively.
 */
struct OutIndexEntry {
    int32_t height{-1};
    uint32_t tx_pos{0};
    uint32_t out_pos{0};

    struct Spend {
        int32_t height{-1};
        uint32_t tx_pos{0};
        uint32_t in_pos{0};

        friend bool operator==(const Spend&, const Spend&) = default;
    };
    std::optional<Spend> spent;

    friend bool operator==(const OutIndexEntry&, const OutIndexEntry&) = default;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        s << VARINT(uint32_t(height)) << VARINT(tx_pos) << VARINT(out_pos);
        s << bool{spent.has_value()};
        if (spent) {
            s << VARINT(uint32_t(spent->height)) << VARINT(spent->tx_pos) << VARINT(spent->in_pos);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint32_t h;
        s >> VARINT(h) >> VARINT(tx_pos) >> VARINT(out_pos);
        height = int32_t(h);
        bool has_spend;
        s >> has_spend;
        spent.reset();
        if (has_spend) {
            Spend sp;
            s >> VARINT(h) >> VARINT(sp.tx_pos) >> VARINT(sp.in_pos);
            sp.height = int32_t(h);
            spent = sp;
        }
    }
};

/**
 * OutIndex maps an output id (CTxOut::GetHash(), which is also the outpoint
 * that spends it) to the block position that created it and, once spent, the
 * block position of the spending input. It lets lookups by output id avoid
 * walking the chain, including for outputs that are no longer in the UTXO
 * set.
 *
 * Entries follow the active chain: a disconnected block removes the entries
 * for the outputs it created and clears the spend it recorded on the outputs
 * it consumed. The index holds one entry per output id: if two blocks create
 * the same id, the later one's position is kept.
 */
class OutIndex final : public BaseIndex
{
protected:
    class DB;

private:
    const std::unique_ptr<DB> m_db;

    bool AllowPrune() const override { return false; }

protected:
    bool CustomAppend(const interfaces::BlockInfo& block) override;

    bool CustomRewind(const interfaces::BlockKey& current_tip, const interfaces::BlockKey& new_tip) override;

    BaseIndex::DB& GetDB() const override;

public:
    explicit OutIndex(std::unique_ptr<interfaces::Chain> chain, size_t n_cache_size, bool f_memory = false, bool f_wipe = false);

    // Destructor is declared because this class contains a unique_ptr to an incomplete type.
    virtual ~OutIndex() override;

    /// Look up an output by its output id. Returns nullopt if the index has
    /// no entry for it.
    std::optional<OutIndexEntry> FindOutput(const uint256& out_id) const;
};

/// The global output index. May be null.
extern std::unique_ptr<OutIndex> g_outindex;

#endif // BITCOIN_INDEX_OUTINDEX_H
