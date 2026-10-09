// Copyright (c) 2016-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockencodings.h>
#include <blsct/wallet/txfactory_global.h>
#include <chainparams.h>
#include <common/system.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <crypto/siphash.h>
#include <logging.h>
#include <random.h>
#include <streams.h>
#include <txmempool.h>
#include <validation.h>

#include <unordered_map>

CBlockHeaderAndShortTxIDs::CBlockHeaderAndShortTxIDs(const CBlock& block) :
        CBlockHeaderAndShortTxIDs(block, block.vtx) {}

CBlockHeaderAndShortTxIDs::CBlockHeaderAndShortTxIDs(const CBlock& block, const std::vector<CTransactionRef>& txs) :
        nonce(GetRand<uint64_t>()),
        shorttxids(txs.size() - 1), prefilledtxn(1), header(block), posProof(block.posProof) {
    FillShortTxIDSelector();
    //TODO: Use our mempool prior to block acceptance to predictively fill more than just the coinbase
    prefilledtxn[0] = {0, txs[0]};
    for (size_t i = 1; i < txs.size(); i++) {
        const CTransaction& tx = *txs[i];
        shorttxids[i - 1] = GetShortID(tx.GetWitnessHash());
    }
}

CBlockHeaderAndComponentIDs::CBlockHeaderAndComponentIDs(const CBlock& block, const std::vector<CTransactionRef>& component_list) :
        CBlockHeaderAndShortTxIDs(block, component_list) {
    Assert(component_list.size() >= 1 + MIN_COMPONENTS);
    m_aggregate_components = true;
}

CTransactionRef AggregateComponents(const std::vector<CTransactionRef>& components)
{
    if (components.size() < CBlockHeaderAndComponentIDs::MIN_COMPONENTS) return nullptr;
    for (const auto& tx : components) {
        if (!tx || !tx->IsBLSCT() || tx->IsCoinBase()) return nullptr;
    }
    try {
        return blsct::AggregateTransactions(components);
    } catch (const std::exception&) {
        // e.g. no component carries a fee output
        return nullptr;
    }
}

bool ComponentListMatchesBlock(const CBlock& block, const std::vector<CTransactionRef>& component_list)
{
    if (block.vtx.size() != 2 || component_list.size() < 1 + CBlockHeaderAndComponentIDs::MIN_COMPONENTS) return false;
    if (component_list[0]->GetWitnessHash() != block.vtx[0]->GetWitnessHash()) return false;
    const auto aggregate{AggregateComponents({component_list.begin() + 1, component_list.end()})};
    return aggregate && aggregate->GetWitnessHash() == block.vtx[1]->GetWitnessHash();
}

std::optional<std::vector<CTransactionRef>> FindAggregateComponents(const CBlock& block, const CTxMemPool& pool)
{
    if (block.vtx.size() != 2 || !block.vtx[1]->IsBLSCT()) return std::nullopt;
    const CTransaction& aggregate{*block.vtx[1]};

    std::vector<CTransactionRef> component_list{block.vtx[0]};
    {
        LOCK(pool.cs);
        size_t pos{0};
        while (pos < aggregate.vin.size()) {
            const CTransaction* spender{pool.GetConflictTx(aggregate.vin[pos].prevout)};
            if (!spender || spender->vin.empty() || pos + spender->vin.size() > aggregate.vin.size()) return std::nullopt;
            for (size_t i = 0; i < spender->vin.size(); ++i) {
                if (!(spender->vin[i] == aggregate.vin[pos + i])) return std::nullopt;
            }
            CTransactionRef ref{pool.get(spender->GetHash().ToUint256())};
            if (!ref) return std::nullopt;
            component_list.push_back(std::move(ref));
            pos += spender->vin.size();
        }
    }
    // Also rejects a lone "component": the assembler keeps a single
    // transaction as is, so such a block is plain BIP152 material.
    if (!ComponentListMatchesBlock(block, component_list)) return std::nullopt;
    return component_list;
}

void RecentBlockComponents::Add(const uint256& block_hash, std::shared_ptr<const std::vector<CTransactionRef>> component_list)
{
    if (Get(block_hash)) return;
    size_t bytes{0};
    for (const auto& tx : *component_list) bytes += tx->GetTotalSize();
    if (bytes > m_max_bytes) return;
    m_entries.push_back({block_hash, std::move(component_list), bytes});
    m_bytes += bytes;
    while (!m_entries.empty() && (m_entries.size() > m_max_lists || m_bytes > m_max_bytes)) {
        m_bytes -= m_entries.front().bytes;
        m_entries.pop_front();
    }
}

std::shared_ptr<const std::vector<CTransactionRef>> RecentBlockComponents::Get(const uint256& block_hash) const
{
    for (const auto& entry : m_entries) {
        if (entry.block_hash == block_hash) return entry.component_list;
    }
    return nullptr;
}

void CBlockHeaderAndShortTxIDs::FillShortTxIDSelector() const {
    DataStream stream{};
    stream << header;
    if (header.IsProofOfStake())
        stream << posProof;
    stream << nonce;
    CSHA256 hasher;
    hasher.Write((unsigned char*)&(*stream.begin()), stream.end() - stream.begin());
    uint256 shorttxidhash;
    hasher.Finalize(shorttxidhash.begin());
    shorttxidk0 = shorttxidhash.GetUint64(0);
    shorttxidk1 = shorttxidhash.GetUint64(1);
}

uint64_t CBlockHeaderAndShortTxIDs::GetShortID(const uint256& txhash) const {
    static_assert(SHORTTXIDS_LENGTH == 6, "shorttxids calculation assumes 6-byte shorttxids");
    return SipHashUint256(shorttxidk0, shorttxidk1, txhash) & 0xffffffffffffL;
}



ReadStatus PartiallyDownloadedBlock::InitData(const CBlockHeaderAndShortTxIDs& cmpctblock, const std::vector<std::pair<uint256, CTransactionRef>>& extra_txn) {
    if (cmpctblock.header.IsNull() || (cmpctblock.shorttxids.empty() && cmpctblock.prefilledtxn.empty()))
        return READ_STATUS_INVALID;
    if (cmpctblock.shorttxids.size() + cmpctblock.prefilledtxn.size() > MAX_BLOCK_WEIGHT / MIN_SERIALIZABLE_TRANSACTION_WEIGHT)
        return READ_STATUS_INVALID;

    if (!header.IsNull() || !txn_available.empty()) return READ_STATUS_INVALID;
    if (cmpctblock.IsAggregateComponents() && cmpctblock.BlockTxCount() < 1 + CBlockHeaderAndComponentIDs::MIN_COMPONENTS)
        return READ_STATUS_INVALID;

    m_aggregate_components = cmpctblock.IsAggregateComponents();
    header = cmpctblock.header;
    posProof = cmpctblock.posProof;
    txn_available.resize(cmpctblock.BlockTxCount());

    int32_t lastprefilledindex = -1;
    for (size_t i = 0; i < cmpctblock.prefilledtxn.size(); i++) {
        if (cmpctblock.prefilledtxn[i].tx->IsNull())
            return READ_STATUS_INVALID;

        lastprefilledindex += cmpctblock.prefilledtxn[i].index + 1; //index is a uint16_t, so can't overflow here
        if (lastprefilledindex > std::numeric_limits<uint16_t>::max())
            return READ_STATUS_INVALID;
        if ((uint32_t)lastprefilledindex > cmpctblock.shorttxids.size() + i) {
            // If we are inserting a tx at an index greater than our full list of shorttxids
            // plus the number of prefilled txn we've inserted, then we have txn for which we
            // have neither a prefilled txn or a shorttxid!
            return READ_STATUS_INVALID;
        }
        txn_available[lastprefilledindex] = cmpctblock.prefilledtxn[i].tx;
    }
    prefilled_count = cmpctblock.prefilledtxn.size();

    // Calculate map of txids -> positions and check mempool to see what we have (or don't)
    // Because well-formed cmpctblock messages will have a (relatively) uniform distribution
    // of short IDs, any highly-uneven distribution of elements can be safely treated as a
    // READ_STATUS_FAILED.
    std::unordered_map<uint64_t, uint16_t> shorttxids(cmpctblock.shorttxids.size());
    uint16_t index_offset = 0;
    for (size_t i = 0; i < cmpctblock.shorttxids.size(); i++) {
        while (txn_available[i + index_offset])
            index_offset++;
        shorttxids[cmpctblock.shorttxids[i]] = i + index_offset;
        // To determine the chance that the number of entries in a bucket exceeds N,
        // we use the fact that the number of elements in a single bucket is
        // binomially distributed (with n = the number of shorttxids S, and p =
        // 1 / the number of buckets), that in the worst case the number of buckets is
        // equal to S (due to std::unordered_map having a default load factor of 1.0),
        // and that the chance for any bucket to exceed N elements is at most
        // buckets * (the chance that any given bucket is above N elements).
        // Thus: P(max_elements_per_bucket > N) <= S * (1 - cdf(binomial(n=S,p=1/S), N)).
        // If we assume blocks of up to 16000, allowing 12 elements per bucket should
        // only fail once per ~1 million block transfers (per peer and connection).
        if (shorttxids.bucket_size(shorttxids.bucket(cmpctblock.shorttxids[i])) > 12)
            return READ_STATUS_FAILED;
    }
    // TODO: in the shortid-collision case, we should instead request both transactions
    // which collided. Falling back to full-block-request here is overkill.
    if (shorttxids.size() != cmpctblock.shorttxids.size())
        return READ_STATUS_FAILED; // Short ID collision

    std::vector<bool> have_txn(txn_available.size());
    {
    LOCK(pool->cs);
        for (const auto& tx : pool->mapTx) {
            uint64_t shortid = cmpctblock.GetShortID(tx.GetTx().GetWitnessHash());
            std::unordered_map<uint64_t, uint16_t>::iterator idit = shorttxids.find(shortid);
            if (idit != shorttxids.end()) {
                if (!have_txn[idit->second]) {
                    txn_available[idit->second] = tx.GetSharedTx();
                    have_txn[idit->second] = true;
                    mempool_count++;
                } else {
                    // If we find two mempool txn that match the short id, just request it.
                    // This should be rare enough that the extra bandwidth doesn't matter,
                    // but eating a round-trip due to FillBlock failure would be annoying
                    if (txn_available[idit->second]) {
                        txn_available[idit->second].reset();
                        mempool_count--;
                    }
                }
            }
            // Though ideally we'd continue scanning for the two-txn-match-shortid case,
            // the performance win of an early exit here is too good to pass up and worth
            // the extra risk.
            if (mempool_count == shorttxids.size())
                break;
        }
    }

    for (size_t i = 0; i < extra_txn.size(); i++) {
        uint64_t shortid = cmpctblock.GetShortID(extra_txn[i].first);
        std::unordered_map<uint64_t, uint16_t>::iterator idit = shorttxids.find(shortid);
        if (idit != shorttxids.end()) {
            if (!have_txn[idit->second]) {
                txn_available[idit->second] = extra_txn[i].second;
                have_txn[idit->second]  = true;
                mempool_count++;
                extra_count++;
            } else {
                // If we find two mempool/extra txn that match the short id, just
                // request it.
                // This should be rare enough that the extra bandwidth doesn't matter,
                // but eating a round-trip due to FillBlock failure would be annoying
                // Note that we don't want duplication between extra_txn and mempool to
                // trigger this case, so we compare witness hashes first
                if (txn_available[idit->second] &&
                        txn_available[idit->second]->GetWitnessHash() != extra_txn[i].second->GetWitnessHash()) {
                    txn_available[idit->second].reset();
                    mempool_count--;
                    extra_count--;
                }
            }
        }
        // Though ideally we'd continue scanning for the two-txn-match-shortid case,
        // the performance win of an early exit here is too good to pass up and worth
        // the extra risk.
        if (mempool_count == shorttxids.size())
            break;
    }

    LogPrint(BCLog::CMPCTBLOCK, "Initialized PartiallyDownloadedBlock for block %s using a cmpctblock of size %lu\n", cmpctblock.header.GetHash().ToString(), GetSerializeSize(cmpctblock));

    return READ_STATUS_OK;
}

bool PartiallyDownloadedBlock::IsTxAvailable(size_t index) const
{
    if (header.IsNull()) return false;

    assert(index < txn_available.size());
    return txn_available[index] != nullptr;
}

ReadStatus PartiallyDownloadedBlock::FillBlock(CBlock& block, const std::vector<CTransactionRef>& vtx_missing, bool segwit_active)
{
    if (header.IsNull()) return READ_STATUS_INVALID;

    uint256 hash = header.GetHash();
    block = header;
    block.posProof = posProof;
    block.vtx.resize(txn_available.size());

    size_t tx_missing_offset = 0;
    for (size_t i = 0; i < txn_available.size(); i++) {
        if (!txn_available[i]) {
            if (vtx_missing.size() <= tx_missing_offset)
                return READ_STATUS_INVALID;
            block.vtx[i] = vtx_missing[tx_missing_offset++];
        } else
            block.vtx[i] = std::move(txn_available[i]);
    }

    // Make sure we can't call FillBlock again.
    header.SetNull();
    txn_available.clear();

    if (vtx_missing.size() != tx_missing_offset)
        return READ_STATUS_INVALID;

    std::vector<CTransactionRef> component_list;
    if (m_aggregate_components) {
        // The filled list is [coinbase, components...]; the block itself is
        // [coinbase, aggregate]. The merkle root check below decides whether
        // the rebuilt aggregate is the one the header commits to.
        component_list = std::move(block.vtx);
        CTransactionRef aggregate{AggregateComponents({component_list.begin() + 1, component_list.end()})};
        if (!aggregate) return READ_STATUS_FAILED;
        block.vtx = {component_list[0], std::move(aggregate)};
    }

    // Check for possible mutations early now that we have a seemingly good block
    IsBlockMutatedFn check_mutated{m_check_block_mutated_mock ? m_check_block_mutated_mock : IsBlockMutated};
    if (check_mutated(/*block=*/block,
                       /*check_witness_root=*/segwit_active)) {
        return READ_STATUS_FAILED; // Possible Short ID collision, or a different aggregation
    }

    if (m_aggregate_components) {
        LogPrint(BCLog::CMPCTBLOCK, "Rebuilt aggregate transaction of block %s from %lu components\n", hash.ToString(), component_list.size() - 1);
    }

    LogPrint(BCLog::CMPCTBLOCK, "Successfully reconstructed block %s with %lu txn prefilled, %lu txn from mempool (incl at least %lu from extra pool) and %lu txn requested\n", hash.ToString(), prefilled_count, mempool_count, extra_count, vtx_missing.size());
    if (vtx_missing.size() < 5) {
        for (const auto& tx : vtx_missing) {
            LogPrint(BCLog::CMPCTBLOCK, "Reconstructed block %s required tx %s\n", hash.ToString(), tx->GetHash().ToString());
        }
    }

    return READ_STATUS_OK;
}
