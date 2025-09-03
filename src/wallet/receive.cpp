// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/txfactory_global.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <wallet/receive.h>
#include <wallet/transaction.h>
#include <wallet/wallet.h>

namespace wallet {
isminetype InputIsMine(const CWallet& wallet, const CTxIn& txin)
{
    AssertLockHeld(wallet.cs_wallet);
    const CWalletTx* prev = wallet.GetWalletTxFromOutpoint(txin.prevout);
    if (prev) {
        CTxOut utxo;
        for (auto& it : prev->tx->vout) {
            if (it.GetHash() == txin.prevout.hash) {
                utxo = it;
                break;
            }
        }
        if (utxo.IsNull()) return ISMINE_NO;
        return wallet.IsMine(utxo);
    }
    return ISMINE_NO;
}

bool AllInputsMine(const CWallet& wallet, const CTransaction& tx, const isminefilter& filter)
{
    LOCK(wallet.cs_wallet);
    for (const CTxIn& txin : tx.vin) {
        if (!(InputIsMine(wallet, txin) & filter)) return false;
    }
    return true;
}

CAmount OutputGetCredit(const CWallet& wallet, const CTxOut& txout, const isminefilter& filter, const TokenId& token_id)
{
    if (txout.tokenId != token_id) return 0;
    if (!txout.HasBLSCTRangeProof() && !MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    LOCK(wallet.cs_wallet);
    if (txout.HasBLSCTRangeProof()) {
        if (wallet.IsMine(txout) & filter) {
            CAmount ret = 0;
            auto blsct_man = wallet.GetBLSCTKeyMan();
            if (blsct_man) {
                auto result = blsct_man->RecoverOutputs({txout});
                if (result.is_completed) {
                    auto xs = result.amounts;
                    for (auto& res : xs) {
                        if (res.id == 0)
                            ret = res.amount;
                    }
                }
            }
            return ret;
        } else {
            return 0;
        }
    } else
        return ((wallet.IsMine(txout) & filter) ? txout.nValue : 0);
}

CAmount OutputGetCredit(const CWallet& wallet, const CWalletOutput& wout, const isminefilter& filter, const TokenId& token_id, bool fIgnoreImmature)
{
    auto txout = *wout.out;
    if (txout.tokenId != token_id) return 0;
    if (!txout.HasBLSCTRangeProof() && !MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    LOCK(wallet.cs_wallet);
    if (fIgnoreImmature && wallet.IsOutputImmatureCoinBase(wout))
        return 0;
    if (txout.HasBLSCTRangeProof()) {
        if (wallet.IsMine(txout) & filter) {
            return wout.blsctRecoveryData.amount;
        } else {
            return 0;
        }
    } else
        return ((wallet.IsMine(txout) & filter) ? txout.nValue : 0);
}

CAmount TxGetCredit(const CWallet& wallet, const CTransaction& tx, const isminefilter& filter, const TokenId& token_id)
{
    CAmount nCredit = 0;
    for (const CTxOut& txout : tx.vout)
    {
        if (txout.tokenId != token_id) continue;
        nCredit += OutputGetCredit(wallet, txout, filter);
        if (!MoneyRange(nCredit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nCredit;
}

bool ScriptIsChange(const CWallet& wallet, const CScript& script)
{
    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a script that is ours, but is not in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    AssertLockHeld(wallet.cs_wallet);
    if (wallet.IsMine(script))
    {
        CTxDestination address;
        if (!ExtractDestination(script, address))
            return true;
        if (!wallet.FindAddressBookEntry(address)) {
            return true;
        }
    }
    return false;
}

bool OutputIsChange(const CWallet& wallet, const CTxOut& txout, const TokenId& token_id)
{
    if (txout.tokenId != token_id) return false;
    if (txout.HasBLSCTRangeProof()) {
        auto blsct_km = wallet.GetBLSCTKeyMan();
        if (blsct_km) return blsct_km->OutputIsChange(txout);
    }
    return ScriptIsChange(wallet, txout.scriptPubKey);
}

CAmount OutputGetChange(const CWallet& wallet, const CTxOut& txout, const TokenId& token_id)
{
    AssertLockHeld(wallet.cs_wallet);
    if (txout.tokenId != token_id) return 0;
    if (!txout.HasBLSCTRangeProof() && !MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    return (OutputIsChange(wallet, txout) ? txout.nValue : 0);
}

CAmount TxGetChange(const CWallet& wallet, const CTransaction& tx, const TokenId& token_id)
{
    LOCK(wallet.cs_wallet);
    CAmount nChange = 0;
    for (const CTxOut& txout : tx.vout)
    {
        if (txout.tokenId != token_id) continue;
        nChange += OutputGetChange(wallet, txout);
        if (!MoneyRange(nChange))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nChange;
}

static CAmount GetCachableAmount(const CWallet& wallet, const CWalletTx& wtx, CWalletTx::AmountType type, const isminefilter& filter, const TokenId& token_id)
{
    if (!token_id.IsNull()) {
        return type == CWalletTx::DEBIT ? wallet.GetDebit(*wtx.tx, filter, token_id) : TxGetCredit(wallet, *wtx.tx, filter, token_id);
    }
    auto& amount = wtx.m_amounts[type];
    if (!amount.m_cached[filter]) {
        amount.Set(filter, type == CWalletTx::DEBIT ? wallet.GetDebit(*wtx.tx, filter) : TxGetCredit(wallet, *wtx.tx, filter));
        wtx.m_is_cache_empty = false;
    }
    return amount.m_value[filter];
}

static CAmount GetAmount(const CWallet& wallet, const CWalletOutput& wout, CWalletTx::AmountType type, const isminefilter& filter, const TokenId& token_id, bool fIgnoreImmature)
{
    if (wout.IsSpent() && type == CWalletTx::DEBIT) {
        return OutputGetCredit(wallet, wout, ISMINE_SPENDABLE | ISMINE_SPENDABLE_BLSCT, token_id, fIgnoreImmature);
    } else if (!wout.IsSpent() && (type == CWalletTx::CREDIT || type == CWalletTx::IMMATURE_CREDIT)) {
        return OutputGetCredit(wallet, wout, ISMINE_SPENDABLE | ISMINE_SPENDABLE_BLSCT, token_id, fIgnoreImmature);
    }

    return 0;
}

CAmount CachedTxGetCredit(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter, const TokenId& token_id)
{
    AssertLockHeld(wallet.cs_wallet);

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (wallet.IsTxImmatureCoinBase(wtx))
        return 0;

    CAmount credit = 0;
    const isminefilter get_amount_filter{filter & ISMINE_ALL};
    if (get_amount_filter) {
        // GetBalance can assume transactions in mapWallet won't change
        credit += GetCachableAmount(wallet, wtx, CWalletTx::CREDIT, get_amount_filter, token_id);
    }
    return credit;
}

CAmount CachedTxGetDebit(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter, const TokenId& token_id)
{
    if (wtx.tx->vin.empty())
        return 0;

    CAmount debit = 0;
    const isminefilter get_amount_filter{filter & ISMINE_ALL};
    if (get_amount_filter) {
        debit += GetCachableAmount(wallet, wtx, CWalletTx::DEBIT, get_amount_filter, token_id);
    }
    return debit;
}

CAmount CachedTxGetChange(const CWallet& wallet, const CWalletTx& wtx, const TokenId& token_id)
{
    if (wtx.fChangeCached)
        return wtx.nChangeCached;
    wtx.nChangeCached = TxGetChange(wallet, *wtx.tx, token_id);
    wtx.fChangeCached = true;
    return wtx.nChangeCached;
}

CAmount CachedTxGetImmatureCredit(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter, const TokenId& token_id)
{
    AssertLockHeld(wallet.cs_wallet);

    if (wallet.IsTxImmatureCoinBase(wtx) && wallet.IsTxInMainChain(wtx)) {
        return GetCachableAmount(wallet, wtx, CWalletTx::IMMATURE_CREDIT, filter, token_id);
    }

    return 0;
}

CAmount OutputGetImmatureCredit(const CWallet& wallet, const CWalletOutput& wout, const isminefilter& filter, const TokenId& token_id)
{
    AssertLockHeld(wallet.cs_wallet);
    if (wallet.IsOutputImmatureCoinBase(wout) && wallet.IsOutputInMainChain(wout)) {
        return GetAmount(wallet, wout, CWalletTx::IMMATURE_CREDIT, filter, token_id, false);
    }

    return 0;
}

CAmount CachedTxGetAvailableCredit(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter, const TokenId& token_id)
{
    AssertLockHeld(wallet.cs_wallet);

    // Avoid caching ismine for NO or ALL cases (could remove this check and simplify in the future).
    bool allow_cache = (filter & ISMINE_ALL) && (filter & ISMINE_ALL) != ISMINE_ALL;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (wallet.IsTxImmatureCoinBase(wtx))
        return 0;

    if (allow_cache && wtx.m_amounts[CWalletTx::AVAILABLE_CREDIT].m_cached[filter]) {
        return wtx.m_amounts[CWalletTx::AVAILABLE_CREDIT].m_value[filter];
    }

    bool allow_used_addresses = (filter & ISMINE_USED) || !wallet.IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE);
    CAmount nCredit = 0;
    for (unsigned int i = 0; i < wtx.tx->vout.size(); i++) {
        const CTxOut& txout = wtx.tx->vout[i];
        if (txout.tokenId != token_id) continue;
        if (!wallet.IsSpent(COutPoint(txout.GetHash())) && (allow_used_addresses || !wallet.IsSpentKey(txout.scriptPubKey))) {
            nCredit += OutputGetCredit(wallet, txout, filter, token_id);
            if (!MoneyRange(nCredit))
                throw std::runtime_error(std::string(__func__) + " : value out of range");
        }
    }

    if (allow_cache) {
        wtx.m_amounts[CWalletTx::AVAILABLE_CREDIT].Set(filter, nCredit);
        wtx.m_is_cache_empty = false;
    }

    return nCredit;
}

std::vector<StakedCommitmentInfo> GetStakedCommitmentInfo(const CWallet& wallet, const CWalletTx& wtx)
{
    AssertLockHeld(wallet.cs_wallet);

    std::vector<StakedCommitmentInfo> ret;

    for (unsigned int i = 0; i < wtx.tx->vout.size(); i++) {
        const CTxOut& txout = wtx.tx->vout[i];
        if (!wallet.IsSpent(COutPoint(txout.GetHash()))) {
            if (wallet.IsMine(txout) == ISMINE_STAKED_COMMITMENT_BLSCT) {
                ret.push_back({txout.GetHash(), i, txout.blsctData.rangeProof.Vs[0],
                               wtx.GetBLSCTRecoveryData(i).amount,
                               wtx.GetBLSCTRecoveryData(i).gamma});
            }
        }
    }

    return ret;
}

void CachedTxGetAmounts(const CWallet& wallet, const CWalletTx& wtx,
                        std::list<COutputEntry>& listReceived,
                        std::list<COutputEntry>& listSent, CAmount& nFee, const isminefilter& filter,
                        bool include_change, const TokenId& token_id)
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();

    // Compute fee:
    CAmount nDebit = CachedTxGetDebit(wallet, wtx, filter);
    CAmount nNet = 0;

    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        CAmount nValueOut = wtx.GetValueOut();
        if (wtx.tx->IsBLSCT()) {
            nNet = nDebit - nValueOut;
        } else {
            nFee = nDebit - nValueOut;
        }
    }

    LOCK(wallet.cs_wallet);

    // Sent/received.
    for (unsigned int i = 0; i < wtx.tx->vout.size(); ++i)
    {
        const CTxOut& txout = wtx.tx->vout[i];
        if (txout.tokenId != token_id) continue;
        isminetype fIsMine = wallet.IsMine(txout);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            if (OutputIsChange(wallet, txout) && (txout.HasBLSCTRangeProof() || !include_change)) continue;

        } else if (!(fIsMine & filter))
            continue;

        if (wtx.tx->IsBLSCT() && txout.IsFee())
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;

        if (txout.HasBLSCTRangeProof()) {
            auto blsct_km = wallet.GetBLSCTKeyMan();
            if (!blsct_km) {
                address = CNoDestination();
            } else {
                address = blsct_km->GetDestination(txout);
            }

            auto recoveryData = wtx.GetBLSCTRecoveryData(i);

            COutputEntry output = {address, recoveryData.amount, (int)i};

            // If we are receiving the output, add it as a "received" entry
            if (fIsMine & filter)
                listReceived.push_back(output);
        } else {
            if (!ExtractDestination(txout.scriptPubKey, address) && !txout.scriptPubKey.IsUnspendable()) {
                wallet.WalletLogPrintf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                                       wtx.GetHash().ToString());
                address = CNoDestination();
            }

            COutputEntry output = {address, txout.nValue, (int)i};

            // If we are debited by the transaction, add the output as a "sent" entry
            if (nDebit > 0 && !wtx.tx->IsBLSCT())
                listSent.push_back(output);

            // If we are receiving the output, add it as a "received" entry
            if (fIsMine & filter)
                listReceived.push_back(output);
        }
    }

    if (wtx.tx->IsBLSCT() && nDebit > 0) {
        COutputEntry output = {CNoDestination(), nNet, -1};
        listSent.push_back(output);
    }
}

bool CachedTxIsFromMe(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter)
{
    return (CachedTxGetDebit(wallet, wtx, filter) > 0);
}

bool CachedTxIsTrusted(const CWallet& wallet, const CWalletTx& wtx, std::set<uint256>& trusted_parents)
{
    AssertLockHeld(wallet.cs_wallet);
    int nDepth = wallet.GetTxDepthInMainChain(wtx);
    if (nDepth >= 1) return true;
    if (nDepth == 0 && wtx.tx->IsBLSCT()) return false;
    if (nDepth < 0) return false;
    // using wtx's cached debit
    if (!wallet.m_spend_zero_conf_change || !CachedTxIsFromMe(wallet, wtx, ISMINE_ALL)) return false;

    // Don't trust unconfirmed transactions from us unless they are in the mempool.
    if (!wtx.InMempool()) return false;

    // Trusted if all inputs are from us and are in the mempool:
    for (const CTxIn& txin : wtx.tx->vin) {
        // Transactions not sent by us: not trusted
        const CWalletTx* parent = wallet.GetWalletTxFromOutpoint(txin.prevout);
        if (parent == nullptr) return false;
        CTxOut parentOut;
        for (auto& it : parent->tx->vout) {
            if (it.GetHash() == txin.prevout.hash) {
                parentOut = it;
                break;
            }
        }
        // Check that this specific input being spent is trusted
        if (wallet.IsMine(parentOut) != ISMINE_SPENDABLE && wallet.IsMine(parentOut) != ISMINE_SPENDABLE_BLSCT) return false;
        // If we've already trusted this parent, continue
        if (trusted_parents.count(parent->GetHash())) continue;
        // Recurse to check that the parent is also trusted
        if (!CachedTxIsTrusted(wallet, *parent, trusted_parents)) return false;
        trusted_parents.insert(parent->GetHash());
    }
    return true;
}

bool IsOutputTrusted(const CWallet& wallet, const CWalletOutput& wout)
{
    AssertLockHeld(wallet.cs_wallet);
    int nDepth = wallet.GetOutputDepthInMainChain(wout);
    if (nDepth >= 1) return true;
    if (nDepth <= 0) return false;

    return true;
}

bool CachedTxIsTrusted(const CWallet& wallet, const CWalletTx& wtx)
{
    std::set<uint256> trusted_parents;
    LOCK(wallet.cs_wallet);
    return CachedTxIsTrusted(wallet, wtx, trusted_parents);
}

Balance GetBalance(const CWallet& wallet, const int min_depth, bool avoid_reuse, const TokenId& token_id)
{
    Balance ret;
    isminefilter reuse_filter = avoid_reuse ? ISMINE_NO : ISMINE_USED;
    {
        LOCK(wallet.cs_wallet);
        std::set<uint256> trusted_parents;
        for (const auto& entry : wallet.mapWallet) {
            const CWalletTx& wtx = entry.second;
            const bool is_trusted{CachedTxIsTrusted(wallet, wtx, trusted_parents)};
            const int tx_depth{wallet.GetTxDepthInMainChain(wtx)};
            const CAmount tx_credit_mine{CachedTxGetAvailableCredit(wallet, wtx, ISMINE_SPENDABLE | ISMINE_SPENDABLE_BLSCT | reuse_filter, token_id)};
            const CAmount tx_credit_staked_commitment{CachedTxGetAvailableCredit(wallet, wtx, ISMINE_STAKED_COMMITMENT_BLSCT, token_id)};
            const CAmount tx_credit_watchonly{CachedTxGetAvailableCredit(wallet, wtx, ISMINE_WATCH_ONLY | reuse_filter, token_id)};
            if (is_trusted && tx_depth >= min_depth) {
                ret.m_mine_trusted += tx_credit_mine;
                ret.m_watchonly_trusted += tx_credit_watchonly;
                ret.m_mine_staked_commitment += tx_credit_staked_commitment;
            }
            if (!is_trusted && tx_depth == 0 && wtx.InMempool()) {
                ret.m_mine_untrusted_pending += tx_credit_mine + tx_credit_staked_commitment;
                ret.m_watchonly_untrusted_pending += tx_credit_watchonly;
            }
            ret.m_mine_immature += CachedTxGetImmatureCredit(wallet, wtx, ISMINE_SPENDABLE | ISMINE_SPENDABLE_BLSCT, token_id);
            ret.m_watchonly_immature += CachedTxGetImmatureCredit(wallet, wtx, ISMINE_WATCH_ONLY, token_id);
        }
    }
    return ret;
}

Balance GetBlsctBalance(const CWallet& wallet, const int min_depth, const TokenId& token_id)
{
    Balance ret;
    {
        LOCK(wallet.cs_wallet);
        for (const auto& entry : wallet.mapOutputs) {
            const CWalletOutput& wout = entry.second;
            if (wout.IsSpent()) continue;
            const bool is_trusted{IsOutputTrusted(wallet, wout)};
            const int out_depth{wallet.GetOutputDepthInMainChain(wout)};
            const CAmount tx_credit_mine{OutputGetCredit(wallet, wout, ISMINE_SPENDABLE | ISMINE_SPENDABLE_BLSCT, token_id)};
            const CAmount tx_credit_staked_commitment{OutputGetCredit(wallet, wout, ISMINE_STAKED_COMMITMENT_BLSCT, token_id)};
            const CAmount tx_credit_watchonly{OutputGetCredit(wallet, wout, ISMINE_WATCH_ONLY, token_id)};
            if (is_trusted && out_depth >= min_depth) {
                ret.m_mine_trusted += tx_credit_mine;
                ret.m_watchonly_trusted += tx_credit_watchonly;
                ret.m_mine_staked_commitment += tx_credit_staked_commitment;
            }
            if (!is_trusted && out_depth == 0 && wout.InMempool()) {
                ret.m_mine_untrusted_pending += tx_credit_mine + tx_credit_staked_commitment;
                ret.m_watchonly_untrusted_pending += tx_credit_watchonly;
            }
            ret.m_mine_immature += OutputGetImmatureCredit(wallet, wout, ISMINE_SPENDABLE | ISMINE_SPENDABLE_BLSCT, token_id);
            ret.m_watchonly_immature += OutputGetImmatureCredit(wallet, wout, ISMINE_WATCH_ONLY, token_id);
        }
    }
    return ret;
}

std::vector<StakedCommitmentInfo> GetStakedCommitmentInfo(const CWallet& wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    std::vector<StakedCommitmentInfo> ret;

    {
        for (const auto& entry : wallet.mapWallet) {
            const CWalletTx& wtx = entry.second;
            const int tx_depth{wallet.GetTxDepthInMainChain(wtx)};
            if (tx_depth < 1) continue;
            auto scinfo = GetStakedCommitmentInfo(wallet, wtx);
            ret.insert(ret.end(), scinfo.begin(), scinfo.end());
        }
    }

    return ret;
}

std::map<CTxDestination, CAmount> GetAddressBalances(const CWallet& wallet, const TokenId& token_id)
{
    std::map<CTxDestination, CAmount> balances;

    {
        LOCK(wallet.cs_wallet);
        std::set<uint256> trusted_parents;
        for (const auto& walletEntry : wallet.mapWallet) {
            const CWalletTx& wtx = walletEntry.second;

            if (!CachedTxIsTrusted(wallet, wtx, trusted_parents))
                continue;

            if (wallet.IsTxImmatureCoinBase(wtx))
                continue;

            int nDepth = wallet.GetTxDepthInMainChain(wtx);
            if (nDepth < (CachedTxIsFromMe(wallet, wtx, ISMINE_ALL) ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < wtx.tx->vout.size(); i++) {
                const auto& output = wtx.tx->vout[i];
                if (output.tokenId != token_id) continue;

                if (output.HasBLSCTRangeProof()) {
                    auto blsct_km = wallet.GetBLSCTKeyMan();
                    CTxDestination address;
                    if (!blsct_km) {
                        address = CNoDestination();
                    } else {
                        address = blsct_km->GetDestination(output);
                    }

                    auto recoveryData = wtx.GetBLSCTRecoveryData(i);

                    CAmount n = wallet.IsSpent(COutPoint(output.GetHash())) ? 0 : recoveryData.amount;
                    balances[address] += n;
                } else {
                    CTxDestination addr;
                    if (!wallet.IsMine(output))
                        continue;
                    if (!ExtractDestination(output.scriptPubKey, addr))
                        continue;

                    CAmount n = wallet.IsSpent(COutPoint(output.GetHash())) ? 0 : output.nValue;
                    balances[addr] += n;
                }
            }
        }
    }

    return balances;
}

std::set<std::set<CTxDestination>> GetAddressGroupings(const CWallet& wallet, const TokenId& token_id)
{
    AssertLockHeld(wallet.cs_wallet);
    std::set<std::set<CTxDestination>> groupings;
    std::set<CTxDestination> grouping;

    for (const auto& walletEntry : wallet.mapWallet) {
        const CWalletTx& wtx = walletEntry.second;

        if (wtx.tx->vin.size() > 0) {
            bool any_mine = false;
            // group all input addresses with each other
            for (const CTxIn& txin : wtx.tx->vin) {
                CTxDestination address;
                if (!InputIsMine(wallet, txin)) /* If this input isn't mine, ignore it */
                    continue;
                CTxOut utxo;
                for (auto& it : wallet.mapWallet.at(txin.prevout.hash).tx->vout) {
                    if (it.GetHash() == txin.prevout.hash) {
                        utxo = it;
                        break;
                    }
                }
                if (!ExtractDestination(utxo.scriptPubKey, address))
                    continue;
                grouping.insert(address);
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine) {
                for (const CTxOut& txout : wtx.tx->vout)
                    if (OutputIsChange(wallet, txout)) {
                        CTxDestination txoutAddr;
                        if (!ExtractDestination(txout.scriptPubKey, txoutAddr))
                            continue;
                        grouping.insert(txoutAddr);
                    }
            }
            if (grouping.size() > 0) {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (const auto& txout : wtx.tx->vout)
            if (wallet.IsMine(txout)) {
                CTxDestination address;
                if (!ExtractDestination(txout.scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
    }

    std::set<std::set<CTxDestination>*> uniqueGroupings;        // a set of pointers to groups of addresses
    std::map<CTxDestination, std::set<CTxDestination>*> setmap; // map addresses to the unique group containing it
    for (const std::set<CTxDestination>& _grouping : groupings) {
        // make a set of all the groups hit by this new group
        std::set<std::set<CTxDestination>*> hits;
        std::map<CTxDestination, std::set<CTxDestination>*>::iterator it;
        for (const CTxDestination& address : _grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        std::set<CTxDestination>* merged = new std::set<CTxDestination>(_grouping);
        for (std::set<CTxDestination>* hit : hits) {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        for (const CTxDestination& element : *merged)
                    setmap[element] = merged;
    }

    std::set<std::set<CTxDestination>> ret;
    for (const std::set<CTxDestination>* uniqueGrouping : uniqueGroupings) {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}
} // namespace wallet
