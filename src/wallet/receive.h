// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_RECEIVE_H
#define BITCOIN_WALLET_RECEIVE_H

#include <consensus/amount.h>
#include <wallet/transaction.h>
#include <wallet/types.h>
#include <wallet/wallet.h>

#include <set>
#include <utility>

namespace wallet {
isminetype InputIsMine(const CWallet& wallet, const CTxIn& txin) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

/** Returns whether all of the inputs match the filter */
bool AllInputsMine(const CWallet& wallet, const CTransaction& tx, const isminefilter& filter);

CAmount OutputGetCredit(const CWallet& wallet, const CTxOut& txout, const isminefilter& filter, const TokenId& token_id = TokenId());
CAmount OutputGetCredit(const CWallet& wallet, const CWalletOutput& wout, const isminefilter& filter, const TokenId& token_id, bool fIgnoreImmature = true);
CAmount TxGetCredit(const CWallet& wallet, const CTransaction& tx, const isminefilter& filter, const TokenId& token_id = TokenId());

bool ScriptIsChange(const CWallet& wallet, const CScript& script) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
bool OutputIsChange(const CWallet& wallet, const CTxOut& txout, const TokenId& token_id = TokenId()) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
CAmount OutputGetChange(const CWallet& wallet, const CTxOut& txout, const TokenId& token_id = TokenId()) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
CAmount TxGetChange(const CWallet& wallet, const CTransaction& tx, const TokenId& token_id = TokenId());

//! A served cover candidate pays its coin back to the subaddress the coin was
//! paid to, which is usually a receive address, so OutputIsChange() does not
//! see it as change. These recognise such an output: it carries
//! blsct::COVER_CANDIDATE_MEMO, and pays the same subaddress and the same
//! amount as one of our coins spent alongside it. A payer can't fake the
//! match, since it doesn't know our amounts.
//!
//! Our BLSCT NAV coins `tx` spends, as (subaddress hash id, amount) pairs.
//! Each cover return found by OutputIsCoverReturn() uses one pair up.
using OwnSpentCoins = std::multiset<std::pair<CKeyID, CAmount>>;
OwnSpentCoins GetOwnSpentCoins(const CWallet& wallet, const CTransaction& tx) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
//! Whether output `txout` of a tx spending `spent` returns one of those coins.
bool OutputIsCoverReturn(const CWallet& wallet, const CTxOut& txout, const range_proof::RecoveredData<Blst>& recovered, OwnSpentCoins& spent) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
//! The same for an output-storage row, whose transaction the wallet does not
//! keep: it matches any of our spent coins other than the row itself.
bool OutputIsCoverReturn(const CWallet& wallet, const CWalletOutput& wout) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

CAmount CachedTxGetCredit(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter, const TokenId& token_id = TokenId())
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
//! filter decides which addresses will count towards the debit
CAmount CachedTxGetDebit(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter, const TokenId& token_id = TokenId());
CAmount CachedTxGetChange(const CWallet& wallet, const CWalletTx& wtx, const TokenId& token_id = TokenId());
CAmount CachedTxGetImmatureCredit(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter, const TokenId& token_id = TokenId())
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
CAmount OutputGetImmatureCredit(const CWallet& wallet, const CWalletOutput& wout, const isminefilter& filter, const TokenId& token_id = TokenId()) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
CAmount CachedTxGetAvailableCredit(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter = ISMINE_SPENDABLE | ISMINE_SPENDABLE_BLSCT, const TokenId& token_id = TokenId())
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
struct COutputEntry
{
    CTxDestination destination;
    CAmount amount;
    int vout;
    std::string memo;   //!< BLSCT recovery message (empty for non-BLSCT outputs)
};
void CachedTxGetAmounts(const CWallet& wallet, const CWalletTx& wtx,
                        std::list<COutputEntry>& listReceived,
                        std::list<COutputEntry>& listSent,
                        CAmount& nFee, const isminefilter& filter,
                        bool include_change, const TokenId& token_id = TokenId());
bool CachedTxIsFromMe(const CWallet& wallet, const CWalletTx& wtx, const isminefilter& filter);
bool CachedTxIsTrusted(const CWallet& wallet, const CWalletTx& wtx, std::set<uint256>& trusted_parents) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
bool CachedTxIsTrusted(const CWallet& wallet, const CWalletTx& wtx);
bool IsOutputTrusted(const CWallet& wallet, const CWalletOutput& wout) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
/**
 * Whether the trust CachedTxIsTrusted() gives `wtx` extends to its output
 * `output_hash`. Always, except in an unconfirmed aggregate this wallet built:
 * there the cover halves' inputs were not vetted, so an output they fund (one
 * a cover provider paid to us) is no safer than an unconfirmed receive. Only
 * the outputs of the wallet's own half (CWalletTx::m_own_half_outputs) are
 * covered.
 */
bool TxTrustCoversOutput(const CWallet& wallet, const CWalletTx& wtx, const uint256& output_hash) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
/**
 * Whether the mapOutputs entry at `outpoint` is already accounted for by the
 * mapWallet path, so walks over mapOutputs must skip it to avoid counting or
 * listing the output twice.
 *
 * Under WALLET_FLAG_BLSCT_OUTPUT_STORAGE, locally-created BLSCT transactions
 * are still recorded in mapWallet and their outputs are mirrored into
 * mapOutputs. The CWalletTx path of the balance and coin queries covers such
 * an output only while that CWalletTx is alive, i.e. confirmed or in the
 * mempool (a send the staker merged into a block tx under another hash counts
 * as confirmed by that block). Otherwise the mapOutputs entry, whose state
 * follows the tx that carries the output on chain or in the mempool, is the
 * record that counts.
 *
 * The transaction listings use a different rule: ListTransactions() lists a
 * CWalletTx whatever its state, so they skip a mapOutputs entry whenever it
 * has a CWalletTx at all.
 */
bool IsOutputCoveredByWalletTx(const CWallet& wallet, const COutPoint& outpoint) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

struct Balance {
    CAmount m_mine_trusted{0};           //!< Trusted, at depth=GetBalance.min_depth or more
    CAmount m_mine_staked_commitment{0}; //!< Staked commitment with >=1 confirmation
    CAmount m_mine_pending_staked_commitment{0}; //!< Trusted staked commitment in mempool only
    CAmount m_mine_untrusted_pending{0}; //!< Untrusted, but in mempool (pending)
    CAmount m_mine_immature{0};          //!< Immature coinbases in the main chain
    CAmount m_watchonly_trusted{0};
    CAmount m_watchonly_untrusted_pending{0};
    CAmount m_watchonly_immature{0};
};
Balance GetBalance(const CWallet& wallet, int min_depth = 0, bool avoid_reuse = true, const TokenId& token_id = TokenId());
Balance GetBlsctBalance(const CWallet& wallet, int min_depth = 0, const TokenId& token_id = TokenId());
//! GetBalance() and GetBlsctBalance() for every NFT of `collection` in one
//! walk, keyed by NFT subid: entry `s` is what they return for
//! TokenId(collection, s); a subid with no entry has a zero balance.
std::map<uint64_t, Balance> GetNftBalances(const CWallet& wallet, const uint256& collection, int min_depth, bool avoid_reuse);
std::map<uint64_t, Balance> GetBlsctNftBalances(const CWallet& wallet, const uint256& collection, int min_depth);

/** Trusted, spendable credit backed by BLSCT outputs of the default token.
 *
 * GetBalance() and GetBlsctBalance() are two halves of one tally: the former
 * walks mapWallet, the latter mapOutputs, and getbalance/getbalances/
 * getwalletinfo add them up. This is the same tally restricted to BLSCT
 * outputs, for getblsctbalance, whose contract is its name -- transparent
 * credit that GetBalance() folds in alongside BLSCT credit is left out.
 * Staked commitments are left out too: they cannot be spent until
 * `stakeunlock` releases them, so they are not available balance. */
struct BlsctTrustedBalance {
    CAmount m_mine{0};
    CAmount m_watchonly{0};
};
BlsctTrustedBalance GetBlsctTrustedBalance(const CWallet& wallet, int min_depth = 0) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

std::map<CTxDestination, CAmount> GetAddressBalances(const CWallet& wallet, const TokenId& token_id = TokenId());
std::set<std::set<CTxDestination>> GetAddressGroupings(const CWallet& wallet, const TokenId& token_id = TokenId()) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);

struct StakedCommitmentInfo {
    Txid hashTx;
    size_t nout;
    BlstG1Point commitment;
    BlstScalar value;
    BlstScalar gamma;
};

std::vector<StakedCommitmentInfo>
GetStakedCommitmentInfo(const CWallet& wallet, const CWalletTx& wtx) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
std::vector<StakedCommitmentInfo> GetStakedCommitmentInfo(const CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
} // namespace wallet

#endif // BITCOIN_WALLET_RECEIVE_H
