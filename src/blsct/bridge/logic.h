// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_BRIDGE_LOGIC_H
#define NAVIO_BLSCT_BRIDGE_LOGIC_H

#include <blsct/bridge/state.h>
#include <blsct/signature.h>
#include <coins.h>
#include <consensus/params.h>
#include <ctokens/tokenid.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <string>
#include <vector>

// NBP bridge consensus logic (navio-bridge-protocol DESIGN.md §4-§9).
// Called from BLSCT tx verification (predicate execution + balance terms),
// ConnectBlock/DisconnectBlock (checkpoints, committee snapshots) and the
// fork-choice code (dynamic finality).

namespace blsct {
class ParsedPredicate;
}
class CBlock;
class CBlockIndex;

namespace nbp {

//! Everything predicate execution needs beyond the coins view. All bridge
//! predicates are invalid when `params` is null or the bridge is inactive
//! at `height`.
struct PredicateContext {
    const Consensus::Params* params{nullptr};
    int height{0};
    uint256 txid;
    const CTxOut* out{nullptr}; // output carrying the predicate
    uint32_t voutIndex{0};
    bool fDisconnect{false};
};

//! Value the predicate feeds into the tx balance equation, under the
//! generator of `tokenId`: pseudoInput adds to the balance key (value
//! created by consensus), pseudoOutput subtracts (value destroyed).
struct BalanceTerms {
    CAmount pseudoInput{0};
    CAmount pseudoOutput{0};
    TokenId tokenId;
};

//! Validate an NBP predicate and apply (or, with ctx.fDisconnect, exactly
//! invert) its state transition on `view`. On the connect path `terms` (if
//! non-null) receives the predicate's balance contribution. Returns false
//! with a reject reason in `err`.
bool ExecuteNbpPredicate(const blsct::ParsedPredicate& pred,
                         CCoinsViewCache& view,
                         const PredicateContext& ctx,
                         BalanceTerms* terms,
                         std::string& err);

//! Spend gating for outputs created by bridge-mint transactions: immature,
//! frozen (challenge pending) and revoked outputs are unspendable
//! (DESIGN §7.4, incl. the R_max fail-safe evaluated dynamically).
bool CheckNbpSpend(const CCoinsViewCache& view,
                   const Consensus::Params& params,
                   const COutPoint& prevout,
                   int height,
                   std::string& err);

//! Verify a >=2/3-bond-weight aggregate signature over `msg` (already
//! DST-prefixed) against the committee for the period containing `height`.
//! Uses the message-augmentation aggregate scheme (each signer signs with
//! its key prepended), so rogue-key attacks are excluded without relying on
//! the registration PoP.
bool VerifyQuorum(const CCoinsViewCache& view,
                  const Consensus::Params& params,
                  int height,
                  const std::vector<unsigned char>& bitfield,
                  const blsct::Signature& aggSig,
                  const std::vector<unsigned char>& msg,
                  std::string& err);

//! Compute the canonical committee Merkle root for a stored snapshot
//! (empty-tree root when the period has no committee).
uint256 CommitteeRootForPeriod(const CCoinsViewCache& view, uint64_t period);

//! Compute the canonical PegOutRoot for an epoch from the accumulated
//! per-epoch event list.
uint256 PegOutRootForEpoch(const CCoinsViewCache& view, uint64_t epoch);

//! Block-level hooks, called at the end of ConnectBlock (all txs applied)
//! and the start of DisconnectBlock respectively. Handle: canonical
//! epoch-boundary records, committee snapshotting at period boundaries
//! (two-period lookahead), and validation + recording of an embedded
//! block checkpoint. On failure `err` carries the reject reason.
bool ConnectNbpBlock(CCoinsViewCache& view,
                     const Consensus::Params& params,
                     const CBlock& block,
                     const CBlockIndex* pindex,
                     std::string& err);
void DisconnectNbpBlock(CCoinsViewCache& view,
                        const Consensus::Params& params,
                        const CBlock& block,
                        const CBlockIndex* pindex);

//! Dynamic finality (DESIGN §5.3): the highest epoch-boundary block
//! referenced by an embedded checkpoint buried >= nFinalityBurial blocks at
//! `tipHeight`. Returns false when no such checkpoint exists.
bool GetFinalizedCheckpoint(const CCoinsViewCache& view,
                            const Consensus::Params& params,
                            int tipHeight,
                            uint256& hashOut,
                            int& heightOut);

} // namespace nbp

#endif // NAVIO_BLSCT_BRIDGE_LOGIC_H
