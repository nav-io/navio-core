// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RFQ_MATCHER_H
#define BITCOIN_RFQ_MATCHER_H

#include <consensus/amount.h>
#include <rfq/quote.h>
#include <rfq/request.h>
#include <sync.h>
#include <uint256.h>

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace rfq {

//! Bounds on the registry's network-fed maps, so a peer flooding RFQ traffic
//! cannot grow them without limit (remote OOM). Pending matches and per-request
//! quotes both arrive from decrypted inbound messages.
static constexpr size_t MAX_PENDING_MATCHES = 4096;
static constexpr size_t MAX_QUOTES_PER_REQUEST = 256;

//! Upper bound on how far in the future a request's collection deadline may sit,
//! enforced at ingress. The pending-match map self-trims entries whose
//! `req.expiry <= now`; without a bound an attacker could set expiry = INT64_MAX
//! so their junk entries never trim and permanently fill the map (blocking a
//! maker from seeing real RFQs). One hour is far longer than any real quote
//! collection window.
static constexpr int64_t MAX_RFQ_EXPIRY_WINDOW_SECONDS = 3600;

//! How a taker ranks collected quotes.
enum class RankBy {
    Price,      //!< ascending sell_cost/fill (default): cheapest unit cost wins
    Fill,       //!< largest fill first, price as tiebreak
    LowestCost, //!< smallest absolute sell_cost
};

//! Pick the best quote for a request of `size` from `quotes`.
//!  - Filter: drop quotes whose fill < size * min_fill_ratio.
//!  - Then rank per `by`. Ties (Price): larger fill, then earlier index.
//! `min_fill_ratio` in [0,1]: 1.0 requires a full fill; <1.0 allows partials.
//! Returns the chosen quote, or nullopt if none pass the filter.
std::optional<RfqQuote> PickBest(const std::vector<RfqQuote>& quotes,
                                 CAmount size,
                                 double min_fill_ratio = 1.0,
                                 RankBy by = RankBy::Price);

//! Taker-side registry of outstanding RFQ requests and the quotes collected for
//! each. The node owns one; the wallet drives it over RPC: open a request,
//! collect inbound quotes (deduped one-shot per quote_id within a uuid), list
//! the ranked quotes, then fetch one to combine + broadcast, or cancel.
class MatcherRegistry
{
public:
    //! Open a request for collection. Returns false if the uuid already exists.
    bool OpenRequest(const RfqRequest& req) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Record an inbound quote for an open request. Returns false if the uuid is
    //! unknown or the quote_id was already seen (one-shot per quote).
    bool AddQuote(const RfqQuote& q) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! All quotes collected for `uuid` (unranked snapshot).
    std::vector<RfqQuote> GetQuotes(const uint256& uuid) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! The request itself, if open.
    std::optional<RfqRequest> GetRequest(const uint256& uuid) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Look up a specific collected quote by (uuid, quote_id). nullopt while
    //! an accept holds the request's claim (see ClaimQuote).
    std::optional<RfqQuote> GetQuote(const uint256& uuid, const uint256& quote_id) const
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! A claimed quote and the token identifying this claim.
    struct Claim {
        RfqQuote quote;
        uint64_t token{0};
    };

    //! Atomically fetch a quote AND claim its request for a single taker. Two
    //! concurrent accepts of the same uuid: only the first sees the quote; the
    //! second gets nullopt until the claim is released. Prevents building two
    //! conflicting taker halves against one order (the TOCTOU that
    //! GetQuote()+Cancel() leaves open). The request stays registered: the
    //! claimant drops it with FinishClaim() once the swap is broadcast, or
    //! hands it back with ReleaseClaim() if the accept fails, so the taker can
    //! retry. Both take the claim's token, so a stale claimant cannot touch a
    //! later claim on a request re-opened under the same uuid.
    std::optional<Claim> ClaimQuote(const uint256& uuid, const uint256& quote_id)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Make the request claimable again, if `token` still holds its claim.
    void ReleaseClaim(const uint256& uuid, uint64_t token) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Drop the request, if `token` still holds its claim.
    void FinishClaim(const uint256& uuid, uint64_t token) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Outcome of Cancel().
    enum class CancelResult {
        Cancelled, //!< the request and its quotes were dropped
        NotFound,  //!< no open request has this uuid
        Claimed,   //!< an accept holds the claim; the request is kept
    };

    //! Drop a request and its quotes. Refused while an accept holds the
    //! request's claim (see ClaimQuote): that accept may still broadcast the
    //! swap, so reporting it cancelled would be false. Retry once the claim is
    //! released; a finished claim drops the request itself.
    CancelResult Cancel(const uint256& uuid) EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    //! Open request uuids.
    std::vector<uint256> ListRequests() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    size_t Size() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    // ---- Maker side: pending requests we matched and should answer ----

    //! An inbound RFQ that matched one of our local intents; the wallet polls
    //! these, builds the quote half, and replies (encrypted to reply_key).
    struct PendingMatch {
        RfqRequest req;       //!< the requester's intent + reply_key
        CAmount fill{0};      //!< buy-token amount we should deliver
        CAmount sell_cost{0}; //!< sell-token amount we should charge
    };

    //! Record a matched inbound request to answer later. Deduped by uuid.
    void AddPendingMatch(const RfqRequest& req, CAmount fill, CAmount sell_cost)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    //! Snapshot of pending matches awaiting a wallet reply.
    std::vector<PendingMatch> ListPendingMatches() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    //! Fetch + remove a pending match by uuid (one-shot reply).
    std::optional<PendingMatch> TakePendingMatch(const uint256& uuid)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

private:
    struct Active {
        RfqRequest req;
        std::map<uint256, RfqQuote> quotes; // quote_id -> quote
        uint64_t claim{0};                  // token of the in-flight accept; 0 = none
    };
    mutable Mutex m_mutex;
    uint64_t m_last_claim GUARDED_BY(m_mutex){0};
    std::map<uint256, Active> m_active GUARDED_BY(m_mutex);
    std::map<uint256, PendingMatch> m_pending GUARDED_BY(m_mutex);
};

//! Holds a claim for the scope of one accept: releases it on destruction
//! unless Finish() ran, so every failure path (including a throw) hands the
//! request back for a retry.
class ClaimGuard
{
public:
    ClaimGuard(MatcherRegistry& reg, const uint256& uuid, uint64_t token)
        : m_reg{reg}, m_uuid{uuid}, m_token{token} {}
    ClaimGuard(const ClaimGuard&) = delete;
    ClaimGuard& operator=(const ClaimGuard&) = delete;
    ~ClaimGuard()
    {
        if (!m_finished) m_reg.ReleaseClaim(m_uuid, m_token);
    }

    //! The accept succeeded: drop the request instead of releasing it.
    void Finish()
    {
        m_finished = true;
        m_reg.FinishClaim(m_uuid, m_token);
    }

private:
    MatcherRegistry& m_reg;
    const uint256 m_uuid;
    const uint64_t m_token;
    bool m_finished{false};
};

//! Process-global handle to the active matcher registry, so the wallet module
//! can reach it (wallet RPC context is a WalletContext, not a NodeContext).
void SetActiveMatcher(MatcherRegistry* matcher);
MatcherRegistry* GetActiveMatcher();

} // namespace rfq

#endif // BITCOIN_RFQ_MATCHER_H
