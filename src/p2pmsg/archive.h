// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_P2PMSG_ARCHIVE_H
#define BITCOIN_P2PMSG_ARCHIVE_H

#include <p2pmsg/fmd.h>
#include <p2pmsg/pow.h>

#include <serialize.h>
#include <sync.h>
#include <uint256.h>
#include <util/fs.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

class CDBWrapper;
class CDBBatch;

namespace p2pmsg {

/**
 * Retention of relayed, FLAGGED envelopes so a peer that was offline can pick
 * up what it missed.
 *
 * The node's UserInbox keeps only what the node itself decrypted with its own
 * prekey, which is nothing at all for a light client. This store is the other
 * half: it keeps CIPHERTEXT the node merely relayed, and hands back the subset
 * matching a detection key the requester supplies.
 *
 * It learns nothing about who a stored envelope is for until someone presents
 * a detection key, and even then it gets the requester's messages plus a
 * 2^-precision fraction of everyone else's with no way to tell them apart.
 * See p2pmsg/fmd.h.
 *
 * Only envelopes carrying a flag are stored: nothing else is retrievable, so
 * nothing else is worth the disk.
 */

//! Defaults for the archive's growth bounds.
static constexpr uint64_t DEFAULT_ARCHIVE_MB = 4096;
static constexpr uint64_t DEFAULT_ARCHIVE_EXPIRY_DAYS = 14;
//! Archiving is opt-in: it costs disk and makes the node a service.
static constexpr bool DEFAULT_ARCHIVE_ENABLE = false;

//! Hard caps on a single query, enforced regardless of the stamp the requester
//! paid. A scan costs (entries scanned) x (precision + 2) group
//! multiplications, which is linear in exactly the two numbers the REQUESTER
//! chooses -- so both are bounded here and priced in ArchiveStampBits().
static constexpr uint16_t MAX_ARCHIVE_LIMIT = 500;
static constexpr size_t MAX_ARCHIVE_SCAN_ENTRIES = 50000;
static constexpr size_t MAX_ARCHIVE_RESPONSE_BYTES = 2 * 1024 * 1024;
//! Token bucket per peer: sustained rate and burst.
static constexpr int64_t ARCHIVE_QUERIES_PER_MINUTE = 6;
static constexpr int64_t ARCHIVE_QUERY_BURST = 3;

/**
 * Proof of work on an archive QUERY.
 *
 * Deliberately not PoWHeader: that header carries a session ephemeral PUBKEY
 * and a payload kind, neither of which means anything for a query, and its
 * pubkey field cannot even encode a placeholder (an all-zero G1 point is not a
 * valid compressed encoding). This is the same flat hashcash over the fields
 * that actually exist.
 *
 * The requester buys node CPU with its own CPU -- the same bargain the bus
 * already strikes for relay.
 */
struct ArchiveStamp {
    uint8_t version{1};
    int64_t timestamp{0}; //!< unix seconds
    uint256 query_hash;   //!< commits to the query fields
    uint64_t nonce{0};

    SERIALIZE_METHODS(ArchiveStamp, obj)
    {
        READWRITE(obj.version, obj.timestamp, obj.query_hash, obj.nonce);
    }

    uint256 Hash() const;
};

//! Difficulty for a query: `base` plus a term that grows with the work asked
//! for, clamped to base+8. A small cheap query costs the base; the largest
//! allowed one costs 256x more. Keep in sync with the requester's grinder.
uint32_t ArchiveStampBits(uint32_t base_bits, uint16_t limit, uint8_t precision);

//! Grind `stamp.nonce` until it meets `bits`. Returns attempts, 0 if exhausted.
uint64_t GrindArchiveStamp(ArchiveStamp& stamp, uint32_t bits, uint64_t max_iters = 0);

//! `getp2pmsgs`: ask an archiving peer for flagged envelopes it relayed.
struct ArchiveRequest {
    uint8_t version{1};
    ArchiveStamp stamp;
    uint64_t cursor{0};  //!< return entries with id > cursor
    uint16_t limit{0};   //!< max entries returned; the node caps it
    uint8_t precision{0};//!< n, so the detection key is n * 32 bytes
    std::vector<uint8_t> detection_key;
    int64_t not_before{0}; //!< 0 = no lower bound on received_at

    SERIALIZE_METHODS(ArchiveRequest, obj)
    {
        READWRITE(obj.version, obj.stamp, obj.cursor, obj.limit, obj.precision,
                  obj.detection_key, obj.not_before);
    }

    //! What stamp.query_hash must equal: SHA256 over the query fields, which
    //! is everything except the stamp itself.
    uint256 QueryHash() const;
};

//! `p2pmsgs`: the matching envelopes.
struct ArchiveResponse {
    struct Item {
        uint64_t id{0};
        int64_t received_at{0};
        std::vector<uint8_t> envelope;

        SERIALIZE_METHODS(Item, obj) { READWRITE(obj.id, obj.received_at, obj.envelope); }
    };

    uint8_t version{1};
    //! Highest id SCANNED, not highest returned. A requester advances its
    //! cursor to this and never re-scans ground already covered, even when
    //! nothing matched.
    uint64_t next_cursor{0};
    //! 1 = the requested window was scanned to the end. 0 = the node stopped
    //! at a cap and there is more. "You have everything" and "I stopped early"
    //! must never be ambiguous, or a requester silently loses messages.
    uint8_t complete{0};
    std::vector<Item> items;

    SERIALIZE_METHODS(ArchiveResponse, obj)
    {
        READWRITE(obj.version, obj.next_cursor, obj.complete, obj.items);
    }
};

class EnvelopeArchive
{
public:
    struct Options {
        fs::path path;
        size_t max_total_bytes{DEFAULT_ARCHIVE_MB << 20};
        int64_t expiry_seconds{int64_t{DEFAULT_ARCHIVE_EXPIRY_DAYS} * 24 * 3600};
        bool memory_only{false}; //!< tests
        bool wipe{false};
        //! Base difficulty a query must pay before the size-dependent term.
        //! Defaults to the bus's own difficulty so an archive query costs about
        //! what sending a message costs.
        uint32_t stamp_base_bits{DEFAULT_POW_BITS};
    };

    struct Entry {
        uint64_t id{0};
        int64_t received_at{0};
        uint8_t kind{0};
        std::vector<uint8_t> flag;
        std::vector<uint8_t> envelope; //!< the complete v2 envelope as relayed

        SERIALIZE_METHODS(Entry, obj)
        {
            READWRITE(obj.id, obj.received_at, obj.kind, obj.flag, obj.envelope);
        }
    };

    explicit EnvelopeArchive(Options opts);
    ~EnvelopeArchive();

    //! Store a relayed envelope, pruning oldest-first to keep the caps.
    //! Ignores unflagged envelopes: they can never be retrieved.
    std::optional<uint64_t> Add(int64_t received_at, uint8_t kind,
                                std::span<const uint8_t> flag,
                                std::span<const uint8_t> envelope)
        EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    struct ScanResult {
        std::vector<Entry> matches;
        uint64_t next_cursor{0};
        bool complete{true};
        size_t scanned{0};
    };

    //! Walk entries with id > cursor, oldest first, testing each flag against
    //! `detection_key`. Stops at whichever of max_entries / max_matches /
    //! max_bytes binds first, setting complete=false. `not_before` skips
    //! entries older than that timestamp WITHOUT testing them, so narrowing the
    //! window is the cheap way to bound a scan.
    ScanResult Scan(uint64_t cursor, std::span<const uint8_t> detection_key,
                    size_t max_entries, size_t max_matches, size_t max_bytes,
                    int64_t not_before) const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);

    uint64_t Count() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    uint64_t TotalBytes() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    uint64_t NewestId() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    uint64_t OldestId() const EXCLUSIVE_LOCKS_REQUIRED(!m_mutex);
    int64_t RetentionSeconds() const { return m_opts.expiry_seconds; }
    uint32_t StampBaseBits() const { return m_opts.stamp_base_bits; }
    uint64_t MaxTotalBytes() const { return m_opts.max_total_bytes; }

private:
    void WriteMetaLocked(CDBBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);
    void PruneLocked(int64_t now, CDBBatch& batch) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    const Options m_opts;
    mutable Mutex m_mutex;
    std::unique_ptr<CDBWrapper> m_db GUARDED_BY(m_mutex);
    uint64_t m_next_id GUARDED_BY(m_mutex){1};
    uint64_t m_total_bytes GUARDED_BY(m_mutex){0};
    uint64_t m_count GUARDED_BY(m_mutex){0};
};

//! Process-wide handle so the net thread can reach the archive without
//! threading a NodeContext through PeerManager, mirroring GetActiveTransport().
void SetActiveArchive(EnvelopeArchive* archive);
EnvelopeArchive* GetActiveArchive();

} // namespace p2pmsg

#endif // BITCOIN_P2PMSG_ARCHIVE_H
