// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_P2PMSG_POW_H
#define BITCOIN_P2PMSG_POW_H

#include <arith_uint256.h>
#include <blsct/public_key.h>
#include <serialize.h>
#include <uint256.h>

#include <atomic>
#include <cstdint>
#include <span>

namespace p2pmsg {

//! Hashcash-style anti-spam stamp for broadcast request types (AGG_ANN,
//! RFQ_REQ, ORDER_ANN). Navio is PoS, so chain difficulty is not a CPU-cost
//! anchor; the target is a flat leading-zero-bits threshold, runtime-tunable
//! for tests via -p2pmsgpowbits.

//! Default difficulty in leading zero bits. A PoW attempt is one SHA256 over
//! the ~98-byte header (~15 ns / ~65M attempts/s on a modern core), so a
//! `bits`-bit target costs ~2^bits/65e6 s honest: 23 bits ≈ 100-200 ms on a
//! fast core, more on slow ones. Runtime-tunable via -p2pmsgpowbits (tests use
//! 1). Lower bits = easier.
static constexpr uint32_t DEFAULT_POW_BITS = 23;
//! Accept stamps whose timestamp is within this skew of local clock.
static constexpr int64_t POW_TIMESTAMP_TOLERANCE_SECONDS = 120;

//! PoW header versions.
//!
//! v1 committed to the ciphertext alone. v2 commits to the ciphertext AND the
//! envelope's detection flag, without changing the header's size or layout --
//! only the meaning of payload_hash. See PayloadHash() below. v1 is not
//! accepted on the wire; the two hashes differ even for an empty flag, so a v1
//! header can never be replayed as v2.
static constexpr uint8_t POW_VERSION_LEGACY = 1;
static constexpr uint8_t POW_VERSION_FLAGGED = 2;
//! What this build produces and accepts.
static constexpr uint8_t POW_VERSION_CURRENT = POW_VERSION_FLAGGED;

//! The fields a producer must commit to and grind a nonce against.
struct PoWHeader {
    uint8_t version{POW_VERSION_CURRENT};
    int64_t timestamp{0};        //!< unix seconds
    uint8_t kind{0};             //!< PayloadKind being stamped
    blsct::PublicKey session_eph;//!< session ephemeral pubkey
    //! Binds the body. v1: EciesPacket::MsgHash(). v2: SHA256(MsgHash || flag),
    //! so the detection flag is covered by the proof of work and a relay can
    //! neither strip it (silently denying the recipient offline delivery) nor
    //! rewrite it into a third party's detection bucket.
    uint256 payload_hash;
    uint64_t nonce{0};

    SERIALIZE_METHODS(PoWHeader, obj)
    {
        READWRITE(obj.version, obj.timestamp, obj.kind, obj.session_eph, obj.payload_hash, obj.nonce);
    }

    //! SHA256 over all fields (including nonce); the value PoW difficulty is
    //! checked against. (Replay detection is keyed separately by the encrypted
    //! packet's EciesPacket::MsgHash(), not this hash.)
    uint256 Hash() const;
};

//! The value payload_hash must carry for a given version, ciphertext hash and
//! flag. `flag` is the raw wire bytes and may be empty.
uint256 PayloadHash(uint8_t version, const uint256& msg_hash, std::span<const uint8_t> flag);

//! target = (2^256 - 1) >> bits. A hash is valid iff `hash < target`, i.e. it
//! has at least `bits` leading zero bits.
arith_uint256 TargetFromBits(uint32_t bits);

//! True iff `header.Hash()` meets the difficulty `bits`.
bool CheckPoW(const PoWHeader& header, uint32_t bits);

//! True iff `header.timestamp` is within POW_TIMESTAMP_TOLERANCE_SECONDS of
//! `now`. Split out from CheckStamp so callers can distinguish an honest
//! message that merely aged in flight (do not penalize the relaying peer) from
//! a genuinely under-difficulty stamp.
bool CheckTimestamp(const PoWHeader& header, int64_t now);

//! Full acceptance: difficulty AND timestamp within tolerance of `now`.
//! Replay is checked separately by the caller's shared cache.
bool CheckStamp(const PoWHeader& header, uint32_t bits, int64_t now);

//! Grind `header.nonce` until CheckPoW passes. Mutates header.nonce. For honest
//! producers and tests; returns the number of attempts. Stops at `max_iters`
//! (0 = unbounded) returning 0 if exhausted. `interrupt`, when non-null, is
//! polled periodically and Grind returns 0 promptly once it is set -- without
//! it a high-difficulty grind (e.g. the 23-bit mainnet default) on a
//! serve/pull tick would block a shutdown join for the length of the grind.
uint64_t Grind(PoWHeader& header, uint32_t bits, uint64_t max_iters = 0,
               const std::atomic<bool>* interrupt = nullptr);

} // namespace p2pmsg

#endif // BITCOIN_P2PMSG_POW_H
