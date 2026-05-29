// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_P2PMSG_POW_H
#define BITCOIN_P2PMSG_POW_H

#include <arith_uint256.h>
#include <blsct/public_key.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <span>

namespace p2pmsg {

//! Hashcash-style anti-spam stamp for broadcast request types (AGG_ANN,
//! RFQ_REQ, ORDER_ANN). Navio is PoS, so chain difficulty is not a CPU-cost
//! anchor; the target is a flat leading-zero-bits threshold, runtime-tunable
//! for tests via -p2pmsgpowbits.

//! Default difficulty: ~100 ms on a median 2026 CPU. Lower bits = easier.
static constexpr uint32_t DEFAULT_POW_BITS = 22;
//! Accept stamps whose timestamp is within this skew of local clock.
static constexpr int64_t POW_TIMESTAMP_TOLERANCE_SECONDS = 120;

//! The fields a producer must commit to and grind a nonce against.
struct PoWHeader {
    uint8_t version{1};
    int64_t timestamp{0};        //!< unix seconds
    uint8_t kind{0};             //!< PayloadKind being stamped
    blsct::PublicKey session_eph;//!< session ephemeral pubkey
    uint256 payload_hash;        //!< SHA256 of the payload body
    uint64_t nonce{0};

    SERIALIZE_METHODS(PoWHeader, obj)
    {
        READWRITE(obj.version, obj.timestamp, obj.kind, obj.session_eph, obj.payload_hash, obj.nonce);
    }

    //! SHA256 over all fields (including nonce). Also the replay-cache key.
    uint256 Hash() const;
};

//! target = (2^256 - 1) >> bits. A hash is valid iff `hash < target`, i.e. it
//! has at least `bits` leading zero bits.
arith_uint256 TargetFromBits(uint32_t bits);

//! True iff `header.Hash()` meets the difficulty `bits`.
bool CheckPoW(const PoWHeader& header, uint32_t bits);

//! Full acceptance: difficulty AND timestamp within tolerance of `now`.
//! Replay is checked separately by the caller's shared cache.
bool CheckStamp(const PoWHeader& header, uint32_t bits, int64_t now);

//! Grind `header.nonce` until CheckPoW passes. Mutates header.nonce. For honest
//! producers and tests; returns the number of attempts. Stops at `max_iters`
//! (0 = unbounded) returning 0 if exhausted.
uint64_t Grind(PoWHeader& header, uint32_t bits, uint64_t max_iters = 0);

} // namespace p2pmsg

#endif // BITCOIN_P2PMSG_POW_H
