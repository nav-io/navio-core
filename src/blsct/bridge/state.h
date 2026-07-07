// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_BRIDGE_STATE_H
#define NAVIO_BLSCT_BRIDGE_STATE_H

#include <coins.h>
#include <consensus/amount.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>

#include <cstdint>
#include <map>
#include <vector>

// Typed accessors for the NBP bridge consensus state stored in the coins
// view's NbpStateMap overlay (navio-bridge-protocol IMPLEMENTATION.md WP1/2).
// Every mutation performed by predicate execution is designed to be exactly
// invertible so DisconnectBlock can restore state by re-executing predicates
// with fDisconnect = true — no undo data is needed.

namespace nbp {

enum class GuardianStatus : uint8_t {
    ACTIVE = 0,
    EXITING = 1,
    SLASHED = 2,
    WITHDRAWN = 3,
};

struct GuardianEntry {
    std::vector<unsigned char> pk; // 48-byte compressed G1
    CAmount bond{0};
    uint8_t status{0};
    uint32_t statusHeight{0};
    //! Restored on slash/withdraw disconnect.
    uint8_t prevStatus{0};
    uint32_t prevStatusHeight{0};
    uint32_t regHeight{0};
    uint32_t lastSppHeight{0};

    SERIALIZE_METHODS(GuardianEntry, obj)
    {
        READWRITE(obj.pk, obj.bond, obj.status, obj.statusHeight,
                  obj.prevStatus, obj.prevStatusHeight, obj.regHeight, obj.lastSppHeight);
    }

    GuardianStatus Status() const { return static_cast<GuardianStatus>(status); }
};

//! Whole registry under one key: committees are small (<= maxCommittee plus
//! inactive registrants) and snapshot building needs full iteration anyway.
struct GuardianSet {
    std::map<std::vector<unsigned char>, GuardianEntry> members;

    SERIALIZE_METHODS(GuardianSet, obj) { READWRITE(obj.members); }
};

enum class DepositStatus : uint8_t {
    MINTED = 0,
    CHALLENGED = 1,
    REVOKED_UPHELD = 2,
    REJECTED = 3, // challenge rejected; mint continues maturing
};

struct DepositRecord {
    uint8_t status{0};
    uint256 mintTxid;
    uint32_t mintHeight{0};
    uint64_t ethChainId{0};
    std::vector<unsigned char> token; // 20 bytes
    CAmount amount{0};
    std::vector<unsigned char> attBitfield; // attesters; slashed if a challenge is upheld
    uint256 challengeTxid;
    uint32_t challengeHeight{0};
    std::vector<unsigned char> challengerPk;
    uint256 resolveTxid;
    uint32_t resolveHeight{0};
    //! Serialized predecessor DepositRecord when re-minting after a
    //! timeout-revocation, so disconnect restores it exactly.
    std::vector<unsigned char> prevRecord;

    SERIALIZE_METHODS(DepositRecord, obj)
    {
        READWRITE(obj.status, obj.mintTxid, obj.mintHeight, obj.ethChainId, obj.token,
                  obj.amount, obj.attBitfield, obj.challengeTxid, obj.challengeHeight,
                  obj.challengerPk, obj.resolveTxid, obj.resolveHeight, obj.prevRecord);
    }

    DepositStatus Status() const { return static_cast<DepositStatus>(status); }

    //! Fail-safe (DESIGN §7.4): a challenge that reaches R_max without
    //! resolution revokes the mint with nobody slashed. Evaluated
    //! dynamically so no height-triggered state write is needed.
    bool IsTimeoutRevoked(int height, uint32_t resolutionWindow) const
    {
        return Status() == DepositStatus::CHALLENGED &&
               height > static_cast<int>(challengeHeight + resolutionWindow);
    }

    //! Whether the deposit id may be minted again (only after fail-safe).
    bool IsReMintable(int height, uint32_t resolutionWindow) const
    {
        return IsTimeoutRevoked(height, resolutionWindow);
    }
};

struct PegOutEvent {
    uint256 txid;
    uint256 tokenId;
    uint64_t amount{0};
    std::vector<unsigned char> ethRecipient; // 20 bytes
    uint32_t outIndex{0};

    SERIALIZE_METHODS(PegOutEvent, obj)
    {
        READWRITE(obj.txid, obj.tokenId, obj.amount, obj.ethRecipient, obj.outIndex);
    }
};

struct EpochPegOuts {
    std::vector<PegOutEvent> events;

    SERIALIZE_METHODS(EpochPegOuts, obj) { READWRITE(obj.events); }
};

struct CommitteeMember {
    std::vector<unsigned char> pk; // 48-byte compressed G1
    CAmount bond{0};

    SERIALIZE_METHODS(CommitteeMember, obj) { READWRITE(obj.pk, obj.bond); }
};

//! Members in canonical order (ascending compressed pk) — this order IS the
//! bitfield bit assignment (IMPLEMENTATION.md §3.4).
struct CommitteeSnapshot {
    std::vector<CommitteeMember> members;

    SERIALIZE_METHODS(CommitteeSnapshot, obj) { READWRITE(obj.members); }

    CAmount TotalWeight() const
    {
        CAmount w = 0;
        for (const auto& m : members) w += m.bond;
        return w;
    }
};

//! Embedded checkpoint accepted on this chain for an epoch.
struct CheckpointRecord {
    uint64_t epoch{0};
    uint256 hashT;
    uint64_t heightT{0};
    uint256 committeeRoot;
    uint256 pegOutRoot;
    uint32_t inclusionHeight{0};

    SERIALIZE_METHODS(CheckpointRecord, obj)
    {
        READWRITE(obj.epoch, obj.hashT, obj.heightT, obj.committeeRoot,
                  obj.pegOutRoot, obj.inclusionHeight);
    }
};

//! Per-wrapped-token cumulative accounting (G1 auditability).
struct TokenAggregate {
    CAmount minted{0};
    CAmount burned{0};

    SERIALIZE_METHODS(TokenAggregate, obj) { READWRITE(obj.minted, obj.burned); }
};

// --- state keys (first byte = record kind, then fixed-width id) ---

std::vector<unsigned char> KeyGuardianSet();
std::vector<unsigned char> KeyDeposit(const uint256& depositId);
//! Keyed by the minted BLSCT output's hash (== its COutPoint hash), so the
//! spend gate can look a prevout up directly.
std::vector<unsigned char> KeyMintOut(const uint256& outHash);
std::vector<unsigned char> KeyEpochPegOuts(uint64_t epoch);
std::vector<unsigned char> KeyCommittee(uint64_t period);
std::vector<unsigned char> KeyCheckpoint(uint64_t epoch);
std::vector<unsigned char> KeySppTag(uint64_t period, const uint256& tag);
std::vector<unsigned char> KeyTokenAggregate(const uint256& tokenId);

// --- typed IO over the coins view ---

template <typename T>
bool GetState(const CCoinsViewCache& view, const std::vector<unsigned char>& key, T& out)
{
    std::vector<unsigned char> raw;
    if (!view.GetNbpState(key, raw)) return false;
    try {
        DataStream ss{raw};
        ss >> out;
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

template <typename T>
void SetState(CCoinsViewCache& view, const std::vector<unsigned char>& key, const T& value)
{
    DataStream ss;
    ss << value;
    const auto bytes = MakeUCharSpan(ss);
    view.SetNbpState(key, std::vector<unsigned char>(bytes.begin(), bytes.end()));
}

inline void EraseState(CCoinsViewCache& view, const std::vector<unsigned char>& key)
{
    view.EraseNbpState(key);
}

} // namespace nbp

#endif // NAVIO_BLSCT_BRIDGE_STATE_H
