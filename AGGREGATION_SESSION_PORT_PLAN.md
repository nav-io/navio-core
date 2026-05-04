# Revised AggregationSession Porting Plan: navcoin-core → navio-core

## 1. Design Philosophy

This is a **complete re-engineering**, not a literal port. The legacy `AggregationSession` (v1/v2 Tor-based, interactive multi-round signing, stempool, manual boost::asio threading) is replaced by a **v3-only, non-interactive, fully-signed, time-batched** system that plugs transparently into the wallet broadcast path.

**Core tenets:**
1. **Zero user interaction** — every BLSCT tx is auto-aggregated before broadcast.
2. **Fully signed candidates** — no signing round. Host simply calls `AggregateTransactions()`.
3. **Time-batched, not count-batched** — wait for a window, then aggregate whatever is available.
4. **Performance first** — aggregation must never block P2P, consensus, or mempool threads.
5. **Dandelion everywhere** — session announcements and final aggregated txs use Dandelion++ for anonymity.
6. **No fee for mixing** — candidates ask for `fee = 0` by default (they still pay their own tx fee).
7. **No RPC** — entirely automatic.

---

## 2. How It Works (End-to-End Flow)

### 2.1 The Happy Path
```
User calls sendtoblsctaddress()
  └─> TxFactory builds signed BLSCT tx (1+ inputs, 1+ outputs, fee paid)
  └─> CommitTransaction() detects IsBLSCT()
      └─> Instead of SubmitTxMemoryPoolAndRelay(), hands tx to AggregationSessionManager
          └─> Manager wraps it as AggregationCandidate and adds to local session pool
              └─> Session is advertised on P2P via Dandelion++

Remote peers discover the session
  └─> They encrypt their own candidates to our session pubkey
  └─> They send CAggShare via Dandelion stem to us
  └─> Our CandidateVerificationThread decrypts and validates (rate-limited)

Time window expires (e.g., 15s)
  └─> Session takes local candidate + up to 3 remote candidates
  └─> Calls AggregateTransactions() — all inputs/outputs merged, one fee output
  └─> Submits final tx to mempool via Dandelion++ (stem, then fluff)
  └─> All participants see their tx confirmed
```

### 2.2 The "Not Enough Candidates" Path
```
Time window expires, only local candidate exists
  └─> Session broadcasts the local tx as-is (no aggregation, no delay beyond window)
```

### 2.3 The "Remote Session Wins" Path
```
Local candidate is also submitted to 1 random remote session
  └─> Remote session finalizes first and broadcasts
  └─> Local session sees the input spent in mempool/block
  └─> Local session drops the candidate and does not double-spend
```

---

## 3. Architecture

### 3.1 File Layout
```
src/blsct/wallet/
  aggregation/
    candidate.h/cpp           # AggregationCandidate (wraps signed CTransactionRef)
    encrypted_share.h/cpp     # EncryptedCandidateShare (ChaCha20-Poly1305)
    session.h/cpp             # AggregationSession (host logic)
    session_manager.h/cpp     # Singleton per-node, manages local + remote sessions
    share_pow.h/cpp           # Proof-of-work for CAggShareMessage
    threads.h/cpp             # Low-priority background threads

src/net_processing.cpp
  # New handlers for P2P messages

src/protocol.h
  # New message types

src/wallet/wallet.cpp
  # Hook in CommitTransaction for BLSCT tx interception
```

### 3.2 Class Diagram
```
CWallet
  └─> AggregationSessionManager m_aggMan  [new member]

AggregationSessionManager
  ├─> m_localSession : AggregationSession    [always active when BLSCT balance > 0]
  ├─> m_remoteSessions : map<uint256, RemoteSession> [discovered via P2P]
  ├─> m_candidateQueue : Thread-safe queue of encrypted shares
  ├─> m_localCandidates : map<COutPoint, AggregationCandidate> [our own txs awaiting aggregation]
  ├─> CandidateVerificationThread()  [rate-limited, low priority]
  ├─> CollectionTimerThread()        [time window enforcement]
  └─> MaybeBroadcastAggregatedTx()   [called on timer expiry]

AggregationSession (host)
  ├─> m_sessionKeyPair : blsct::KeyPair
  ├─> m_candidates : vector<AggregationCandidate>
  ├─> m_config : {windowDuration=15s, maxCandidates=3, minCandidates=1}
  ├─> AddCandidate(share) -> bool
  ├─> TryFinalize() -> optional<CTransactionRef>
  └─> AnnounceViaDandelion()

AggregationCandidate
  ├─> tx : CTransactionRef          [FULLY SIGNED, valid BLSCT tx]
  ├─> inputOutpoint : COutPoint     [for dedup & spent tracking]
  ├─> nTime : int64_t               [arrival timestamp]
  ├─> fee : CAmount                 [always 0 for mix, but tx itself has fee]
  ├─> nTime : int64_t               [arrival timestamp]
  └─> Validate(view) -> bool

EncryptedCandidateShare
  ├─> Encrypt(hostPubKey, candidate, nonce) -> share
  └─> Decrypt(hostPrivKey) -> optional<candidate>
```

---

## 4. Data Structures

### 4.1 `blsct::AggregationCandidate`

```cpp
struct AggregationCandidate {
    //! MUST be a fully signed, valid BLSCT transaction.
    //! Recommended shape: exactly 1 input, exactly 1 BLSCT output (canonical mix tx).
    CTransactionRef tx;
    
    //! The outpoint this candidate spends. Used for dedup and spent-tracking.
    COutPoint inputOutpoint;
    
    //! Timestamp when the candidate was received/created.
    int64_t nTime;
    
    //! Fee offered to the aggregator (0 for free mixing).
    CAmount aggFee{0};
    
    //! Proof of work nonce. Must satisfy Hash(candidate) < target.
    uint64_t powNonce{0};
    
    bool Validate(const CCoinsViewCache& view, const Consensus::Params& params) const {
        // 1. Must be BLSCT
        if (!tx->IsBLSCT()) return false;
        
        // 2. Input must exist and be unspent
        if (!view.HaveCoin(inputOutpoint)) return false;
        
        // 3. Input must not already be in our mempool (race check)
        // (checked at finalize time, not here)
        
        // 4. Tx must pass standard policy checks (size, fee, etc.)
        // Note: since it's already signed, we can do a lightweight ATMP test_accept
        
        // 5. Verify PoW
        if (!CheckPoW()) return false;
        
        return true;
    }
    
    bool CheckPoW() const {
        auto h = SerializeHash(*this);
        return (UintToArith256(h) <= GetPoWTarget());
    }
    
    static arith_uint256 GetPoWTarget() {
        // Adjustable via -aggsharepowbits (default: 24 ≈ 1/16M)
        return arith_uint256(1) << (256 - gArgs.GetIntArg("-aggsharepowbits", 24));
    }
    
    SERIALIZE_METHODS(AggregationCandidate, obj) {
        READWRITE(obj.tx, obj.inputOutpoint, obj.nTime, obj.aggFee, obj.powNonce);
    }
};
```

**Why fully signed?** Because navio already has `AggregateTransactions(const std::vector<CTransactionRef>&)`. If every candidate is a complete valid tx, the host merely concatenates inputs/outputs and calls this function. No multi-round signing protocol, no coordination, no interactive latency.

### 4.2 `blsct::EncryptedCandidateShare`

```cpp
class EncryptedCandidateShare {
public:
    //! Ephemeral BLS public key from the joining peer.
    blsct::PublicKey ephemeralPubKey;
    
    //! Optional: session id to prevent cross-session decryption attempts.
    uint256 sessionId;
    
    //! ChaCha20-Poly1305 ciphertext of serialized AggregationCandidate.
    std::vector<uint8_t> ciphertext;
    
    //! Poly1305 authentication tag.
    std::array<uint8_t, 16> tag;
    
    //! Additional authenticated data = sessionId || ephemeralPubKey.
    std::vector<uint8_t> aad;
    
    static EncryptedCandidateShare Encrypt(
        const blsct::PublicKey& hostPubKey,
        const AggregationCandidate& candidate,
        const uint256& sessionId
    ) {
        // 1. Generate ephemeral BLS keypair
        auto ephemeralSk = blsct::PrivateKey::Generate();
        auto ephemeralPk = ephemeralSk.GetPublicKey();
        
        // 2. ECDH shared secret = ephemeralSk * hostPubKey
        auto sharedPoint = hostPubKey * ephemeralSk;
        
        // 3. Derive symmetric key via HKDF-SHA256
        auto sharedSecret = sharedPoint.GetHashWithSalt(0);
        std::vector<uint8_t> key = HKDF_SHA256(sharedSecret.begin(), 32, 
                                               "navio-agg-v1", 12, 32);
        
        // 4. Serialize candidate
        std::vector<uint8_t> plaintext = candidate.Serialize();
        
        // 5. Encrypt with ChaCha20-Poly1305
        auto aad = sessionId.ToVector();
        aad.insert(aad.end(), ephemeralPk.begin(), ephemeralPk.end());
        
        auto [ct, tag] = ChaCha20Poly1305_Encrypt(key, nonce, plaintext, aad);
        
        return {ephemeralPk, sessionId, ct, tag, aad};
    }
    
    std::optional<AggregationCandidate> Decrypt(
        const blsct::PrivateKey& hostPrivKey
    ) const {
        // 1. Reconstruct shared secret = hostPrivKey * ephemeralPubKey
        auto sharedPoint = ephemeralPubKey * hostPrivKey;
        auto sharedSecret = sharedPoint.GetHashWithSalt(0);
        std::vector<uint8_t> key = HKDF_SHA256(sharedSecret.begin(), 32,
                                               "navio-agg-v1", 12, 32);
        
        // 2. Decrypt
        auto plaintext = ChaCha20Poly1305_Decrypt(key, nonce, ciphertext, tag, aad);
        if (!plaintext) return std::nullopt;
        
        // 3. Deserialize
        return AggregationCandidate::Deserialize(*plaintext);
    }
    
    SERIALIZE_METHODS(EncryptedCandidateShare, obj) {
        READWRITE(obj.ephemeralPubKey, obj.sessionId, obj.ciphertext, obj.tag);
    }
};
```

**Cryptographic improvements over legacy:**
- **ChaCha20-Poly1305** (AEAD) instead of legacy `EncryptSecret` (unauthenticated AES-CBC equivalent).
- **HKDF-SHA256** key derivation instead of raw `SerializeHash(sharedKey.Serialize())`.
- **Per-candidate ephemeral key** for forward secrecy.
- **AAD includes sessionId** — prevents cross-session replay attacks.

---

## 5. P2P Protocol

### 5.1 Message Types

```cpp
// In src/protocol.h
extern const char* AGGSESSION;       //!< Announce a local aggregation session (Dandelion++)
extern const char* AGGSHARE;         //!< Submit an encrypted candidate share
extern const char* AGGGETSESSIONS;   //!< Request known aggregation sessions from peer
extern const char* AGGSESSIONS;      //!< Response with session list
```

### 5.2 `CAggSessionMessage` (Dandelion++ stem/fluff)

```cpp
class CAggSessionMessage {
public:
    uint256 sessionHash;            //!< Hash of sessionPubKey + nTime + nonce
    blsct::PublicKey sessionPubKey; //!< Ephemeral BLS pubkey for this session
    int32_t nVersion{3};            //!< Protocol version (v3 only)
    int64_t nTime;                  //!< Creation timestamp
    int64_t nWindowClose;           //!< Timestamp when collection window closes
    uint32_t nMaxCandidates{3};     //!< How many candidates host will aggregate
    CNetAddr hostAddr;              //!< Fallback address for direct connect
    
    //! PoW on session to prevent spam
    uint64_t nNonce;
    
    bool CheckPoW() const {
        auto h = SerializeHash(*this);
        return (UintToArith256(h) <= GetSessionPoWTarget());
    }
    
    static arith_uint256 GetSessionPoWTarget() {
        // Default: 20 bits ≈ 1/1M — lighter than candidate PoW
        return arith_uint256(1) << (256 - gArgs.GetIntArg("-aggsessionpowbits", 20));
    }
    
    SERIALIZE_METHODS(CAggSessionMessage, obj) { ... }
};
```

**Relay rules:**
- Sent via Dandelion++ `stem` to one random outbound peer.
- If embargo expires without fluff, or random `DANDELION_FLUFF_CHANCE` triggers, fluffed to all peers.
- Peers maintain `mapKnownAggSessions` with TTL (similar to addrman, 10 min expiry).

### 5.3 `CAggShareMessage`

```cpp
class CAggShareMessage {
public:
    uint256 sessionHash;            //!< Which session this is for
    EncryptedCandidateShare share;  //!< Encrypted candidate
    
    SERIALIZE_METHODS(CAggShareMessage, obj) {
        READWRITE(sessionHash, share);
    }
};
```

**Relay rules:**
- Sent **directly** to the session host's `NodeId` (looked up from `CAggSessionMessage` origin, or via addr).
- NOT relayed further by intermediate nodes. Direct unicast.
- Host responds with `CAggShareAck` (optional, for congestion control).

### 5.4 Dandelion++ Integration

navio already has fully working Dandelion++:
- `DANDELION_EMBARGO_MIN = 10s`, `DANDELION_EMBARGO_AVG = 20s`
- `DANDELION_FLUFF_CHANCE = 10%`
- `DANDELION_MAX_ROUTES = 2` stem peers
- `DANDELION_SHUFFLE_INTERVAL = 600s`

**Session announcements** use the same mechanism as regular txs:
1. Host calls `LocalDandelionDestinationPushInventory(inv)` where `inv.type = MSG_DANDELION_AGGSESSION`.
2. If no Dandelion route available, falls back to `RelayAggSession()` (fluff).
3. Embargo time = PoissonNextSend(now, DANDELION_EMBARGO_AVG).

**Final aggregated txs** use standard Dandelion tx broadcast (`node.chainman->ProcessTransaction(tx, false, is_stem=true)`), benefiting from existing stem/fluff anonymity.

---

## 6. Session Lifecycle

### 6.1 State Machine
```
INACTIVE ──[wallet has BLSCT balance]──> ADVERTISING
    │                                        │
    │                                        ▼
    │                                   COLLECTING
    │                        (time window: ~15s configurable)
    │                                        │
    │                    ┌───────────────────┴───────────────────┐
    │                    │ window closes                         │
    │                    ▼                                       │
    │            [candidates >= min && <= max]           [candidates < min]
    │                    │                                       │
    │                    ▼                                       ▼
    │            AGGREGATING ──> BROADCASTING            BROADCAST_SOLO
    │ (AggregateTransactions)    (Dandelion stem)      (local tx as-is)
    │                    │                                       │
    │                    └───────────────────┬───────────────────┘
    │                                        │
    ▼                                        ▼
RETURN TO ADVERTISING (immediately start new session)
```

### 6.2 Collection Window
```cpp
struct SessionConfig {
    //! How long to collect candidates before attempting aggregation.
    std::chrono::seconds windowDuration{15};
    
    //! Minimum candidates to aggregate (including local).
    size_t minCandidates{2};  // local + 1 remote
    
    //! Maximum candidates to aggregate.
    size_t maxCandidates{4};  // local + 3 remote
    
    //! How long to hold a candidate before considering it stale.
    std::chrono::seconds candidateTtl{60};
    
    //! Max encrypted shares to decrypt per second (rate limit).
    size_t maxDecryptPerSec{50};
};
```

**Why time-batched?**
- Privacy: a fixed-size batch reveals the number of participants once the tx hits the chain. A time window reveals only the time distribution, which is harder to deanonymize.
- UX: users don't wait indefinitely for "enough" candidates. Their tx goes out within ~15s guaranteed.
- Performance: predictable CPU bursts. Decrypt/validate runs on a background thread; main threads unaffected.

### 6.3 Finalization Algorithm
```cpp
std::optional<CTransactionRef> AggregationSession::TryFinalize() {
    LOCK(m_candidates_mutex);
    
    // 1. Remove stale / already-spent candidates
    CleanCandidates();
    
    // 2. Find our local candidate (if any)
    auto localIt = std::find_if(m_candidates.begin(), m_candidates.end(),
        [](const auto& c) { return c.isLocal; });
    
    bool hasLocal = localIt != m_candidates.end();
    size_t nRemote = m_candidates.size() - (hasLocal ? 1 : 0);
    
    // 3. If we have a local tx and at least 1 remote, aggregate
    if (hasLocal && nRemote >= 1) {
        std::vector<CTransactionRef> txs;
        txs.push_back(localIt->tx);
        
        // Add up to maxCandidates-1 remote candidates
        size_t added = 0;
        for (const auto& c : m_candidates) {
            if (c.isLocal) continue;
            if (added >= m_config.maxCandidates - 1) break;
            txs.push_back(c.tx);
            added++;
        }
        
        // 4. Call navio's existing aggregation
        return blsct::AggregateTransactions(txs);
    }
    
    // 4. If only remote candidates exist and we're nice, we can aggregate them too
    //    (but we get no fee from this). Optional: only aggregate if >= 2 remotes.
    if (!hasLocal && m_candidates.size() >= 2) {
        std::vector<CTransactionRef> txs;
        for (const auto& c : m_candidates) {
            txs.push_back(c.tx);
        }
        return blsct::AggregateTransactions(txs);
    }
    
    // 5. Not enough candidates
    return std::nullopt;
}
```

**If no aggregation possible:**
- If local candidate exists, broadcast it solo.
- Start a new session immediately.

---

## 7. Wallet Broadcast Hook

### 7.1 Modified `CWallet::CommitTransaction`

```cpp
void CWallet::CommitTransaction(CTransactionRef tx, mapValue_t mapValue, 
                                std::vector<std::pair<std::string, std::string>> orderForm)
{
    LOCK(cs_wallet);
    // ... existing wallet recording logic ...
    
    if (!fBroadcastTransactions) return;
    
    std::string err_string;
    
    if (tx->IsBLSCT() && m_aggMan && m_aggMan->IsEnabled()) {
        // Hand off to aggregation manager instead of broadcasting immediately
        if (m_aggMan->SubmitLocalCandidate(tx)) {
            WalletLogPrintf("Submitted BLSCT tx %s to aggregation session\n", 
                           tx->GetHash().ToString());
            return; // Aggregation manager will handle broadcast
        }
        // If submission failed (e.g., manager disabled), fall through to normal broadcast
    }
    
    if (!SubmitTxMemoryPoolAndRelay(*wtx, err_string, true)) {
        // ... existing error handling ...
    }
}
```

### 7.2 Modified `CWallet::SubmitTxMemoryPoolAndRelay`

No changes needed for direct calls. The aggregation manager owns the `CTransactionRef` and calls `chain().broadcastTransaction()` when it's time to broadcast the aggregated result.

### 7.3 Aggregation Manager Submit Path

```cpp
bool AggregationSessionManager::SubmitLocalCandidate(CTransactionRef tx) {
    if (!m_localSession || !m_localSession->IsActive()) {
        // Try to start a new session
        if (!StartNewLocalSession()) return false;
    }
    
    // Build candidate (lightweight wrap)
    AggregationCandidate candidate;
    candidate.tx = tx;
    candidate.inputOutpoint = tx->vin[0].prevout; // primary input for tracking
    candidate.nTime = GetTime();
    candidate.aggFee = 0;
    
    // Compute and set PoW
    ComputePoW(candidate);
    
    // Add to local session
    m_localSession->AddLocalCandidate(candidate);
    
    // Opportunistically submit to 1 random remote session too
    // (increases chance of aggregation, but we track to prevent double-spend)
    auto remote = PickRandomRemoteSession();
    if (remote) {
        SubmitToRemoteSession(remote, candidate);
    }
    
    return true;
}
```

### 7.4 Double-Spend Prevention

Since a local candidate may be submitted to both local and remote sessions, we must ensure it is only spent once:

```cpp
void AggregationSessionManager::OnMempoolTxAdded(const CTransactionRef& tx) {
    // Called via ValidationInterface when ANY tx enters mempool
    // Check if it spends any of our tracked local candidate inputs
    for (const auto& in : tx->vin) {
        auto it = m_trackedInputs.find(in.prevout);
        if (it != m_trackedInputs.end()) {
            // Our candidate input was spent by someone (local or remote session)
            // Remove from ALL pending sessions
            RemoveCandidateFromAllSessions(in.prevout);
            m_trackedInputs.erase(it);
        }
    }
}
```

This uses the existing `ValidationInterface` mechanism, so it runs asynchronously and does not block the mempool accept path.

---

## 8. Security & DoS Mitigations

### 8.1 Proof-of-Work on Candidate Shares (`CAggShareMessage`)

```cpp
// Hashcash-style PoW on the share message itself
bool CAggShareMessage::CheckPoW() const {
    auto h = SerializeHash(*this);
    return (UintToArith256(h) <= GetSharePoWTarget());
}

static arith_uint256 GetSharePoWTarget() {
    // Default: 24 bits ≈ 1/16M
    // On a modern CPU, this takes ~5-20ms to compute.
    return arith_uint256(1) << (256 - gArgs.GetIntArg("-aggsharepowbits", 24));
}
```

**Why this matters:** Without PoW, an attacker can flood a host with millions of encrypted shares, forcing the host to burn CPU on fruitless decryption. With PoW, an attacker needs ~16M CPU-seconds to generate 1 valid share. A legitimate user needs ~10ms.

**Alternative / additional: fee-burn**
If PoW is deemed too wasteful, require the candidate tx to have an `OP_RETURN` output burning a small amount (e.g., 1000 sat) to a protocol-specific address. This is checked in `AggregationCandidate::Validate()`.

### 8.2 Rate Limits on Decryption

```cpp
void CandidateVerificationThread() {
    while (running) {
        EncryptedCandidateShare share;
        if (m_queue.try_pop_for(share, 50ms)) {
            if (m_decryptLimiter.try_acquire()) {
                ProcessShare(share);
            } else {
                // Rate limit exceeded; drop oldest share
                LogPrint(BCLog::AGGSESSION, "Decryption rate limit hit, dropping share\n");
            }
        }
    }
}
```

`m_decryptLimiter` is a token bucket (e.g., max 50/second).

### 8.3 Memory Limits

```cpp
struct SessionConfig {
    //! Max total bytes of encrypted shares stored in queue.
    size_t maxQueueBytes{10 * 1024 * 1024}; // 10 MB
    
    //! Max candidates held per session.
    size_t maxCandidatesTotal{100};
    
    //! Max remote sessions tracked.
    size_t maxRemoteSessions{50};
};
```

When limits are exceeded, oldest entries are evicted (LRU).

### 8.4 Input Conflicts

```cpp
bool AggregationSession::AddCandidate(const AggregationCandidate& c) {
    LOCK(m_candidates_mutex);
    
    // No duplicate inputs
    if (m_seenInputs.count(c.inputOutpoint)) return false;
    
    // Mempool check: if input is already in mempool, reject
    if (mempool.exists(c.inputOutpoint.hash)) return false;
    
    // Size limit
    if (m_candidates.size() >= m_config.maxCandidatesTotal) return false;
    
    m_candidates.push_back(c);
    m_seenInputs.insert(c.inputOutpoint);
    return true;
}
```

---

## 9. Performance Design

### 9.1 Priority Inversion Protection

Aggregation threads run at **lowest priority** and use **cooperative yielding**:

```cpp
void AggregationSessionManager::CandidateVerificationThread() {
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("navio-agg-ver");
    
    while (m_running) {
        // Process at most N candidates before yielding
        for (int i = 0; i < 10 && !m_queue.empty(); ++i) {
            ProcessOneCandidate();
        }
        
        // Yield unconditionally every 50ms to P2P/consensus threads
        MilliSleep(50);
    }
}
```

### 9.2 Async Decryption

Decryption + validation runs in a dedicated background thread. The main P2P thread (`ProcessMessage`) only:
1. Checks PoW (fast: single hash).
2. Appends to lock-free queue.
3. Returns immediately.

The heavy lifting (BLS scalar math, ChaCha20-Poly1305, `HaveCoin` lookup) happens in the background thread.

### 9.3 Cached Validation

Candidates are validated once on arrival and cached:
```cpp
struct CachedCandidate {
    AggregationCandidate candidate;
    bool validated{false};
    bool valid{false};
    int64_t validationTime{0};
};
```

On finalize, only mempool-race checks are re-run (O(1) per candidate).

### 9.4 No Stempool

Unlike navcoin-core, navio has no separate `CStempool`. Candidates live only in memory (in `AggregationSession`). If the node restarts, candidates are lost — this is acceptable because they are fully signed txs that can be rebroadcast by their creators.

### 9.5 Minimal Lock Contention

- `m_candidates_mutex` is held only for short operations (insert, erase, finalize).
- Queue between P2P and verification threads is lock-free (or fine-grained mutex with short critical sections).
- `CCoinsViewCache` lookups for validation are read-only and do not contend with `cs_main` if using the `CoinsTip()` view (already designed for concurrent reads).

---

## 10. Integration with Dandelion++

### 10.1 Session Announcement

```cpp
void AggregationSession::AnnounceViaDandelion() {
    uint256 hash = GetHash();
    CInv inv(MSG_DANDELION_AGGSESSION, hash);
    
    int64_t nCurrTime = GetTimeMicros();
    int64_t nEmbargo = 1000000 * DANDELION_EMBARGO_MIN + 
                       PoissonNextSend(nCurrTime, DANDELION_EMBARGO_AVG);
    
    InsertDandelionAggSessionEmbargo(hash, nEmbargo);
    
    if (!LocalDandelionDestinationPushInventory(inv)) {
        // No Dandelion route; fluff immediately
        RelayAggSession(hash);
    }
}
```

New inventory type: `MSG_DANDELION_AGGSESSION = 12` (next free after `MSG_DWTX = 7`).

### 10.2 Aggregated Tx Broadcast

Final aggregated txs are submitted via the **standard Dandelion tx path**:
```cpp
node.chainman->ProcessTransaction(aggTx, false, /*is_stem=*/ true);
```

This reuses all existing Dandelion infrastructure (embargo, fluff chance, stem routing) without any new code.

---

## 11. Testing Plan

### 11.1 Unit Tests (`src/test/blsct/aggregation/`)

| Test File | Coverage |
|-----------|----------|
| `candidate_tests.cpp` | Serialize round-trip, PoW validation, `CheckPoW()` edge cases |
| `encrypted_share_tests.cpp` | Encrypt/decrypt with known keys, tamper detection, wrong key failure |
| `session_tests.cpp` | State machine, AddCandidate dedup, TryFinalize with 1/2/3 candidates, timeout path |
| `pow_tests.cpp` | Difficulty calculation, solve time distribution |
| `integration_tests.cpp` | Full flow: create tx -> submit -> aggregate -> verify result IsBLSCT |

### 11.2 Functional Tests (`test/functional/`)

```python
# blsct_auto_aggregation.py
class BlsctAutoAggregationTest(BitcoinTestFramework):
    def test_basic_aggregation(self):
        """3 nodes send BLSCT txs simultaneously; verify they are aggregated."""
        # Each node sends 1 BLSCT tx
        # Wait for collection window
        # Check mempool: should have 1 aggregated tx with 3 inputs, 3 outputs
        
    def test_timeout_falls_back_to_solo(self):
        """1 node sends tx in isolation; should be broadcast solo after window."""
        
    def test_dandelion_anon(self):
        """Verify session announcements use stem phase; tx uses stem phase."""
        
    def test_dos_protection(self):
        """Node sends 1000 shares without PoW; verify host drops them."""
        
    def test_double_spend_prevention(self):
        """Candidate submitted to 2 sessions; verify only 1 aggregation succeeds."""
        
    def test_encrypted_share_integrity(self):
        """Tamper with ciphertext; verify host rejects during decryption."""
```

### 11.3 Sanitizer & Performance Tests

| Test | Tool | Goal |
|------|------|------|
| Memory safety | MSan | No uninitialized reads in crypto paths |
| Thread safety | TSan | No races between verification thread and finalize timer |
| DoS resilience | `bench_aggregation.cpp` | Host can process 1000 valid shares/sec without latency spike on P2P |
| Aggregation correctness | `test_navio` | `AggregateTransactions()` output passes `blsct::VerifyTx()` |

---

## 12. Configuration

```bash
# Enable/disable auto-aggregation (default: true for BLSCT wallets)
-blsctautoagg=1

# Collection window duration in seconds (default: 15)
-blsctaggwindow=15

# Max candidates per aggregation (default: 4)
-blsctaggmax=4

# PoW difficulty for candidate shares, in bits (default: 24)
-aggsharepowbits=24

# PoW difficulty for session announcements, in bits (default: 20)
-aggsessionpowbits=20

# Max decryption operations per second (default: 50)
-aggmaxdecryptps=50

# Optional: require fee-burn instead of/alongside PoW
-aggsharefeeburn=0  # satoshis to burn in OP_RETURN
```

---

## 13. Work Breakdown & Revised Estimates

| Phase | Task | Effort |
|-------|------|--------|
| A | Core data structures (`AggregationCandidate`, `EncryptedShare`, PoW helpers) | 1.5 weeks |
| B | Session logic + state machine + `AggregateTransactions()` integration | 1.5 weeks |
| C | P2P messages (`AGGSESSION`, `AGGSHARE`) + Dandelion++ integration | 2 weeks |
| D | Wallet broadcast hook (`CommitTransaction` interception) + double-spend tracking | 1 week |
| E | Background threads + rate limiting + memory limits | 1 week |
| F | Unit tests + functional tests + sanitizer fixes | 2 weeks |
| G | Benchmarking + performance tuning | 1 week |
| H | Code review + documentation | 1 week |
| **Total** | | **~11 weeks** (~2.5 months) |

---

## 14. Key Simplifications Over Legacy

| Legacy Complexity | navio Approach | Benefit |
|-------------------|----------------|---------|
| v1 Tor hidden service | Removed entirely | No boost::asio, no SOCKS5, no port binding |
| v2 simple pubkey | Removed; v3 only | Single code path |
| Interactive signing round | Removed; fully signed candidates | No `AggSigReq/AggSigReply`, no latency, no coordination failures |
| `CStempool` | Removed; standard mempool only | Less state, simpler reorgs |
| Manual `CDataStream` serialization | `SERIALIZE_METHODS` + `UnsignedTransaction` | Type-safe, maintainable |
| `EncryptSecret` (fragile AES) | ChaCha20-Poly1305 + HKDF | Authenticated encryption, forward secrecy |
| Boost threads | `std::jthread` + `CScheduler` | Modern C++, graceful shutdown |
| Dandelion as external dependency | Reuse navio's native Dandelion++ | Single anonymization layer for both sessions and txs |
| RPC commands | None | Zero attack surface, zero UX friction |
| Fee-based mixing barriers | Zero fee by default | More participants, better anonymity set |
| Count-based batching | Time-based batching | Predictable latency, better privacy |

---

## 15. Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| **Low participation** → tx always solo after timeout | Acceptable fallback; anonymity set grows over time as adoption increases. Window defaults to 15s (not minutes). |
| **Host DoS** via decryption flood | Rate-limiting (50/sec), PoW on shares (24 bits), max queue size (10MB). |
| **Double-spend** across multiple sessions | `ValidationInterface` tracks all candidate inputs; removes from all sessions on mempool entry. |
| **Host eclipse** → no remote candidates | Session announcements use Dandelion fluff if no stem route; falls back to global relay. |
| **Aggregation breaks** `AggregateTransactions()` invariant | Extensive unit tests + property-based testing (fuzz) on random tx combinations. |
| **Privacy leak** through timing | Time-batching + Dandelion stem phase hides exact origin. Host does not know which peer sent which candidate (encrypted + direct send may still leak IP, but this is inherent in any P2P protocol). |
| **Regulatory concern** with mixing | Users can disable with `-blsctautoagg=0`; mixing is opt-out, not mandatory. |

---

## 16. Summary

This revised plan transforms the legacy `AggregationSession` from a complex, Tor-dependent, interactive protocol into a **simple, fast, non-interactive** feature:

1. **Fully signed candidates** mean the host just calls `AggregateTransactions()` — no signing round, no state machine complexity.
2. **Time-batched collection** guarantees txs are broadcast within ~15s regardless of network conditions.
3. **Dandelion++ integration** provides strong anonymity for both session discovery and final tx broadcast, reusing existing navio infrastructure.
4. **Broadcast hook** makes aggregation completely transparent to users — every BLSCT tx is automatically mixed.
5. **Performance-first design** (rate limits, async decryption, low-priority threads, no stempool) ensures the node remains responsive under attack.
6. **No RPC, no fee, no interaction** — maximum participation, minimum friction.

The result is a privacy feature that "just works" for every BLSCT transaction, with a codebase that is smaller, more secure, and more maintainable than the legacy navcoin implementation.
