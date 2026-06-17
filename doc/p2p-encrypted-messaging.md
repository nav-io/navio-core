# P2P Encrypted Messaging

An **application-agnostic, PoW-gated, encrypted broadcast bus** for Navio.

Nodes relay any well-formed p2pmsg message to their peers **regardless of
whether they understand or can decrypt it**. A message carries an opaque `kind`
byte; the relay layer never inspects it beyond keying handler dispatch on the
receiving node. This means a new application claims a new `kind` and ships a
handler in a wallet or daemon, and it propagates network-wide **with no
node-software upgrade** — existing nodes flood it blindly. Proof-of-work on
*every* message is the universal admission gate that keeps kind-blind relay safe
from amplification.

Two applications ship on the bus today:

1. **Aggregation sessions** — cover traffic for BLSCT transactions. A node
   merges single-input-single-output fee-0 "candidate" half-txs from other
   nodes into its outgoing transaction so the broadcast tx hides which outputs
   originate from whom.
2. **RFQ atomic swaps** — token/NFT swaps. A taker broadcasts a signed,
   PoW-stamped intent; passive makers reply (encrypted) with an unbalanced
   half-tx when a locally configured intent matches or a cached standing order
   matches. The taker picks the best quote, aggregates, and broadcasts.

Kinds `7..255` are reserved for future applications.

There are **no persistent node identities**. Every session uses a freshly
generated BLS keypair; the session pubkey *is* the identity and is discarded
when the session ends. No identity key is written to disk. This is the
navcoin-core BLS-ECIES + Dandelion posture.

The subsystem is enabled by default and can be turned off with `-p2pmsg=0`.

## Modules

```
src/p2pmsg/
  worker_pool.{h,cpp}   Bounded POD-job ring + worker threads for heavy crypto
  crypto.{h,cpp}        1-layer ECIES (BLS G1 ECDH + HKDF + ChaCha20Poly1305)
  pow.{h,cpp}           Flat-target hashcash anti-spam (runtime-tunable bits)
  transport.{h,cpp}     Net dispatch, envelope, replay cache, Dandelion send
src/aggregation/
  combine.{h,cpp}       Union vin/vout + BLS sig-aggregate of half-tx sigs
  pool.{h,cpp}          Sharded candidate pool, spent-input eviction
  session.{h,cpp}       Candidate-weight / over-funding fee math
src/rfq/
  request.h / quote.h   RfqRequest / RfqQuote wire structs
  intent_store.{h,cpp}  Maker-local swap intents, config-only matching
  matcher.{h,cpp}       Taker-side quote ranking
  order_cache.{h,cpp}   14-day standing-order LRU, spent-input eviction
src/rpc/p2pmsg.cpp      Debug + maker RPCs
```

## Threading model

Consensus, net, and validation threads never block on p2p-messaging work.

- **Net thread** (`PeerManagerImpl::ProcessMessage`): for `p2pmsg`/`dp2pmsg`, it
  parses the envelope, verifies PoW (one hash) for stamped kinds, checks the
  replay cache, and copies the bytes into the worker queue. No crypto.
- **`WorkerPool`**: `min(2, hw/4)` threads by default (`-onionworkers=N`). Owns
  all ECIES decryption, BLS verification, and tx combining. Fed by a bounded
  ring of fixed-size POD jobs with no per-enqueue allocation; drops on overflow.
- **`CValidationInterface`** callbacks (`CandidatePool`, `OrderCache`) run on the
  background signal scheduler and only do cheap map bookkeeping (evict entries
  whose inputs were spent).

## Wire protocol

Two net message types carry everything:

| msg | phase |
|-----|-------|
| `p2pmsg`  | fluff |
| `dp2pmsg` | Dandelion stem |

The `dp2pmsg` variant reuses the existing Dandelion stem routing
(`m_send_stem`, `ShuffleStemRoutes`) and fluffs with the same probability as
`DTX`.

Envelope:

```
u8          kind        // opaque application id; relay never inspects it
PoWHeader   pow         // mandatory on every message
EciesPacket enc
```

`kind` is a `PayloadKind` (`PING, PONG, AGG_ANN, CANDIDATE_TX, RFQ_REQ,
RFQ_QUOTE, ORDER_ANN`, plus `7..255` reserved). The wire field is a plain `u8`;
a node that does not recognize a kind still relays the message.

### Relay (app-agnostic flood)

`OnWire` (net thread) parses the envelope, verifies the mandatory PoW +
timestamp, and checks the replay cache. If the message is **new and valid**, the
node:

1. **relays it to every peer except the origin** (kind-blind), so it floods the
   network and carries applications this node may not implement; then
2. enqueues a decrypt job for its own handlers.

The replay cache doubles as the relay loop-breaker: each message is relayed at
most once per node. A new application therefore propagates network-wide with no
software upgrade on relaying nodes.

### ECIES

```
EciesPacket = G1 eph_pubkey (48) || ciphertext || u8[16] tag
```

- Sender draws a fresh ephemeral BLS keypair per message.
- Shared secret = `eph_sk * recipient_pub` (a G1 point), serialized to 48 bytes.
- `CHKDF_HMAC_SHA256_L32` derives the AEAD key from the shared secret.
- `AEADChaCha20Poly1305` encrypts with a zero nonce. The zero nonce is safe
  because the key is unique per message (fresh ephemeral key every time).
- Decryption failure (wrong recipient, tampered ciphertext/tag) is silent — the
  common case for broadcast traffic a node is merely relaying.

### Anti-spam PoW

Navio is proof-of-stake, so chain difficulty is **not** a CPU-cost anchor. The
PoW target is a flat leading-zero-bits threshold:

```
target = (2^256 - 1) >> bits           // default bits = 23 (~100-200 ms median CPU)
h = SHA256(version || timestamp || kind || session_eph || payload_hash || nonce)
accept iff h <= target
        && |now - timestamp| <= 120 s
        && h not in replay cache
```

**Every** message is stamped — PoW is the universal admission gate that makes
kind-blind relay safe (no free amplification), not an app-specific choice. The header
binds the ciphertext via `payload_hash`, so the cheap net-thread PoW check also
vouches for the body before a worker slot is spent decrypting it.

`bits` is runtime-tunable via `-p2pmsgpowbits=N` (DEBUG_ONLY) so regtest and
functional tests run at trivial difficulty. If CPU drift ever makes the flat
target too cheap, a `P2PMSG_POW_TARGET_V2` can be activated at a scheduled
height via the existing version-bits machinery.

The single replay cache is a `CuckooCache<uint256>` keyed by the encrypted
packet hash. It is memory-bounded (sized by `replay_cache_bytes`); eviction is
LRU/probabilistic under load rather than a fixed time-based TTL.

## Aggregation

A candidate is a 1-input-1-output BLSCT self-spend with `input.value ==
output.value` and **zero fee**. It does not verify standalone (it pays no fee)
but contributes a valid balance/signature to an aggregate.

`CombineHalves` builds the aggregate: union all inputs (rejecting cross-half
double-spends), union all outputs (including the zero-value fee outputs so their
PayFee predicate signatures stay covered), and set the combined `txSig` to the
BLS aggregate of every half's `txSig`. BLS aggregation is associative, so the
result is a single valid signature over the union; no party shares or recomputes
another's gamma.

**Fee.** The initiator pays the whole aggregate fee. BLSCT enforces
`fee >= weight(tx) * BLSCT_DEFAULT_FEE` and rejects more than one non-zero fee
output, so the candidates must be fee-0 and the initiator over-funds its own
half to cover the *combined* weight. `TxFactory::BuildTx` takes an
`additionalFee` argument = `sum(candidate weights) * fee_rate` for this.

`CandidatePool` keeps up to `POOL_TARGET = 20` candidates (hard caps: 512 total,
8 per source peer, 16 combined per aggregate), sharded 16 ways by input-outpoint
hash. It dedupes on input (first-seen wins) and evicts a candidate when its
input is spent in the mempool or a connected block. Candidates have no timeout —
they live until spent.

## RFQ

A maker configures `Intent{token_in, token_out, min_size, max_size, price_min,
expiry}` locally (never gossiped). Matching is **config-only**: it checks the
token pair, the size band, and expiry — it does not consult wallet balance.
This is deliberate: an RFQ prober can only learn the advertised config (which is
the offer itself), not the wallet balance. `price_min` is fixed-point,
sell-units per buy-unit scaled by 1e8.

The taker ranks collected quotes (`PickBest`): default `rank_by=price` ascending
(`sell_cost / fill`), with `rank_by=fill` and `rank_by=lowest_cost` variants and
a `min_fill_ratio` filter for partial fills.

Standing orders are broadcast pre-signed half-txs cached in `OrderCache`
(bounded 32 MiB LRU). Their effective lifetime is `min(declared expiry, 14
days)`, and they are evicted when any input is spent. Any peer holding a
matching order can answer an RFQ on behalf of an offline maker.

## RPCs

Maker / debug surface (hidden or `p2pmsg` category):

- `setswapintent token_in token_out min_size max_size price_min expiry`
- `clearswapintent intent_id`
- `listswapintents`
- `listorders` — standing-order cache state
- `getp2pmsginfo` — inbox pubkey + PING counter
- `sendp2pping inbox_pubkey [stem]` — debug echo

## Status / what is wired

Built, wired into the node, and tested:

- worker pool, ECIES, PoW, transport, net dispatch, Dandelion send;
- `CombineHalves` (verified end-to-end: real fee-0 candidates + over-funding
  initiator half → aggregate passes full `VerifyTx`);
- `CandidatePool` and `OrderCache` registered as validation interfaces with
  live spent-input eviction;
- `IntentStore` matching and quote ranking;
- the maker/debug RPCs above;
- a cross-wire PING echo functional test.

### Deferred orchestration

The following background flows are **not yet wired**; their building blocks are
all complete and tested. They are the remaining work before the full
broadcast-and-collect orchestration is enabled:

- aggregation session loop: broadcast `AGG_ANN`, responders auto-build
  candidates, initiator collects `CANDIDATE_TX`, combines, broadcasts;
  `ReplenishOwned` heuristic; `sendtoaddress aggregate=true`;
- RFQ taker loop: `requestquote` / `acceptquote` broadcast-and-collect state
  machine; passive maker auto-reply to inbound `RFQ_REQ`; multi-TokenId swap
  combine;
- standing-order gossip: wallet-built `broadcastorder` half + `ORDER_ANN`
  propagation + on-receipt caching.

These require running wallet coin selection and tx building on worker threads
(off the net/validation path) with a wallet snapshot taken under lock and
released before the heavy build. The transport subsystem itself is enabled by
default (`-p2pmsg=1`); these higher-level orchestration flows remain gated off
until they land and pass a full end-to-end functional suite.

## Security posture

- **Unlinkability**: 1-layer ECIES + Dandelion stem. Matches legacy navcoin-core.
  Weaker than onion routing against a global passive adversary; an optional
  Loopix-style mix layer is possible future work.
- **DoS**: flat-target PoW on requests, per-peer rate limiting, DoS scoring for
  malformed/under-PoW messages, silent drop on MAC failure, bounded queues and
  caches that drop rather than grow.
- **RFQ probing**: config-only matching means probing cannot binary-search a
  maker's balance; it can only enumerate advertised config.
- **Half-tx replay**: a quote signs `(uuid, half_tx hash, expiry)`; the matcher
  is one-shot per `uuid`.
- **Crypto**: per-message ephemeral BLS ECDH + ChaCha20Poly1305 + HKDF. No
  post-quantum primitives yet; PQ migration is tracked separately.
```
