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

No identity key is written to disk, and every quote/order is signed under a
**fresh, single-use** BLS keypair (`Transport::SignEphemeral`), so a maker's
messages are not linkable to one another or to the node. Note the node's
*inbox* key (the key peers encrypt confidential replies to, reported by
`getp2pmsginfo`) is generated once per process run, not per message: it is a
per-run identity, not written to disk but stable for the node's uptime. This is
the navcoin-core BLS-ECIES + Dandelion posture.

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
- The `kind` byte is passed as AEAD **associated data**, so it is
  authenticated: an attacker cannot flip the cleartext `kind` in flight to route
  the same ciphertext to a different handler (the tag check fails).
- The plaintext is **length-padded** to a small ladder of fixed bucket sizes
  before encryption (framed as `u32 length || payload || zero pad`), so the
  ciphertext length reveals only a coarse bucket, not the exact payload size.
- Decryption failure (wrong recipient, tampered ciphertext/tag, altered kind) is
  silent — the common case for broadcast traffic a node is merely relaying.

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

The single replay cache is a `CuckooCache<uint256>` keyed by
`SHA256(kind || encrypted-packet-hash)`. The packet hash alone does not cover
the `kind` byte, so keying on it would let an attacker pre-broadcast a
kind-flipped copy that arrives first and suppresses the genuine message as a
"replay"; including `kind` gives each `(kind, ciphertext)` its own slot while
staying nonce-independent (re-grinding the PoW nonce cannot bypass it, so there
is no relay amplification). It is memory-bounded (sized by `replay_cache_bytes`);
eviction is LRU/probabilistic under load rather than a fixed time-based TTL. A
message dropped because the worker ring was full is removed from the cache so a
later re-broadcast is not black-holed.

The net thread separates the two PoW rejection reasons: an under-difficulty
stamp is the sending peer's fault (DoS-scored), but a timestamp outside the
±120 s window is not — an honest message can age past it during multi-hop
propagation, so the relaying peer is not penalized for forwarding it.

## Aggregation

A candidate is a 1-input-1-output BLSCT self-spend with `input.value ==
output.value`, **zero fee**, and **no fee output** (built via
`TxFactory::BuildCandidate` / `BuildTx(emitFeeOutput=false)`: only its balance
and input signatures are produced). It does not verify standalone but
contributes a valid balance/signature to an aggregate.

`CombineHalves` builds the aggregate: union all inputs (rejecting cross-half
double-spends), union all outputs, and set the combined `txSig` to the BLS
aggregate of every half's `txSig`. BLS aggregation is associative, so the result
is a single valid signature over the union; no party shares or recomputes
another's gamma. Because candidates carry no fee output, the combined tx has
**exactly one** fee output (the initiator's), and the combined inputs and
outputs are **shuffled** — so an observer can neither count the parties by
their fee outputs nor segment the tx back into per-party runs by output order.

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

### Aggregation session loop

The loop is **pull-based**. Candidates are never broadcast in the clear: a
publicly readable candidate is a decoy any bus observer could subtract back
out of the aggregate it later appears in (its inputs/outputs are copied into
the combined transaction verbatim), reducing the anonymity set to zero against
anyone running a p2pmsg node. Instead each node privately fills its own pool:

1. **Pull** — every node runs a background `CandidatePuller` thread
   (`-candidatepullinterval`, default 60s). While its pool is below
   `POOL_TARGET` it generates a FRESH reply keypair per round, registers it as
   a transport session key (bounded TTL), and broadcasts an `AGG_ANN` request
   carrying only the reply pubkey. Pulling runs on a steady cadence decoupled
   from any actual send, so pull traffic never signals that a send is imminent.
2. **Serve** — nodes queue incoming `AGG_ANN` reply keys
   (`CandidateRequestQueue`, deduped, capped globally and per source peer,
   TTL'd, claimed FIFO on enqueue time). A `naviod` with a loaded BLSCT
   wallet answers them by default: a serving thread (`-servecandidates`,
   default on, opt out with `-servecandidates=0`;
   `-servecandidateinterval` ticks) claims queued requests and
   answers each with a fee-0 self-spend candidate built from the wallet's
   own coin, sent as a `CANDIDATE_TX` encrypted **1:1 to the requester's
   reply key**. Serving is bounded twice: a per-input reservation (TTL) so
   concurrent candidates spend distinct coins, and a rolling per-window
   budget (`SERVE_MAX_COINS_PER_WINDOW`) so a requester that keeps minting
   fresh reply keys cannot walk the wallet's coin set as reservations
   lapse. `navio-p2pmsg -producecandidates` does the
   same over RPC (`listpendingcandidaterequests` one-shot claim +
   `replycandidate`) for wallet-less orchestration. Only the requester learns
   a candidate; each producer can recognise only its own contribution in a
   later aggregate, so a PASSIVE observer can only undo the cover with every
   producer of that aggregate colluding. An ACTIVE puller is stronger: by
   requesting continuously it can come to hold a share of each serving
   wallet's candidates, later recognise those same coins when they appear as
   cover in an aggregate, and subtract them. The per-peer request cap and
   the rolling serve budget bound how fast that position can be built, and
   operators who do not want the exposure can opt out with
   `-servecandidates=0` — but the collusion argument alone should not be
   read as a guarantee against an active adversary.
3. **Collect** — the `CANDIDATE_TX` handler pools a candidate ONLY when it
   decrypted under one of the node's registered pull session keys
   (`InboundMessage::recipient == SESSION`); candidates readable under the
   inbox or broadcast key are rejected. Spent-input eviction keeps the pool
   fresh. Pool contents are node-private.
4. **Aggregate** — every wallet send RPC (`sendtoblsctaddress`, token/NFT
   sends, staking ops — anything routed through `blsct::SendTransaction`) picks
   a RANDOM subset from the pool by default (`-aggregatesends=1`), over-funds
   its own half's fee to cover the combined weight, combines behind a single
   shuffled fee output, and broadcasts. When the pool is empty or the merge
   fails the send falls back to a plain transaction, so aggregation never
   blocks a payment. `aggregatesend` remains for explicit control
   (`max_candidates`, merged-count reporting).

Wallet building always runs on the RPC/daemon/wallet-scheduler threads under
`cs_wallet`, never on the net or worker threads. The transport is enabled by
default (`-p2pmsg=1`); with a loaded BLSCT wallet both sides of the loop are on
by default — serving (`-servecandidates=0` opts out) and consumption
(`-aggregatesends=0` opts out) — so a stock node both supplies and uses cover
with zero configuration.

### Still deferred

- RFQ taker broadcast-and-collect helper RPCs and multi-TokenId swap combine.

## Security posture

- **Unlinkability**: 1-layer ECIES + Dandelion stem. Matches legacy navcoin-core.
  Weaker than onion routing against a global passive adversary; an optional
  Loopix-style mix layer is possible future work.
- **DoS**: flat-target PoW on every message, a **global** relay token bucket
  (`relay_tokens_per_sec`) capping this node's amplification, DoS scoring for
  malformed/under-PoW messages (but NOT for merely stale timestamps), silent
  drop on MAC failure, and bounded queues/caches that drop rather than grow.
  Per-source caps additionally bound the aggregation candidate pool
  (`POOL_MAX_PER_PEER`). Note the relay limiter is global, not per-peer.
- **RFQ probing**: config-only matching means probing cannot binary-search a
  maker's balance; it can only enumerate advertised config.
- **Candidate-serving probing**: a served candidate is a signed self-spend of
  one real, unspent output — a proof of ownership resolvable on-chain by the
  requester (navio outpoints are output hashes anyone can derive). Serving is
  on by default (opt out with `-servecandidates=0`) and bounded against
  enumeration: per-peer request caps, FIFO claim order on
  enqueue time (never on requester-chosen key bytes), a per-input reservation
  TTL, and a rolling per-window budget on distinct coins served
  (`SERVE_MAX_COINS_PER_WINDOW`), so repeated pulling saturates instead of
  walking the coin set. Amounts stay blinded and a candidate cannot be
  redirected or broadcast standalone.
- **Half-tx replay**: a quote signs `(uuid, half_tx hash, expiry)` under a fresh
  single-use key; the matcher is one-shot per `uuid` and first-write-wins on a
  uuid (a re-broadcast of the same uuid cannot redirect a maker's reply). The
  taker enforces the token pair (`AddQuote` rejects a quote whose pair differs
  from the request) and the quote's expiry at accept time.
- **Crypto**: per-message ephemeral BLS ECDH + ChaCha20Poly1305 + HKDF, with the
  `kind` byte bound as AEAD associated data and length-bucket padding. No
  post-quantum primitives yet; PQ migration is tracked separately.
```
