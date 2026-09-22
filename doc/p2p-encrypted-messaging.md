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

Every quote/order is signed under a **fresh, single-use** BLS keypair
(`Transport::SignEphemeral`), so a maker's messages are not linkable to one
another or to the node.

The node's inbox is an **identity / prekey split**:

- An **identity key** — the node's stable p2pmsg address. It signs prekeys and,
  by default, is **ephemeral per run** (nothing at rest). With
  `-p2pmsgpersistidentity` the identity scalar is stored in
  `<datadir>/p2pmsg_identity.dat` so the address survives restarts — an explicit
  opt-in that trades the not-on-disk property for durable reachability.
- A rotating **inbox prekey** — the key peers actually encrypt confidential
  messages to. `getp2pmsginfo` publishes the bundle `{identity_pubkey,
  inbox_pubkey (= prekey), prekey_sig}`; a sender is expected to verify
  `prekey_sig` under `identity_pubkey` before encrypting, so a substituted
  prekey is rejected.

Rotating the prekey bounds two things without disturbing reachability:
confidential replies are linkable to one node only within an epoch, not for the
whole run; and an in-memory prekey extraction decrypts at most the current epoch
plus a bounded grace window (retired prekeys are dropped). Because the prekey is
a contact address, rotation is **manual by default** (`prekey_rotation_secs = 0`)
— trigger a privacy reset with the `rotatep2pmsginbox` RPC — with opt-in periodic
rotation via `-p2pmsginboxrotation=<secs>`.

> **Default posture, stated plainly.** With rotation off by default, a node that
> never rotates uses one static prekey for its whole run, so the session-linkage
> the rotation machinery addresses is **only mitigated when the operator opts
> in** (the `rotatep2pmsginbox` RPC, or a positive `-p2pmsginboxrotation`). The
> default is deliberate — auto-rotating a contact address breaks senders who
> cached it — but it means the mitigation is opt-in, not automatic.
>
> **Consuming half is scaffolding today.** Nothing in the node yet publishes or
> verifies a prekey bundle *over the bus*: `prekey_sig` is produced and exposed
> by `getp2pmsginfo`, but the only in-tree verifier is a unit test, and a prekey
> still reaches a sender out of band (fetched via RPC and verified by the
> sender's own tooling). Automatic default rotation is safe only once the bundle
> is published and verified on the bus, so that stays opt-in until that path
> exists — the identity key and `prekey_sig` are the groundwork for it (and for a
> future direct-message app, see the chat note under Forward secrecy).

This extends the navcoin-core BLS-ECIES posture with the identity/prekey split
and a Dandelion++ stem mapping (below).

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

Envelope (**version 2**):

```
u8            kind        // opaque application id; relay never inspects it
PoWHeader     pow         // mandatory on every message, version 2
CompactSize   flen        // 0 = no detection flag
u8[flen]      flag        // fuzzy message detection flag, 83 bytes when present
EciesPacket   enc
```

`kind` is a `PayloadKind` (`PING, PONG, AGG_ANN, CANDIDATE_TX, RFQ_REQ,
RFQ_QUOTE, ORDER_ANN, USER_DATA`, plus `8..255` reserved). The wire field is a
plain `u8`; a node that does not recognize a kind still relays the message.

`flag` is optional and empty for everything except messages a recipient may
want to retrieve after being offline — see **Fuzzy message detection** below.
A flag of exactly 83 bytes is one this build can test; other non-empty sizes
are reserved, relayed and stored unchanged but never matched, so a future
parameter change propagates without a node upgrade. Sizes above 128 bytes are
rejected.

> **Wire break.** Envelope v1 had no `flen` field and its `PoWHeader` was
> version 1. `ParseEnvelope` rejects trailing bytes, so there was no
> backward-compatible place to put the flag; v1 envelopes are rejected outright
> rather than accepted alongside, because a v1 stamp bound only the ciphertext
> and could otherwise be replayed with an attacker's flag attached.

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

`payload_hash` is version-dependent, and that is the only difference between the
two header versions — the header stays exactly 98 bytes, so the grinder and the
target arithmetic are untouched:

| version | `payload_hash` |
|---|---|
| 1 | `enc.MsgHash()` |
| 2 | `SHA256(enc.MsgHash() \|\| flag)`, with `flag` empty when `flen == 0` |

Folding the flag in means a relay can neither **strip** it (silently denying the
recipient any chance of offline retrieval) nor **rewrite** it into a third
party's detection bucket, without redoing the work. The two hashes differ even
for an empty flag, so a v1 header can never be replayed as a v2 envelope.

`bits` is runtime-tunable via `-p2pmsgpowbits=N` (DEBUG_ONLY) so regtest and
functional tests run at trivial difficulty. If CPU drift ever makes the flat
target too cheap, a `P2PMSG_POW_TARGET_V2` can be activated at a scheduled
height via the existing version-bits machinery.

The single replay cache is a `CuckooCache<uint256>` keyed by
`SHA256(kind || payload_hash)`, so it covers the flag as well as the ciphertext.
Two envelopes with identical ciphertext but different flags are distinct
messages and both relay — deliberate, since it lets a sender re-flag a
retransmission for a recipient whose clue key rotated, and each variant costs a
fresh grind. The packet hash alone does not cover
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

### Fuzzy message detection

The bus deliberately carries no recipient field, which is exactly why a node
cannot hold messages for an offline peer: a store has nothing to index on. The
node's `UserInbox` only stores what the node itself decrypted with its own
prekey, so it does nothing for a light client.

FMD closes that without reintroducing a recipient identifier. The recipient
publishes a **clue key**; a sender uses it to attach an 83-byte **flag**; the
recipient later derives a **detection key** at a false-positive rate of its own
choosing and hands it to a node that stores envelopes, which returns the
recipient's messages plus a `2^-n` fraction of everyone else's and cannot tell
the two apart.

The property that makes this worth 83 bytes per envelope: holding someone's
public clue key does **not** let you test whether a flag is theirs. Testing
needs the detection key. A plain tag such as `H(pubkey || epoch)` fails exactly
here — anyone who knows the address computes the tag — which is why one is not
used.

Scheme: FMD2 from Beck, Len, Miers and Green, *Fuzzy Message Detection*
(ePrint 2021/089, Figure 3), instantiated over BLS12-381 G1. Only the group, the
hash instantiations and the seed-derived key generation are ours.

```
gamma = 24                          // flag bits = maximum precision
clue key       = (h_1 .. h_gamma),  h_i = g^{x_i}       1152 bytes
detection key  = (x_1 .. x_n),      n <= gamma            n*32 bytes
flag           = (u, y, c_1..c_gamma)                       83 bytes
```

Flagging costs the sender `gamma + 2` group multiplications — negligible beside
the proof of work. Testing costs `n + 2` per flag, which is the per-envelope
cost of a scan and the reason retrieval has to be rate-limited and priced.

The `x_i` are **independent**. A compact variant exists that derives them from a
single scalar (`x_i = x + H(X||i)`, 48-byte clue key), and it is deliberately
not used: `H(X||i)` is public, so a detector handed a precision-`n` key recovers
`x` and can then test at full precision. Precision would stop being the
recipient's choice and become the detector's. The 1152 bytes buy that guarantee.

A detection key cannot be revoked and keeps matching future flags, so the clue
key rotates with the inbox prekey (`rotatep2pmsginbox`, or
`-p2pmsginboxrotation`) and a detection key's reach is bounded by the epoch.
Senders must verify `fmd_sig` under `identity_pubkey` before flagging: flagging
to a substituted clue key hands the retrieval side to whoever substituted it.

### Envelope archive

An archiving node keeps the flagged envelopes it relays and serves them back on
request, so a peer that was offline can pick up what it missed. Opt-in
(`-p2pmsgarchive`), advertised as `NODE_P2PMSG_ARCHIVE` (bit 26).

It stores only envelopes carrying a flag: nothing else is retrievable, so
nothing else is worth the disk. What it holds is ciphertext it cannot read, in
a LevelDB store bounded by `-p2pmsgarchivesize` (MiB) and
`-p2pmsgarchiveexpiry` (days), pruned oldest-first. Ids are monotonic and never
repeat, so a requester polls with a cursor and misses nothing that was not
pruned.

Two net messages carry it. Both fit `COMMAND_SIZE` (12) -- a longer name is
silently dead on the wire, as `getoutputdata` (13 characters) demonstrates.

```
getp2pmsgs:
  u8            version = 1
  ArchiveStamp  stamp        // u8 version, i64 timestamp, u256 query_hash, u64 nonce
  u64           cursor       // return entries with id > cursor
  u16           limit
  u8            precision    // n, so detection_key is n*32 bytes
  vector<u8>    detection_key
  i64           not_before   // 0 = no lower bound on received_at

p2pmsgs:
  u8            version = 1
  u64           next_cursor  // highest id SCANNED, not highest returned
  u8            complete     // 1 = window scanned to the end
  vector<Item>  items        // { u64 id, i64 received_at, vector<u8> envelope }
```

`next_cursor` is the highest id **scanned**, so a requester advances past ground
already covered even when nothing matched. `complete` distinguishes "you have
everything" from "I stopped at a cap and there is more" -- conflating the two
would silently lose messages. An entry that matched but did not fit in the
response is never skipped by the returned cursor.

**Cost and abuse.** A scan costs `(entries scanned) x (precision + 2)` group
multiplications: linear in exactly the two numbers the requester chooses, so
the requester pays for both.

- The query carries its own proof of work, at
  `ArchiveStampBits(base, limit, precision)` -- a base (default: the bus's own
  difficulty, `-p2pmsgarchivepowbits`) plus a term that doubles with the work
  requested, capped at base+8. The requester buys node CPU with its own CPU,
  the same bargain relay already strikes. The stamp commits to every query
  field, so a peer cannot pay for a cheap scan and then ask for an expensive
  one, and it is verified against the *capped* limit.
- Hard caps regardless of the stamp: 500 entries returned, 50 000 scanned,
  2 MiB per response.
- Queries are metered per peer (3 burst, 6/minute) on top of the stamp: the
  stamp prices the size of one query, the bucket bounds how often. Over budget
  the query is dropped silently rather than penalised -- a client syncing a
  long window legitimately issues back-to-back queries and should back off, not
  be disconnected.

**What the archive learns.** The detection key it is given, and therefore the
ability to test future flags at that precision until the clue key rotates; the
set matching it, which is the requester's messages plus `2^-n` of everyone
else's with no way to tell them apart; and the requester's address and sync
timing. Choosing a high precision for bandwidth tells the node almost exactly
which messages are yours. The choice is the requester's, which is the property
the scheme exists to provide.

The query travels in the clear on a v1 link, so an on-path observer sees the
detection key too. Clients should require an encrypted transport (BIP324, or
TLS in front of a WebSocket listener) before sending one.

**Not included:** this node never *sends* `getp2pmsgs`. Retrieval belongs to
the client that owns the detection key -- a full node reaches its own messages
through the local inbox, which is already storing them. A light client driving
this is the intended consumer.

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
- `listorders [verbose]` — standing-order cache state; with `verbose=true`
  also lists every live cached order (quote_id, buy/sell token, fill,
  sell_cost, price, declared expiry, maker session pubkey, half-tx hash
  and spent inputs — wire-public `ORDER_ANN` fields — plus two pieces of
  THIS NODE's local bookkeeping: `received` (when this node cached the
  order; the set of receive times maps the node's uptime since its last
  restart) and `effective_expiry` (`min(order_expiry, received + 14d)`,
  which leaks `received` whenever the cap binds). Fine over a private
  RPC connection; strip those two fields before republishing the output
  on a public endpoint; the array is sorted by the wire-public declared
  `order_expiry` (quote_id tie-break), so its order reveals nothing node-local
- `getp2pmsginfo` — identity, inbox prekey, `prekey_sig`, FMD clue key +
  `fmd_sig` + `fmd_gamma`, PING counter, peer counts
- `getp2pmsgdetectionkey precision` — derive a detection key at false-positive
  rate `2^-precision` (see below; the result is secret and long-lived)
- `rotatep2pmsginbox` — rotate the inbox prekey **and** the clue key
- `sendp2pmsg recipient topic payload [stem] [cluekey]` — `cluekey` attaches a
  detection flag
- `sendp2pping inbox_pubkey [stem]` — debug echo

`getp2pmsginfo` also reports `archive_peers` (connected peers advertising
`NODE_P2PMSG_ARCHIVE`) and, when this node archives, an `archive` object with
entry count, bytes, id range, retention and the query base difficulty.

## WebSocket listener

Standalone SDK clients — above all code running in a browser, which has no raw
TCP sockets — can take part in the P2P network (and therefore in the p2pmsg
bus) through an optional **WebSocket listener**:

```
-p2pwsbind=<addr>[:<port>]
```

The option is off by default, can be given several times and takes the same
`addr:port` syntax as `-bind` (`[host]:port` for IPv6). Each address becomes an
additional listening socket, alongside the ordinary `-bind`/`-port` ones.

- **Framing.** A WebSocket connection carries the *normal v1 P2P byte stream*
  (24-byte message headers, checksums, `version`/`verack`, ...). Binary frames
  are merely chunks of that stream and frame boundaries carry no meaning; the
  receiver concatenates payloads, so a client may fragment freely and a single
  P2P message may straddle frames. Text frames are a protocol error and close
  the connection. `ping` is answered with `pong`, `pong` is ignored, `close` is
  answered with `close`. Client frames must be masked (RFC 6455 §5.1); server
  frames never are. No extension is ever negotiated (`permessage-deflate` is
  ignored) and no subprotocol is required.
- **Handshake.** A standard HTTP/1.1 `GET` upgrade with `Upgrade: websocket`,
  `Connection: Upgrade`, `Sec-WebSocket-Version: 13` and `Sec-WebSocket-Key`;
  the node answers `101 Switching Protocols` with the RFC 6455
  `Sec-WebSocket-Accept`. A malformed request gets `400 Bad Request` and the
  connection is closed.
- **Same peer, same rules.** A WebSocket peer is an ordinary `inbound` peer:
  it counts against `-maxconnections`, gets `NetPermissionFlags::None` unless
  whitelisted, and is subject to the same DoS scoring, eviction and ban logic.
  It always uses the v1 transport (BIP324 is not attempted). `getpeerinfo`
  reports `"websocket": true` for such peers. Limits: the upgrade request is
  capped at 8 KiB and a single frame payload at 4 MiB.
- **No TLS.** `naviod` speaks plain `ws://` only. For `wss://` (which browsers
  require from `https://` pages) terminate TLS in a reverse proxy such as nginx
  or Caddy and forward the upgraded connection to the `-p2pwsbind` address,
  e.g. with Caddy: `reverse_proxy /p2p 127.0.0.1:8355` under a `https://`
  site block. Bind the listener to loopback or a private interface when it is
  fronted this way.

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
   TTL'd, claimed FIFO on enqueue time; the per-peer request cap keys on the
   relaying neighbour, `pfrom.GetId()`, so it is a local flood control, not
   per-requester accounting — ephemeral reply keys and stem routing leave no
   stable origin identity). A `naviod` with a loaded BLSCT wallet answers them
   by default: a serving thread (`-servecandidates`,
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

- **Unlinkability**: 1-layer ECIES + **Dandelion++ stem** (per-epoch stem
  mapping, see below) + a rotating inbox prekey under an identity that is
  ephemeral per run by default. Stronger than the plain-Dandelion navcoin-core
  posture, still weaker than onion routing against a global passive adversary; an
  optional Loopix-style mix layer is possible future work. Note
  `-p2pmsgpersistidentity` deliberately makes the *identity* stable across runs
  for reachability — a linkability trade the operator opts into.
- **Forward secrecy**: each message uses a fresh ephemeral sender key
  (ephemeral-static ECDH), so a sender's key never sits at rest. The recipient
  *prekey* is static between rotations, so replies within one prekey epoch are
  not individually forward-secret; prekey rotation (manual via
  `rotatep2pmsginbox`, or periodic via `-p2pmsginboxrotation`) bounds a prekey
  extraction to one epoch (+ grace) rather than the whole run. Full per-message
  forward secrecy would need an ephemeral-ephemeral handshake (the requester
  contributing an ephemeral prekey, X3DH-style); this is a poor fit for a
  serverless flood overlay — one-time prekeys need a directory to distribute and
  a way to prevent reuse — so it is tracked as future work. The **session-key
  path** (RFQ reply keys, aggregation reply keys) already gets per-exchange
  forward secrecy today because those keys are per-request and dropped after use;
  any future direct flow that can do an initial round-trip (e.g. a chat session)
  should ride a session key rather than the static prekey.
- **DoS**: flat-target PoW on every message, a **global** relay token bucket
  (`relay_tokens_per_sec`) capping this node's amplification, DoS scoring for
  malformed/under-PoW messages (but NOT for merely stale timestamps), silent
  drop on MAC failure, and bounded queues/caches that drop rather than grow.
  Per-source caps additionally bound the aggregation candidate pool
  (`POOL_MAX_PER_PEER`). Note the relay limiter is global, not per-peer.
- **Mixed networks**: the `NODE_P2PMSG` service bit advertises a *relay*
  capability -- that the node processes and forwards P2PMSG/DP2PMSG -- and
  `forward()` stems/broadcasts only to peers that set it. It is a routing hint
  only: it does **not** promise the node serves candidates (that is the separate
  `-servecandidates` behaviour). A node that does not run p2pmsg silently drops
  these messages without relaying, so routing to it would lose the message (a
  stem hop dead-ends, a fluff copy is wasted); the bit keeps the overlay on
  capable peers. Advertisements are unauthenticated, so a peer may set the bit
  and not actually relay (the message is then just lost, as it would be with no
  path) -- best-effort, but strictly better than routing blind.
- **Leaves (`NODE_P2PMSG_LEAF`)**: a second bit for clients that want to
  *receive* bus traffic but cannot relay it -- standalone SDK clients (browser,
  mobile) that hold one or two connections to full nodes and have no peers of
  their own to forward to. A relay fluffs `P2PMSG` to a leaf exactly as to a
  `NODE_P2PMSG` peer, so the leaf sees everything that fluffs past its node, but
  a leaf is **never** chosen as a Dandelion++ stem successor: a stem hop is a
  single unicast, and handing it to a non-relaying peer would black-hole the
  message before it ever fluffs. If a node's only p2pmsg-capable peers are
  leaves it has no stem route and fluffs instead (see below). A leaf may still
  *send* `p2pmsg`/`dp2pmsg` like any peer, under the same PoW/DoS gates.
  `getp2pmsginfo` reports `leaf_peers` (LEAF without P2PMSG) next to
  `relay_capable_peers`. A node that relays should set `NODE_P2PMSG`, not this
  bit; the leaf bit only widens delivery, never the stem set.
- **Participation is network-visible**: because `NODE_P2PMSG` is a service flag,
  it rides ADDR gossip and appears in `getpeerinfo`/`getnodeaddresses`. Enabling
  `-p2pmsg` therefore announces participation network-wide, not just to direct
  peers -- an observer can enumerate the capable set without connecting to each
  node. This is the standard service-bit trade-off (the same is true of
  `NODE_COMPACT_FILTERS` etc.), but it means p2pmsg is not a covert-participation
  feature: the fact that you relay the overlay is public, even though message
  contents and your role in any given message are not. `getp2pmsginfo` reports
  `relay_capable_peers`, the count of directly-connected peers advertising the
  bit; treat it as a lower bound, since capability propagates via ADDR beyond
  your own connections.
- **Dandelion++ stem routing**: in the stem phase a node forwards to a **single
  successor pinned for the whole epoch** (`stem_epoch_secs`, ~10 min, with a
  per-node random phase offset so rotations are not globally synchronized), not a
  fresh random successor per message. This is the defining Dandelion++
  improvement over plain Dandelion: because every stem message a node relays in
  an epoch exits through the same peer, an adversary observing that node's stem
  traffic cannot use fan-out-to-different-peers to separate messages the node
  *originated* from messages it merely *relayed*, nor learn the stem graph by
  watching successor choices vary. The successor is re-rolled only when the epoch
  rolls over or the pinned peer becomes ineligible (disconnect, or dropped the
  `NODE_P2PMSG` bit; `NODE_P2PMSG_LEAF` peers are never eligible). If no
  eligible successor exists, or the pinned successor is
  the very peer a message arrived from (which would loop), the node **fluffs**
  that message instead of dead-ending it -- privacy is preserved because the
  fluffing node is the one broadcasting. A stem successor still learns its
  immediate predecessor *relayed* the message, not that it *originated* it; a
  colluding fraction of the stem graph degrades this the usual Dandelion++ way,
  and the ECIES layer hides contents throughout. Remaining gap vs. the full
  Dandelion++ paper: no explicit embargo timer to detect a black-holing stem
  successor (a dropped stem message is recovered only when its origin re-sends);
  tracked as future work.
- **RFQ probing**: config-only matching means probing cannot binary-search a
  maker's balance; it can only enumerate advertised config.
- **Candidate-serving probing**: a served candidate is a signed self-spend of
  one real, unspent output — a proof of ownership resolvable on-chain by the
  requester (navio outpoints are output hashes anyone can derive). Serving is
  on by default (opt out with `-servecandidates=0`) and bounded against
  enumeration. The enumeration bound that matters is origin-independent: a
  rolling per-window budget on distinct coins served
  (`SERVE_MAX_COINS_PER_WINDOW`), so repeated pulling saturates instead of
  walking the coin set — this holds regardless of who asks or how the request
  is routed. Ephemeral reply keys and Dandelion stem routing mean there is no
  stable per-requester identity, so the per-peer request cap and FIFO claim
  order (on enqueue time, never on requester-chosen key bytes) are local
  relay-flood/fairness controls on the queue rather than per-origin accounting.
  A per-input reservation TTL keeps concurrent candidates spending distinct
  coins. Amounts stay blinded and a candidate cannot be
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
