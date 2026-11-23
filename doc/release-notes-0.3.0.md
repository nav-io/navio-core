Navio Core version 0.3.0 Release Notes
======================================

Navio Core version 0.3.0 is now available from:

  <https://github.com/nav-io/navio-core/releases/tag/v0.3.0>

This release includes new features, various bug fixes and performance
improvements.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/nav-io/navio-core/issues>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes in some cases), then replace the
binaries (`naviod`, `navio-cli`, `navio-wallet`, `navio-staker`, ...) with the
new ones and start the node again. If you run `navio-staker`, upgrade and
restart it together with the node.

Before upgrading, read the [breaking changes](#breaking-changes) below. In
particular:

- A wallet that uses an external signer can no longer be loaded, and `naviod`
  refuses to start if such a wallet is listed with `-wallet` or in the
  load-on-startup list. Unload it first (see [Wallet](#wallet)).
- An existing `-coinstatsindex` is wiped and rebuilt from genesis on the first
  start (see [Indexes](#indexes)). A pruned node running with
  `-coinstatsindex` has to disable the index or `-reindex`.
- A node that crashed while writing the chainstate in a stretch of blocks with
  token, NFT or staking activity may hold a wrong token or staked-commitment set
  from before this release; restart it once with `-reindex-chainstate` (see
  [Chainstate](#block-and-transaction-handling-and-chainstate)).
- A BLSCT wallet that ran with `-blockfilterindex=1` may have missed
  transactions during rescans; run `rescanblockchain` after upgrading (see
  [BLSCT wallet](#blsct-wallet)).

Downgrading
-----------

This release does not change the wallet database format, but some data it
writes is not understood by older releases:

- Wallets record the wallet's own fee of merged block transactions and swaps as
  an `ownfee` metadata entry. An older release shows it as an extra `ownfee`
  field in `gettransaction` and `listtransactions` and reports the old fee
  figures.
- An older release does not detect the coin statistics index written by this
  release and silently extends it with the old coin hash. After downgrading,
  rebuild it by deleting `indexes/coinstats` in the network's data directory,
  or with `-reindex`. Upgrading again does not repair it; rebuild it the same
  way.

Compatibility
=============

Navio Core is supported and tested on operating systems using the Linux Kernel
3.17+, macOS 11.0+, and Windows 7 and newer. Other Unix-like systems may work
but are not regularly tested. UTF-8 path and argument handling on Windows
needs Windows 10 version 1903 or newer (see [Build](#build)).

Notable changes
===============

Breaking changes
----------------

These changes can break existing scripts, integrations and configurations.
Details are in the sections below.

- **Removed RPCs:**
  - all PSBT RPCs: `analyzepsbt`, `combinepsbt`, `converttopsbt`, `createpsbt`,
    `decodepsbt`, `descriptorprocesspsbt`, `finalizepsbt`, `joinpsbts`,
    `utxoupdatepsbt`, `walletcreatefundedpsbt`, `walletprocesspsbt` and
    `psbtbumpfee`;
  - `migratewallet`;
  - external signer RPCs: `enumeratesigners` and `walletdisplayaddress`.
- **Removed RPC options and fields:** the `psbt` option of `send` and `sendall`
  and the `psbt` key of `fundrawtransaction`'s options (passing them is now an
  error); the `psbt` field of the `send` and `sendall` results; the
  `external_signer` field of `getwalletinfo`. `createwallet` with
  `external_signer=true` is now an error.
- **Transparent RPCs refused on BLSCT networks** (mainnet and testnet):
  `generatetoaddress`, `generatetodescriptor`, `generateblock`,
  `createrawtransaction`, `signrawtransactionwithkey`, `addmultisigaddress`,
  `newkeypool`, `settxfee`, `sendmany`, `send`, `sendall`,
  `fundrawtransaction`, `signrawtransactionwithwallet`, `bumpfee`, and
  `keypoolrefill` on non-BLSCT wallets.
- **Changed RPC results:**
  - `gettransaction` reports a new top-level `amount` and `fee` for BLSCT sends;
    swaps taken with `acceptquotewallet` and block transactions that replaced
    the wallet's sends report the wallet's own fee instead of the whole fee.
  - `listtransactions`, `listsinceblock` and `listpendingtransactions` omit
    `txid` for output-storage entries held as bare outputs (it used to be a
    copy of `outid`).
  - `gettxoutsetinfo`'s `hash_serialized_3` and `muhash` change on chains with
    BLSCT outputs.
  - `getblsctauditkey` on a keyless wallet fails with `RPC_WALLET_BLANK` (-37)
    instead of -1.
  - `createwallet` refuses `blank=true` together with `seed`, `mnemonic` or
    `seedphrase_extension`, and `disable_private_keys=true` together with a
    master `seed`, `mnemonic` or `seedphrase_extension`;
    `disable_private_keys=true` with `blsct=true` no longer generates a seed.
  - `createwallet`'s `mnemonic_passphrase` is renamed to `seedphrase_extension`
    (the old name is a deprecated alias).
  - `gettxoutproof` without `-txindex` has a new error text; `scanblocks` and
    `scantxoutset` refuse BLSCT addresses.
- **Removed and changed startup options:** `-signer` is removed (an invalid
  parameter on the command line); `-checkpoints` has no effect; `-signet` now
  requires `-signetchallenge`; `-p2pmsgstoresize` is split into per-scope
  budgets; `navio-wallet -mnemonicpassphrase` is renamed to
  `-seedphraseextension` and the negated forms are refused.
- **Wallets with an external signer** can no longer be loaded.
- **libblsct C API:** `build_range_proof`, `sign_message` and `verify_msg_sig`
  take an explicit `msg_len` argument. Every libblsct consumer and binding must
  be updated and rebuilt.
- **Transaction shape:** ordinary BLSCT sends now always carry a change output
  (`-blsctpadoutputs`, default on), so exact-amount sends, sweeps and
  subtract-fee sends pay one extra output's fee and can leave zero-value coins
  in the wallet.
- **P2P:** the `getoutputdata` message is removed.
- **Testnet** no longer has fixed seeds; connect with `-addnode`, `-seednode`
  or `-connect`.
- `navio-wallet create` now exits non-zero on failure.

P2P and network changes
-----------------------

- **Compact blocks for aggregated BLSCT blocks.** A BLSCT block with more than
  one user transaction carries one aggregate that is never in any mempool, so
  BIP152 compact blocks always had to download it. Peers that both run this
  release now relay such blocks as `cmpctaggblk`, a list of short ids of the
  aggregate's component transactions, and rebuild the aggregate from their
  mempool, fetching missing components with `getaggblktxn`/`aggblocktxn`. The
  block is accepted only if its merkle root matches; otherwise the full block is
  requested. Support is announced with `sendcmpct` version 3 as a capability
  flag only; older peers keep using version 2 compact blocks. `-blocksonly`
  nodes don't announce it. A node only relays component lists recovered from
  its own mempool, and remembered lists are bounded in number and size (#486,
  #540).
- **Proof-of-stake header sync.** Header presync now applies the
  proof-of-stake retarget rule past the last proof-of-work height. It used to
  check only the proof-of-work rule, so on mainnet presync aborted at the first
  PoS retarget. Because PoS headers carry no proof of work, a header chain may
  now claim work at most 4x the node's own recent rate (measured from the fork
  point and within any one retarget timespan, with future timestamps clamped to
  the allowed maximum); this check is off during initial block download. On
  BLSCT chains, headers from inbound peers that fork more than 144 blocks below
  the tip are ignored; outbound and manual peers can still lead the node onto a
  heavier deep fork (#713, #759).
- **Orphan parents** are fetched by output id through the transaction request
  tracker, with the usual per-peer limits, timeouts and fallback to other
  peers. They are requested with a `MSG_WITNESS_TX` getdata carrying the output
  id, a form every released version answers. `MSG_OUTPUT_HASH` (8) getdata
  requests are also served. Requests that name a transaction by an output hash
  now go through the same relay rules as requests by txid, including the
  Dandelion++ stem embargo (#482, #489, #502).

  No version released so far (v0.2.2 and older) applies the Dandelion++ stem
  embargo to such a request: it checks the embargo by txid, while the request
  names an output id, so the check never matches. A peer running one of these
  versions can therefore reply with a parent that is still in its stem phase as
  a plain `tx`, ending its stem phase early. This is not new (any peer could
  already send such a request), and it goes away as peers upgrade.
- The `getoutputdata` P2P message has been removed. The node never sent it, and
  its 13-character name does not fit the v1 command field. BIP324 short id 29
  is left unassigned (#489).
- **Light-wallet output keys.** A new optional `-peeroutkeys` setting (default
  off) makes the node serve per-block BLSCT output keys to peers so light
  wallets can scan the chain without downloading range proofs. It is
  advertised with the new service bit `NODE_OUTKEYS` (bit 28, one of the bits
  reserved for experiments) and is incompatible with `-prune`, since replies
  are read from the block files.

  - `getoutkeys` (`uint32 start_height`, `uint256 stop_hash`) requests the range
    of active-chain blocks from `start_height` up to and including `stop_hash`,
    at most 1000 blocks. A request for an unknown or not yet servable stop
    block, a start above the stop block, or a larger range disconnects the
    peer, as does a request to a node that does not advertise `NODE_OUTKEYS`.
  - `outkeys` is sent once per block, in height order, and carries
    `uint256 block_hash`, then a vector with one entry per output carrying
    BLSCT keys, in block order (`uint256 output_hash`, 48-byte
    `blinding_key`, 48-byte `spending_key`, `uint16 view_tag`, and a
    `scriptPubKey` that is empty unless `spending_key` is the identity point),
    then a vector of the `uint256` output hashes spent by the block's inputs,
    in block order.

  A reply stops early, before the first block whose `outkeys` would take the
  reply's total payload over 4,000,000 bytes. The first block is always sent,
  even if it alone is larger, so every request makes progress. A client that
  receives fewer blocks than it asked for continues with a new `getoutkeys`
  starting at the height after the last block it received.

  A wallet derives the nonce from `blinding_key` and its view key, discards
  outputs whose `view_tag` does not match, and resolves the subaddress from
  `spending_key` (or the keys in `scriptPubKey`). It then fetches the
  transactions of its own outputs, which carry the range proofs needed to
  recover amounts, for example with a getdata naming the output hash. The
  `spent` list tells it which of its outputs a block consumed.
- **WebSocket listener.** A node whose WebSocket listener is publicly usable
  now advertises the new `NODE_P2P_WS` service bit (`1 << 30`, `P2P_WS`) and,
  right after the version handshake, sends peers a `wsendpoint` message with
  the listener's port and, when it sits behind a reverse proxy, its public URL.
  The bit is set when a `-p2pwsbind` address is not loopback-only, or when the
  new `-p2pwsexternal=<ws(s)://host[:port][/path]>` option names the public URL
  (its port, or 80/443 by scheme, is the one announced). A loopback-only
  listener without `-p2pwsexternal` is not advertised. `wsendpoint` is not sent
  over Tor, I2P or CJDNS connections, nor over outbound connections made
  through a proxy. The `NODE_P2P_WS` bit is likewise left out of the `version`
  message (and of the node's own address advertised) on those connections.
  Setting `-p2pwsexternal` together with `-proxy` logs a startup warning.
- `-whitelist` no longer applies to peers that connect through a `-p2pwsbind`
  WebSocket listener. Those connections usually reach the node through a
  reverse proxy, so every client appears to come from the proxy's (often
  loopback) address and an address-based permission cannot single any of them
  out. WebSocket peers now get no permissions, the same as inbound Tor peers. A
  `-whitelist` entry covering the proxy's address still applies to ordinary P2P
  connections from it.
- The WebSocket listener's handshake now requires `Sec-WebSocket-Key` to be a
  base64-encoded 16-byte nonce, as RFC 6455 requires, and answers anything else
  with HTTP 400. `-p2pwsbind` gets the same bad-port warning as `-bind`, and the
  `-listen=0` error names `-p2pwsbind` when it is set (#539).
- Testnet no longer has any fixed seeds. The built-in testnet list was
  Bitcoin's testnet3 node list, so a testnet node with no known peers dialed
  Bitcoin testnet3 nodes on port 18333, none of which can serve Navio blocks.
  Navio testnet has no known seed nodes yet: connect a testnet node with
  `-addnode`, `-seednode` or `-connect`.

### p2pmsg

- Each `p2pmsg` kind is now accepted only when it decrypts under the recipient
  key class listed below. A message that decrypts under any other class is
  dropped before its handler runs and logged under the `net` debug category.
  Relay is unchanged: every kind is still relayed whether or not the node can
  decrypt it. SDKs and light makers must encrypt each kind to the key class
  shown here, or the receiving node discards it.

  | Kind           | Value | Accepted under                                                            |
  | -------------- | ----- | ------------------------------------------------------------------------- |
  | `PING`         | 0     | inbox key                                                                 |
  | `PONG`         | 1     | none: no local handler, relayed only                                      |
  | `AGG_ANN`      | 2     | broadcast key                                                             |
  | `CANDIDATE_TX` | 3     | internal session key carried by the pull request                          |
  | `RFQ_REQ`      | 4     | broadcast key                                                             |
  | `RFQ_QUOTE`    | 5     | internal session key carried by the RFQ request                           |
  | `ORDER_ANN`    | 6     | broadcast key                                                             |
  | `USER_DATA`    | 7     | inbox key, broadcast key, or a reply key minted with `mintp2pmsgreplykey` |

  "Inbox key" includes the previous inbox keys a node still holds for a grace
  period after rotating its prekey. `USER_DATA` is only handled while the
  message store is enabled (`-p2pmsgstoresize` above 0); otherwise it is dropped
  like any kind without a handler. A reply key minted with
  `mintp2pmsgreplykey` is accepted for `USER_DATA` only, and an internal
  session key is never accepted for `USER_DATA`.
- A cover candidate received over p2pmsg is now checked before it enters the
  candidate pool, the way mempool acceptance would check it except for the
  minimum fee (a candidate is fee-0): its signature, balance and range proof,
  that its input is a confirmed unspent coin and, if a coinbase output, a
  mature one, and that no mempool transaction already spends that input. Its
  scriptSig must also pass the standardness rules for inputs (push-only, at
  most 1650 bytes). Its output and the coin it spends must be confidential
  (carry a range proof), and it must carry no signature operations
  (`candidate-sigops`). When the node requires standard transactions (no
  `-acceptnonstdtxn`), the candidate must also pass the same transaction and
  input standardness checks mempool acceptance applies. Its output must not
  already exist as an unspent coin, in a mempool transaction or in another
  pooled candidate; a pooled candidate is evicted when a mempool or block
  transaction later creates its output. Candidates the pool would refuse anyway
  (wrong shape, input already pooled, pool full) are dropped before any of this
  work. Previously a forged candidate was pooled and only failed when an
  aggregate that picked it was broadcast.
- A wallet now serves cover candidates (through `replycandidate` and automatic
  serving) only from NAV coins with at least 2 confirmations. Its own
  unconfirmed change used to qualify, and the requester dropped such a
  candidate. When no such coin is free, `replycandidate` fails with "No NAV coin
  with 2 confirmations free to build a candidate from" (#755).
- p2pmsg envelopes are now rejected at their length prefix when a field claims
  more bytes than the protocol allows, before any memory is allocated for it
  (#613).

Mempool policy
--------------

These are policy changes only: block validation is unchanged, and none of them
is a consensus change.

- The mempool now rejects two BLSCT transaction shapes as non-standard
  (`TX_NOT_STANDARD`, so the sending peer is not penalised):
  - `non-native-fee-output`: a fee output that pays a non-zero value in a
    token other than the native one. The consensus minimum fee is a native
    per-weight rate, so a token issuer could otherwise pay it in a token they
    mint for free.
  - `blsct-vin-empty`: a transaction with no inputs. Only a mint can balance
    one, so it is the zero-input form of the same transaction.

  Blocks carrying either shape stay valid. The checks are not affected by
  `-acceptnonstdtxn` (#611).
- Mempool acceptance now bounds the `OP_BLSCHECKSIG` calls the input scripts
  of a BLSCT transaction may make, at 16 + 2 per input. Each call adds a pair
  to the aggregate signature check. A transaction over the bound is rejected
  with the new reason `too-many-bls-signature-pairs`. A coin locked to a script
  with more `OP_BLSCHECKSIG` calls than the bound is still valid in a block,
  but a spend of it is no longer accepted into the mempool or relayed (#610).
- The mempool now rejects with `txn-duplicate-output` a transaction that
  repeats one of its own spendable outputs, creates a spendable output another
  mempool transaction already creates (unless that transaction is a direct
  conflict being replaced), or recreates a coin that is still unspent in the
  chain. A package that creates the same spendable output twice is rejected
  with `package-duplicate-output`. This matches what block validation already
  requires, so the mempool no longer holds transactions that cannot be mined
  together (#492).
- When a block confirms mempool transactions through its aggregate, without
  listing their txids, those transactions now leave the mempool as confirmed
  rather than conflicted. Their in-mempool descendants are kept, the fee
  estimator learns from them, and wallets are no longer told they conflicted
  (#490).
- After a block connects, mempool transactions whose token predicates no
  longer hold at the new tip (for example a mint of a token whose supply cap
  that block reached) are evicted, like transactions whose inputs the block
  spent. Only transactions touching a token the block changed are checked.
  After a reorg, mempool transactions whose token predicates no longer hold
  (for example a mint of a token whose creation the reorg undid) are evicted as
  well (#609).

Mining
------

- Block templates no longer fail when the mempool holds token transactions
  that conflict with each other, such as two mints that are each valid on their
  own but together exceed the token's supply cap. Mempool acceptance checks
  each transaction's token predicates against the chain only, so both were
  accepted, and every template that selected both failed `TestBlockValidity`
  with `failed-to-execute-predicate`, stopping block production. Package
  selection now applies token predicates on top of the packages already chosen
  and skips a package that conflicts (#609).
- A single transaction with a token-denominated fee used to be able to halt
  block production: the block assembler merges every selected transaction into
  one with a single native fee output, and a token fee left the merged
  transaction unbalanced. Besides the new mempool rule, the assembler now drops
  such a transaction (and any transaction spending its outputs) before merging,
  and the merge itself refuses a non-native fee (#611).

Block and transaction handling and chainstate
---------------------------------------------

- A BLSCT block whose coinbase carries a token or NFT predicate that depends on
  another transaction in the same block is now disconnected correctly. Such a
  block connected normally, but disconnecting it failed, so a reorganization
  past it, `invalidateblock` on it and `verifychain` at level 3 or higher all
  failed. The coinbase's predicates are applied after the block's other
  transactions on connect, and are now reverted before them on disconnect.
  Block validity is unchanged. A node that is already unable to reorganize past
  such a block needs this release to do so.
- After a crash or power loss in the middle of writing the chainstate to disk,
  the node replays the blocks between the last completed write and the tip on
  the next start. That replay now applies the token and NFT predicates (create,
  mint, NFT mint) of the replayed blocks, including those carried by a block's
  coinbase, and removes every staked commitment those blocks spent, even one
  whose coin the interrupted write had already erased. Previously tokens
  created or minted in the replayed blocks went missing, and such a spent
  staked commitment could stay in the staked-commitment set that PoS proofs are
  checked against, so the node could reject valid PoS blocks. A node in that
  state could also fail its startup block verification with "Corrupted block
  database detected". Replay now reads the undo data of the blocks it rolls
  forward as well as the blocks themselves.
- A node that crashed or was killed while writing the chainstate, in a stretch
  of blocks with token or NFT activity or with staking transactions, may still
  hold a wrong token set or staked-commitment set from before this release.
  Restart it once with `-reindex-chainstate` to rebuild both from the blocks; a
  pruned node can't use that and needs `-reindex`, which downloads the blocks
  again.
- Token entries are now written to the chainstate database only in the final
  batch of a write, together with the new best block, so they are never left
  half-written by an interrupted write. The debug options `-dbbatchsize` and
  `-dbcrashratio` no longer split or interrupt token writes; they still apply
  to coins.
- `verifychain` at level 4 (and `-checklevel=4` at startup) no longer fails
  with "Corrupted block database detected" when a token created in the checked
  range is minted later in it (#534).
- Undo data for BLSCT blocks no longer reserves space for the full range proofs
  it does not store, so rev files no longer have unused gaps and pruning no
  longer overcounts their size (#559).

Indexes
-------

- A new optional `-outindex` index (default off) maps each output hash (the
  outpoint that spends it) to the block, transaction and output position that
  created it and, once a block spends it, to the block, transaction and input
  position of the spend. It follows reorganisations and is incompatible with
  pruning. It is built in the background for an existing chain and its state
  is reported by `getindexinfo` as `outindex`. See the new `getoutputinfo` RPC.
- The coin statistics index (`-coinstatsindex`) now hashes every coin in one
  canonical form (see `gettxoutsetinfo` under [Updated RPCs](#updated-rpcs))
  and records the version of the coin hash it was built with. An existing index
  is wiped and rebuilt from the genesis block the first time the node starts
  after upgrading; this happens in the background, and until it catches up,
  index-backed `gettxoutsetinfo` calls report that the index is still syncing
  (pass `use_index=false` to compute the values from the UTXO set instead). The
  rebuild needs the full block history, so a pruned node running with
  `-coinstatsindex` has to disable the index or `-reindex` after upgrading.
- Downgrading is not detected: an older release ignores the version record and
  keeps extending the index with the old coin hash, so its values silently go
  wrong. After downgrading, rebuild the index by deleting `indexes/coinstats` in
  the network's data directory (or with `-reindex`). Upgrading again does not
  repair it: the version record written by this release is still present, so
  the mixed index is not rebuilt either. Rebuild it the same way.

Proof of stake and navio-staker
-------------------------------

- `navio-staker` now takes turns between the commitments it stakes, in wallet
  mode and in `-delegated` mode. Each cycle it starts with the commitment after
  the one that produced its last block, instead of always starting with the
  first, so every stake that can produce a block gets its turn. Before, the
  first commitment in the list that could stake produced every block; with
  several stakes, which one earned the rewards depended on the order the wallet
  happened to list them in. In `-delegated` mode the rewards (and the
  per-delegation counts in `-statsfile`) are now spread across the delegations
  instead of going to the most confirmed one.
- `navio-staker` in wallet mode (without `-delegated`) also stakes the wallet's
  own delegated stakes. A block it produces with one of them now pays the
  reward to that delegation's reward address instead of `-coinbasedest`.
  Before, the reward reached the wallet but not the reward address, so
  `listdelegations` kept reporting `rewards_received` as 0. The staker falls
  back to `-coinbasedest` when connected to a node whose `listdelegations`
  lacks the new `commitment` field. It calls `listdelegations` only when the
  wallet's set of staked commitments changes, not on every staking cycle.
- A wallet-mode staker whose `listdelegations` call keeps failing no longer
  retries it and logs the error on every staking cycle. It logs the first
  failure, retries after about 2 seconds, doubles the wait after each further
  failure up to `-delegationrefresh` (default: 300 seconds, now capped at one
  day), and logs `Listed delegations again after N failed attempt(s)` once the
  call succeeds. A change in the wallet's staked commitments (a stake added,
  delegated or unlocked) is retried on the cycle that sees it, without waiting.
  While the call fails, delegated stakes the staker has not yet looked up pay
  `-coinbasedest`; once the node answers again, that lasts until the next
  scheduled retry (at most `-delegationrefresh`) or the next staked-commitment
  change, whichever comes first. `-delegationrefresh` therefore now also
  applies outside `-delegated` mode.
- A staker that cannot reach its node (with `-rpcwait=0`, or once
  `-rpcwaittimeout` expires) no longer retries and logs the connection error on
  every staking cycle. It logs `Lost connection to the node` once, retries
  after about 2 seconds, doubles the wait after each further failure up to 60
  seconds, and logs `Reconnected to the node after N failed attempt(s)` once a
  cycle reaches the node again. The dashboard keeps running meanwhile, shows
  the state as `waiting for node`, and still counts every failed attempt under
  `RPC errors`. A connection failure while building a block proposal is now
  handled the same way, instead of being logged as a skipped slot every cycle.
  A `-delegated` staker rescans its delegations on the first cycle after a
  connection failure.
- A `-delegated` staker whose delegation rescan (`liststakedcommitmentsdata`)
  gets an RPC error, for example from a node still warming up after a restart,
  no longer drops the delegations it tracks and their statistics. It keeps
  staking the previous set, logs `Could not load staked commitments data`, and
  retries on the next `-delegationrefresh`.
- Writing the staker's `-statsfile` now checks the write before replacing the
  old file, retries the rename on Windows when it is refused, and removes the
  temporary file when the rename fails (#604, #617, #625, #635).

Signet
------

- Signet is now a BLSCT network. It used Bitcoin's signet challenge, genesis
  block and assumevalid with BLSCT disabled, so it could only follow Bitcoin's
  signet. It now has its own genesis block, BLSCT addresses with the `snv`
  prefix (matching libblsct's `Signet` chain), proof-of-work blocks up to height
  1000 and proof-of-stake blocks after, and P2P port 48488.
- There is no default signet network: `-signet` now requires
  `-signetchallenge`, and naviod refuses to start without it. The default
  signet no longer lists Bitcoin Core's signet seeds.
- Every block must be signed for the challenge, proof-of-stake blocks included.
  `generatetoblsctaddress` takes the signing key as a new `signetkey` argument
  on signet, and `navio-staker` takes it as `-signetblockkey`. Both take the key
  as 32 bytes of hex.
- A signet block's signature now commits to the block's version, previous hash,
  transactions and time. It used to spend an output identified only by its own
  hash, so one valid signature validated any block.
- `contrib/signet/getcoins.py`, a client for Bitcoin's signet faucet, and the
  signet miner (`contrib/signet/miner`) have been removed;
  `contrib/signet/README.md` now describes running a navio signet.

BLSCT wallet
------------

### Transaction shape

- Ordinary BLSCT sends now always carry a change output. The wallet used to
  drop a change output whose value came to zero, so exact-amount sends, sweeps
  and subtract-fee sends had one non-fee output while every other send had two,
  which set them apart in the mempool. With the new `-blsctpadoutputs` option
  (default `1`) such a send gets a zero-value, range-proofed change output for
  each fungible token it spends. This costs one extra output's fee on those
  sends only (about 0.00137 NAV at the default rate), and each zero-value
  output stays in the wallet as a 0-amount coin, listed by `listblsctunspent`,
  that ordinary sends do not spend; a sweep or subtract-fee send collects them.
  Stake, unstake, token create and mint, aggregation cover candidates and NFT
  change keep their shape. `-blsctpadoutputs=0` restores the old behaviour
  (#494).

### Aggregated sends and merged block transactions

- Chained unconfirmed sends now work after an aggregated `sendtoblsctaddress`
  or `consolidate` (the default, `-aggregatesends`), `aggregatesend` or
  `acceptquotewallet`. Previously the wallet did not record its aggregated send
  until it found it in the mempool, and then treated the change as untrusted
  because the cover inputs belong to other wallets, so the next send failed
  with "Not enough funds available". The wallet now records the aggregate as
  its own send when it broadcasts it, together with the outputs of its own
  half, and those outputs (the change, or a payment to itself) count as trusted
  at 0 confirmations, like the change of a plain send. The wallet's own inputs
  are still checked.

  Only the own half's outputs are trusted. Any other output of the aggregate
  that pays this wallet, such as a cover candidate addressed to it, is funded
  only by another wallet's input and stays untrusted pending, and out of the
  spendable coins, until the aggregate confirms.

  This accepts a risk: a cover provider can double-spend its coin, at the cost
  of one fee-0 candidate, and evict the aggregate from the mempool together
  with every unconfirmed send chained on its change, so those sends never
  confirm. For `acceptquotewallet` the swap maker can do the same by
  double-spending one of its quote inputs, and unlike a cover provider it is a
  counterparty to the trade that may have a motive to back out of it. The
  wallet handles the evicted aggregate like any other of its unconfirmed sends
  that leaves the mempool. A wallet that only received an aggregate, such as a
  cover provider's, still treats its outputs as untrusted until they confirm.

  Chains of aggregated sends make it more likely that a send leaves the mempool
  without confirming. Wallets with output storage now handle this as follows:
  - After a block conflict, for example when a cover provider's double-spend of
    its candidate input, or a swap maker's double-spend of a quote input, is
    mined, the wallet marks the aggregate and every send chained on it as
    conflicted, as Bitcoin Core does for non-BLSCT transactions:
    `confirmations` in `gettransaction` goes negative. When the double-spend is
    not a wallet transaction, such as a cover provider's, `walletconflicts`
    stays empty. Their inputs no longer count as spent, so the original coins
    are back in the balance and in `listblsctunspent` without
    `abandontransaction`. If the conflicting block is disconnected, they become
    unconfirmed transactions again that keep their inputs spent until they are
    abandoned. Previously the wallet kept them as unconfirmed and not
    abandoned, so the trusted balance and the coin set dropped, and sends
    failed with "Not enough funds available" until
    `abandontransaction <aggregate txid>` restored the original coins. The same
    now applies when another sender's aggregate using the same cover candidate
    is mined; the wallet used to count its own aggregate as confirmed then,
    although its own outputs never reached the chain.
  - After expiry, eviction or another removal that is not a block conflict, the
    transaction keeps its inputs spent until it is abandoned, but the wallet no
    longer treats it as in the mempool: it stops being trusted, and its change
    leaves `getbalances` and `listblsctunspent`. `abandontransaction <txid>`
    now accepts it and restores the coins it spent. Until then the wallet may
    rebroadcast it, at startup or periodically, and if the mempool accepts it
    again it counts as before. Previously the transaction stayed marked as in
    the mempool, `getbalances` kept counting it, and `abandontransaction` was
    refused until a restart resubmitted it.

  Only the wallet that broadcast the aggregate marks it as its own send. A
  wallet restored or reimported from the same seed (or any wallet that did not
  run the send) that learns of a still-unconfirmed aggregate from the mempool
  treats its change as untrusted pending, so a chained send from that wallet
  fails with "Not enough funds available" until the aggregate confirms. The
  wallet-local comment of the send is not recovered.

  For `consolidate` the trusted output is the merged coin, usually most of the
  wallet's small-coin balance, so an aggregate that is conflicted or leaves the
  mempool affects more of the balance at once; a later consolidation may also
  chain on that coin before the aggregate confirms.

  For `acceptquotewallet` the taker's own half pays the sell token and receives
  the bought token. Its change is trusted at once, but the received output is
  funded only by the maker's inputs, so it stays untrusted pending, and out of
  the spendable coins, until the swap confirms.
- `getbalances` no longer briefly counts a parent's spent change next to the
  new change right after a chained send is recorded (#555).
- An output-storage wallet (`storage_output=true`) now treats its own send as
  in the mempool while a transaction that merges it (spends all of its inputs
  and creates all of its non-fee outputs) is in the mempool under its own hash.
  That is typically the block transaction a staker merged the send into, which
  the node puts back into its mempool when the block holding it is
  disconnected. Previously the send stayed unconfirmed outside the mempool: its
  change was untrusted in `getbalances` and missing from `listblsctunspent`
  while its inputs stayed spent, `abandontransaction` accepted it although the
  network could still mine it, and the wallet periodically rebroadcast it on
  its own, which the mempool rejects as a conflict with the merging
  transaction. When the merging transaction leaves the mempool without being
  mined (expiry, eviction, replacement or a conflict), the send leaves it too
  and can be abandoned. A send that was abandoned is no longer abandoned once a
  transaction merging it enters the mempool, as for any transaction that
  re-enters the mempool, and has to be abandoned again if that transaction
  leaves it unmined.
- An output-storage wallet now returns its own send to unconfirmed when the
  block that confirmed it is disconnected after a staker merged the send into
  one block transaction under another txid. Previously the send stayed
  confirmed in the disconnected block: its `confirmations` in `gettransaction`
  kept growing with each new block, its change counted as trusted in
  `getbalances` and `listblsctunspent` although it was no longer on the chain,
  `abandontransaction` refused it, and a later block that merged it again under
  yet another txid did not confirm it there. The send now behaves like any
  other wallet transaction of a disconnected block: it keeps its inputs spent
  until it confirms again, is conflicted, or is abandoned.
- A BLSCT wallet that keeps full transactions (`storage_output=false`) now
  reports its own fee for a block transaction that replaced its sends. A staker
  merges every transaction of a block into one block transaction with a single
  fee output for all of them, and such a wallet replaces its merged sends with
  that transaction once it confirms. `gettransaction` and `listtransactions`
  used to report the whole block fee as the wallet's `fee`, and the amount sent
  to others less the other senders' fees. They now report the fees of the
  replaced sends and the amount those sends paid to others. The sum of `amount`
  and `fee`, and the balances, are unchanged. The block transaction's fee is
  still reported whole when the replaced sends do not account for everything
  the block transaction spends from the wallet (a coin of the wallet spent by a
  send it holds no record of), and for a wallet that only learned of the block
  transaction by rescanning. The wallet's own fee is stored with the
  transaction as an `ownfee` entry of its metadata, like the `ownhalf` entry of
  an aggregated send; an older version that loads the wallet shows it as an
  extra `ownfee` field in `gettransaction` and `listtransactions` and reports
  the whole block fee.
- A wallet restored or reimported from a seed after a staker merged a chain of
  its sends into one block transaction now reports the correct amount for that
  transaction. Each send in the chain spends the change of the one before, and
  the block transaction keeps those intermediate change outputs together with
  the inputs that spend them. The wallet already left those inputs out of the
  amount it spent, but it still subtracted the intermediate change as returned
  to itself, so `listtransactions` and the `details` of `gettransaction` showed
  one `send` with a large positive amount. The intermediate change is now left
  out on both sides, and the row shows the amount paid to others with the
  merged transaction's fee. Balances and `listblsctunspent` were already
  correct and are unchanged (#512).

  The restored wallet still shows the whole chain as one `send` row under the
  block transaction's txid, not one row per original send: the block
  transaction does not record where one send ends and the next begins. An
  output-storage wallet that made the sends, or saw them in the mempool before
  they were mined, keeps one row per send. Other BLSCT wallets replace the
  merged sends with the block transaction when it confirms, so they also show
  the single row, now with the correct amount. A wallet whose only involvement
  in the block transaction is an output it also spent there now lists no
  `listtransactions` row for it (`gettransaction` still returns it, with amount
  0 and no details), since that output and the input spending it are both left
  out.
- A merged send is now found by the inputs the block transaction spends, so it
  confirms even when another wallet transaction carries the same output (#638).

### Conflicts and output storage

- A wallet with output storage now marks a received payment conflicted when the
  payment is evicted from the mempool because a block spends one of its inputs,
  or the input of a payment it descends from. Previously the payment stayed in
  `listtransactions` as an unconfirmed receive with 0 confirmations for good,
  also after a restart, although it can never confirm.

  Bitcoin Core drops a conflicted receive from `listtransactions` and reports
  negative `confirmations` for it in `gettransaction`. In a wallet with output
  storage the payment has no wallet transaction, so `gettransaction` does not
  know its txid, as before. The payment now leaves `listtransactions` and is
  listed by `listpendingtransactions` as a `receive` with negative
  `confirmations` (counted from the block that conflicts it), `trusted` false
  and its `outid` as `txid`. Balances and `listblsctunspent` already left such
  a payment out and still do. A send of this wallet that spends the payment's
  output is marked conflicted with the same block, so `gettransaction` reports
  negative `confirmations` for it instead of leaving it unconfirmed. If the
  conflicting block is disconnected, the payment and such sends become
  unconfirmed again.

  The payment stays unconfirmed, as before, when:
  - the block does not conflict it through inputs, for example when the mempool
    evicts it because the block adds the same staked commitment, or because it
    descends from a transaction of another wallet that the block conflicts;
  - it was not in this node's mempool when the conflicting block arrived;
  - the wallet loses the eviction before the block is reported to it: the
    wallet keeps evictions in memory until then, so a crash or `unloadwallet`
    in between drops them, and so does a block disconnected in between;
  - the conflicting block is disconnected and later connected again.

  `abandontransaction` still does not accept a received payment in a wallet
  with output storage.
- A wallet transaction evicted from the mempool because its token predicates
  no longer hold (see [Mempool policy](#mempool-policy)) is now marked
  conflicted with the block that caused the eviction (`confirmations` -1), so
  the coins it spent are available again without `abandontransaction`. If that
  block is disconnected, the transaction returns to unconfirmed. When several
  blocks connect at once, the conflict is recorded against the latest of them
  that touched the transaction's token (or its parent's, for a wallet
  transaction spending the evicted one). That block is never earlier than the
  one that caused the eviction, so disconnecting the latter always returns the
  transaction to unconfirmed.

  The wallet learns about such a conflict only from the mempool eviction and
  cannot rebuild it from chain state. A wallet that misses the eviction (it was
  not loaded at the time, the node stopped before the block was reported to
  it, or the transaction is found by a rescan), or a mint that confirmed on a
  chain later reorganized away and is rejected when resubmitted, leaves the
  transaction unconfirmed with its inputs spent, as before. Use
  `abandontransaction` to free them.
- A rescan of an output-storage wallet now repairs spends and confirms held
  outputs that a block disconnect had left inactive, instead of skipping
  transactions it already holds (#535).
- After a broadcast, a failure to write the wallet's output-storage records is
  now logged with the txid instead of reporting the already broadcast
  transaction as failed, and every output is still mirrored (#634, #675, #750,
  #760).

### Tokens, NFTs and swaps

- `minttoken` and `mintnft` no longer spend the issuer's existing coins of the
  token being minted. The minted amount comes from the mint predicate, so a
  mint only needs native coins for its fee, but the wallet used to add every
  coin of the minted token (or, for an NFT mint, of the exact NFT id) as an
  input and return it as change. While such a mint was unconfirmed the held
  tokens moved with it, and if it was never mined `gettokenbalance` reported 0
  although the earlier mint was confirmed. Mints now spend native coins only.
- `gettransaction` and `listtransactions` now report a swap taken with
  `acceptquotewallet` with a `fee` of 0 and an `amount` of the full sell cost,
  on the transaction and on its `send` entry. The maker's half funds the whole
  fee of the swap, but the taker's wallet used to report that fee as its own,
  and an `amount` short of the sell cost by the same figure. The sum of
  `amount` and `fee`, and the balances, are unchanged. The taker's fee is
  stored with the swap as an `ownfee` entry of its metadata, so it survives a
  reload, and a block transaction a staker merges the swap into adds none of
  the swap's fee to the wallet's own. Swaps recorded before the upgrade keep
  the old figures.
- `acceptquotewallet`, `broadcastorder` and `replyquote` no longer hang when
  the NAV inputs of the wallet's swap half exactly cover what it pays in NAV,
  fee included, leaving zero NAV change. Such a half now pays the with-change
  fee, overpaying by one change output's weight.

### Keys, seeds and wallet creation

- A BLSCT wallet created with the `createwallet` RPC no longer gets a legacy key
  manager with a transparent HD seed beside its BLSCT keys, matching wallets
  made by `navio-wallet create`. Nothing on a BLSCT chain could use those
  transparent keys. Existing wallet files that have a legacy key manager still
  load and keep it. For a new BLSCT wallet:
  - `getwalletinfo` reports `keypoolsize` and `keypoolsize_hd_internal` as 0,
    since they count transparent keys only. `hdseedid` and `keypoololdest`
    still come from the BLSCT key manager.
  - A wallet created with a passphrase is still reported as not `blank` by
    `getwalletinfo`; its BLSCT seed now clears that flag.
  - `navio-wallet info` shows "HD (hd seed available): no" and "Keypool Size:
    0", as it already did for wallets made by `navio-wallet create`.
- A BLSCT wallet now always rescans by inspecting every block, even when the
  node runs with `-blockfilterindex=1`. Before, a BLSCT wallet without a legacy
  key manager, such as one created with `navio-wallet create`, took the fast
  rescan that uses block filters. BLSCT outputs are found by view key, not by a
  scriptPubKey a block filter can match, so that rescan skipped every block.
  Every rescan of such a wallet was affected: restoring it, loading it after
  blocks were mined while it was unloaded, and `rescanblockchain` all missed
  its transactions. If you ran such a wallet with `-blockfilterindex=1`, run
  `rescanblockchain` after upgrading to pick up anything that was missed. A
  BLSCT wallet created with the `createwallet` RPC before this release carries
  a legacy key manager and already used the slow rescan. Non-BLSCT descriptor
  wallets still use the fast rescan.
- Creating a BLSCT wallet from an audit key (`createwallet` with a
  160-character `seed`, or `navio-wallet create -blsct -seed=<audit key>`) now
  fails with "Invalid audit key" (`RPC_INVALID_PARAMETER` from `createwallet`)
  when the view-key half is zero or not below the group order, or the
  spend-key half is not a valid G1 point or is the identity. The key is checked
  before the wallet is created, so no wallet is left behind. Such a key used to
  be accepted, and the wallet then watched sub-addresses that are not the
  audited wallet's.
- Loading a BLSCT wallet with private keys disabled that nevertheless holds a
  seed (such as one created with
  `createwallet blsct=true disable_private_keys=true` by an earlier release,
  which generated a random seed) now warns "Private keys detected in wallet ...
  with disabled private keys", as it already did for non-BLSCT wallets.
  Audit-key wallets hold no seed and load without the warning. To get a truly
  watch-only wallet, export the audit key of the affected wallet with
  `getblsctauditkey` and recreate the wallet from it with
  `createwallet blsct=true disable_private_keys=true seed=<audit key>`. The old
  wallet file still holds a seed that can spend its funds, so keep it as
  securely as any spending wallet.
- Loading a BLSCT wallet that has no seed, although it is neither blank nor
  watch-only, now fails with an error instead of aborting the node. Such a
  wallet is left behind when its creation does not complete; restore it from
  its mnemonic or seed, or from a backup.
- Outputs past the recovery search bound (the 17th output of a transaction
  onward, or after 32 builds on the same inputs) now get random blinding keys
  and the wallet logs it, instead of silently deriving keys nothing can
  re-derive. `signblsctoutput` cannot sign for such outputs, and its error now
  names these causes (#501, #515, #530).
- Secret material (scalars, keys, mnemonic and seed temporaries, hasher state)
  is now wiped from memory more thoroughly (#646, #656, #669, #670, #694,
  #701, #707, #715, #723, #732, #742, #764).

Wallet
------

- External signer (hardware wallet) support has been removed. It worked by
  passing PSBTs for transparent outputs to an HWI-compatible tool, which BLSCT
  transactions never use. This removes the `-signer` option, the
  `enumeratesigners` and `walletdisplayaddress` RPCs, and the
  `ENABLE_EXTERNAL_SIGNER` build option. Passing `-signer` on the command line
  is now an invalid parameter error; a `signer=` line in the configuration
  file is ignored with a log message.
- A wallet created with an external signer can no longer be loaded. `naviod`
  and `navio-wallet info` refuse it with the error "This wallet uses an
  external signer, which this build no longer supports". `navio-wallet dump`
  can still export its records, but `navio-wallet createfromdump` refuses such
  a dump with a similar error instead of creating a wallet that cannot be
  loaded.
- If such a wallet is listed with `-wallet` or in the load-on-startup list in
  `settings.json`, `naviod` now fails to start with that error. Before
  upgrading, unload it with `unloadwallet <name> false` (which removes it from
  the `settings.json` startup list) and drop any `-wallet` option naming it,
  whether on the command line or in `navio.conf`. If you have already
  upgraded, `unloadwallet` is not available for it, since the wallet cannot be
  loaded: stop `naviod`, remove the wallet from the `"wallet"` list in
  `settings.json` and from any `-wallet` option, then start again.
- When `createwallet` fails after it has created the wallet's database, for
  example because the BLSCT keys cannot be set up from the given seed, it now
  removes the wallet file and the wallet directory it created. Retrying with
  the same name used to fail with "Database already exists". A directory or
  wallet file that existed before the call, and any other file in the
  directory, is left in place. For a nested wallet name such as `a/b/c`, every
  directory level the call created is removed, deepest first, up to the first
  one that existed before. A failed `restorewallet` now does the same; it used
  to remove only the last level.
- While `createwallet` or `restorewallet` runs, including the removal of a
  failed attempt, `loadwallet`, `createwallet` and `restorewallet` of the same
  name are refused with "Wallet already loading.".
- Fee estimates for transparent wallet transactions no longer count a 4-byte
  output index per input, which navio outpoints do not carry. Each input was
  estimated 4 vbytes too large, so wallets overpaid by that much per input.
- `sendall` now pays enough fee when recipients are given without an amount. It
  used to estimate those outputs 8 vbytes too small each, so at the minimum
  relay feerate the transaction was rejected by the mempool while `sendall`
  still reported it complete.
- `sendall` with an explicit input the wallet does not hold now fails with
  "Input not found" instead of crashing the node (non-BLSCT chains only; on
  BLSCT networks `sendall` is refused) (#655).

Updated RPCs
------------

### Refused on BLSCT networks

On networks that only accept confidential (BLSCT) transactions, which includes
mainnet and testnet, these RPCs now fail with an error saying so instead of
doing work that can never confirm:

- `generatetoaddress`, `generatetodescriptor` and `generateblock` built blocks
  paying a transparent coinbase, which these networks always reject. Up to the
  network's last proof-of-work height, `generatetoblsctaddress` can mine
  instead; above it, blocks must be proof-of-stake. The error says so, and
  names `generatetoblsctaddress` only while the chain is below that height.
- `createrawtransaction` and `signrawtransactionwithkey` built and signed
  transparent transactions. Use `createblsctrawtransaction` and
  `signblsctrawtransaction`.
- `addmultisigaddress` and `newkeypool` only created transparent (ECDSA)
  multisig scripts and keys.
- `settxfee` set a rate only transparent transactions use; BLSCT fees follow
  the consensus fee rate, so it silently had no effect.
- `sendmany`, `send` and `sendall` built transparent transactions. Use
  `sendtoblsctaddress`. These spend RPCs refuse every wallet, not only BLSCT
  ones; the BLSCT alternatives they name need a BLSCT wallet.
- `fundrawtransaction` and `signrawtransactionwithwallet` funded and signed
  transparent transactions. Use `fundblsctrawtransaction` and
  `signblsctrawtransaction`.
- `bumpfee` replaced transparent transactions. There is no BLSCT fee bump;
  send a new confidential transaction with `sendtoblsctaddress` instead.
- `keypoolrefill` on a non-BLSCT wallet only refilled transparent (ECDSA) keys.
  It keeps working on BLSCT wallets, where it refills the BLSCT subaddress
  pool.

`sendtoaddress` is unchanged: on these networks it already sends a
confidential transaction through `sendtoblsctaddress`.

### PSBT removal

- `send` and `sendall` no longer return a `psbt` field, and their `psbt` option
  has been removed (passing it is now an invalid parameter error, so a call
  that still asks for a PSBT fails instead of broadcasting a transaction). A
  transaction the wallet cannot fully sign, for example one from a wallet with
  private keys disabled or a locked wallet, is now returned as a raw
  transaction in the `hex` field, signed as far as the wallet could, with
  `complete` set to `false`. As with `signrawtransactionwithwallet`, any inputs
  that failed signature verification are listed with the reason in an
  `errors` array, which is omitted when there are none. Nothing is broadcast
  or added to the wallet in that case. With `add_to_wallet=false`, `send` and
  `sendall` return only the signed transaction in `hex` and its `txid`.
- `fundrawtransaction` no longer accepts a `psbt` key in its options, which it
  had ignored; passing it is now an error.
- `bumpfee` on a wallet with private keys disabled still fails, and its error
  no longer suggests `psbtbumpfee`. A transaction with inputs from other
  wallets can no longer be fee-bumped: `bumpfee` refuses with "Transaction
  contains inputs that don't belong to this wallet".

### Wallet creation and keys

- `createwallet`:
  - The `mnemonic_passphrase` argument is renamed to `seedphrase_extension`. It
    is the optional BIP-39 passphrase combined with the mnemonic when deriving
    the keys of a BLSCT wallet, and is unrelated to the wallet encryption
    `passphrase`. `mnemonic_passphrase` is still accepted as a deprecated alias
    and will be removed in a future release. Passing both names is an error.
    The rename does not change key derivation.
  - `blank=true` together with `seed`, `mnemonic` or `seedphrase_extension` is
    now refused (`RPC_INVALID_PARAMETER`). These used to be dropped silently.
  - With `blsct=true` and `disable_private_keys=true` it no longer generates a
    random seed: without a `seed` the wallet holds no keys. Wallets created this
    way before this release hold a full private seed, which `getblsctseed` and
    `dumpmnemonic` return.
  - `disable_private_keys=true` together with a master `seed`, a `mnemonic` or
    a `seedphrase_extension` is now refused; it used to store the private keys
    in a wallet reporting `private_keys_enabled: false`. Pass an audit key (from
    `getblsctauditkey`) as `seed` to create a watch-only BLSCT wallet.
  - The `external_signer` parameter is kept so that the parameters after it
    keep their positions, but setting it to `true` is now an error.
- `getwalletinfo` no longer returns the `external_signer` field.
- `getblsctseed` and `dumpmnemonic` on a BLSCT wallet with private keys
  disabled now say so, instead of suggesting `setblsctseed`, which refuses such
  wallets.
- `getblsctauditkey` on a BLSCT wallet that holds no keys (a blank wallet, or
  one created with private keys disabled and no audit key) now fails with
  `RPC_WALLET_BLANK` (-37) and a message naming the cause, as `getblsctseed`
  does. It used to fail with a generic error (-1) carrying an internal message.
- `keypoolrefill` on a BLSCT wallet with `blsct=true` (the default) now checks
  the BLSCT subaddress pool it refilled rather than the transparent key pool,
  which a new BLSCT wallet does not have. A size above 0 no longer fails with
  "Error refreshing keypool." With `blsct=false` a new BLSCT wallet has no
  transparent pool to refill, so a size above 0 still fails with that error.
  On a view-only BLSCT wallet it fails with "Error: Private keys are disabled
  for this wallet".

### Transaction history and balances

- `gettransaction` now reports the correct top-level `amount` and `fee` for
  BLSCT transactions the wallet sent. It used to compute the fee as inputs
  minus visible outputs, but confidential outputs carry no visible value, so
  the payment and the change were counted as fee: a send showed a large
  negative `fee` and a positive `amount`. For a transaction this wallet built,
  a send of X now reports `amount` -X and `fee` equal to its BLSCT fee output,
  matching its `details` entries and `listtransactions`; a send to the wallet's
  own address reports `amount` 0. A transaction in which this wallet's coins
  only served as aggregation cover, and all came back as change, reports `fee`
  0. A merged block transaction that the wallet only learned of by rescanning
  reports the merged fee of every sender, as its `details` entries already did.
- `gettransaction`, `listtransactions`, `listsinceblock` and
  `listpendingtransactions` now mark a BLSCT send whose `fee` may include fees
  that other wallets paid with `"fee_may_include_other_senders": true`, on the
  transaction and on its `send` entries. A wallet that learned of a staker's
  merged block transaction only by rescanning, without its own original sends,
  cannot tell its share of that fee from the other senders'. Such a send
  reports the whole fee, and an `amount` that leaves the other senders' fees
  out; their sum is still what the wallet spent. The field is absent for every
  other transaction, including a block transaction whose inputs are all the
  wallet's own, which pays only its fees.
- `listtransactions`, `listsinceblock` and `gettransaction` no longer mark
  ordinary sends of an output-storage BLSCT wallet as `involvesWatchonly:
  true`. Any send spending a coinbase, stake or received coin was flagged,
  although the wallet held no watch-only scripts. A token input of such a
  wallet also no longer counts toward the NAV amount sent.
- `listtransactions`, `listsinceblock` and `listpendingtransactions` no longer
  report a `txid` for entries of an output-storage wallet that the wallet holds
  as a bare output, without the transaction that created it
  (`"output_storage": true`: payments received from others, staking rewards).
  Those entries used to carry the output id under `txid`, a copy of their
  `outid` that is not a transaction id. The field is now absent instead.
  `outid` still names the output; `gettxfromoutputhash` (or `getoutputinfo`
  with `-outindex`) finds the transaction holding it, and `gettransaction`
  still accepts the `outid` of such an entry. Entries for transactions the
  wallet built itself are unchanged and keep their `txid`. Rows in
  `listsinceblock`'s `removed` array are the exception: they come from reading
  the detached block, so they carry the `txid` of the transaction that held the
  output.
- `gettransaction` called with the `outid` of such an entry still returns that
  `outid` in its top-level `txid` field, because the field is required there.
  The value is an output id, not a transaction id; use `gettxfromoutputhash` to
  find the transaction.
- `simulaterawtransaction` now reports the correct `balance_change` for BLSCT
  transactions. It read each output's visible value, which is zero for a
  confidential output, so a wallet receiving a BLSCT payment saw no change and
  the sender saw its whole input spent with no change returned. Outputs are now
  credited with the amount the wallet recovers from them, staked commitments
  count as the wallet's own, and only NAV outputs count toward the balance
  change (a transparent token output's value used to be added as NAV).
  Simulating a transaction with an out-of-range transparent output value now
  fails with an error instead of summing it.
- On a wallet that stores full transactions (`storage_output=false`), an NFT
  input is no longer debited as NAV. An NFT output carries its value in the
  clear, and the wallet counted that value as NAV spent, so
  `simulaterawtransaction` overstated the NAV leaving the wallet when it spent
  an NFT, and `gettransaction` and `listtransactions` reported an NFT send's
  `amount` as that value instead of zero (the fee was unaffected).
- `removeprunedfunds` now fully forgets a send in a BLSCT wallet created with
  output storage (`storage_output`). Such a wallet also records a local send in
  its per-output records, and those were left behind: the send's change kept
  being counted in the balance and listed by `listblsctunspent`, and the coin
  it spent stayed spent, across restarts. The change is now removed and the
  spent coin is reported as unspent again, as a full-transaction wallet already
  did. A send the staker merged into a block transaction under another hash is
  the exception: that transaction spent the coin and created the change on
  chain, so both are kept.

### Coins

- `listunspent` on an output-storage wallet lists the change of the wallet's
  own sends once. It used to list it twice, once without an `address`, so the
  listed amounts summed to more than the balance. Every BLSCT coin is now
  listed with its address and recovered amount. The wallet's available-balance
  figure no longer counts that change twice either.
- `listunspent` on an output-storage wallet no longer lists the outputs of a
  transaction that is neither confirmed nor in the mempool (for instance a send
  that expired from the mempool or was never relayed), even with
  `include_unsafe`. They were listed as unsafe 0-confirmation coins although no
  balance counts them.
- `listunspent`'s `maximumCount` and `minimumSumAmount` now apply to the
  merged listing of an output-storage wallet, and only to coins that pass the
  `addresses` filter. They used to be applied to each of the wallet's two coin
  lists separately, and to count coins the address filter then dropped, so
  `maximumCount: 1` could list two coins, or none for an address that held
  some (#712, #724).

### Raw transactions, tokens and RFQ

- `createblsctrawtransaction` now accepts an NFT in an output's `token_id`,
  written as the collection's 64-hex token id followed by `#<subid>`, the form
  the RFQ and order RPCs already take. Before, `token_id` had to be exactly 64
  hex characters, so a raw transaction could not send an NFT. A malformed
  `token_id` is still refused with `RPC_INVALID_PARAMETER`, now with the same
  message those RPCs give.
- `setswapintent`, `requestquote`, `sendquote`, `sendorder` and
  `broadcastorder` now accept an NFT as a token argument, written the way
  `listorders` prints it: the 64-hex token id followed by `#<subid>`. The subid
  must be plain decimal with no sign, leading zeros or `0x` prefix; NAV (empty
  or all-zero) cannot carry one, and `#18446744073709551615` (the fungible
  marker) is rejected rather than read as the bare token. The error now names
  the argument (e.g. `buy_token must be a 64-hex token id, ...`) instead of the
  generic `token must be of length 64`.
- `listswapintents` (`token_in`, `token_out`) and `listpendingquoterequests`
  (`buy_token`, `sell_token`) now print the `#<subid>` suffix for an NFT,
  matching `listorders`. Before, the suffix was dropped, so an NFT intent or
  request listed as its fungible token. Output for fungible tokens and NAV is
  unchanged.
- `listorders`: expired standing orders are now dropped from the cache once a
  minute. Before, only an RFQ match pruned them, so on a node that never served
  an RFQ `count` and `bytes` kept counting expired orders until LRU pressure
  evicted them. `listorders` also gained optional `count` and `skip` arguments
  that page through the verbose `orders` list in its existing order (declared
  `order_expiry`, then `quote_id`). Without them every live order is listed, as
  before.
- `cancelrfq` now fails with an error while one of the RFQ's quotes is being
  accepted. Before, it returned `true` and dropped the request even though the
  in-flight accept could still broadcast the swap. Retry once the accept has
  finished: a successful accept drops the request itself, and a failed one
  makes it cancellable again.
- `consolidate` with `max_txs` greater than 1: if building or broadcasting a
  later transaction fails after at least one consolidation was already sent,
  the call now stops and returns the ids of the transactions it sent, instead
  of raising an error and losing them. The failure is written to the wallet
  log. A failure before anything is sent still raises an error as before. A
  short result therefore no longer always means the wallet ran out of outputs
  to merge. Calling `consolidate` again reports the error if it persists.

### Staking

- `listdelegations` entries carry a new `commitment` field: the staked
  commitment, in the same encoding `liststakedcommitments` uses.

### p2pmsg

- `replycandidate` also returns `hex`, the serialized candidate that was sent.
- `getp2pmsginfo` gained a `store` object, present when the user-message store
  is enabled, with `entries`, `bytes`, `last_id` (the highest message id
  assigned so far) and `undecodable`. Ids never repeat, so `last_id` is a
  cursor; pass it as `listp2pmsgs`' `since_id` to receive only messages stored
  from now on. `undecodable` is the number of messages on disk that this node
  cannot read, for example ones written under a different obfuscation key or an
  incompatible store format. They are kept rather than deleted, but are not
  returned by `listp2pmsgs` and are not counted in `entries`, `bytes` or toward
  `-p2pmsgstoresize`. Previously they showed only in a log line at startup.
- `clearp2pmsgs` is unchanged, but its help now spells out how to use it
  safely: `0` (the default) drops every stored message, including ones that
  arrived after the client's last `listp2pmsgs`. To drop only what was read,
  pass the highest id `listp2pmsgs` returned, and skip the call when it
  returned nothing. Passing `last_id` drops everything stored by then, read or
  not. It also removes undecodable messages in its range and counts them in its
  result, so `removed` can exceed the number of messages `listp2pmsgs`
  returned.

### Node and chain

- `gettxoutsetinfo` now hashes every coin in one canonical form: the coin's
  output id, its height and coinbase flag, and the output with BLSCT data in
  the form block-undo data stores it (range-proof body omitted). Previously a
  BLSCT output was hashed with its full range proof when it came from a block,
  but without it once it had been restored by a block disconnect, so the
  `hash_serialized_3` and `muhash` values of the same UTXO set could differ
  between nodes depending on their reorg history, and the `-coinstatsindex`
  muhash drifted away from the one computed from the UTXO set as soon as a
  BLSCT output was spent. On chains with BLSCT outputs both values change;
  values for coins without a range proof are unchanged.
- `gettxfromoutputhash` answers confirmed outputs, including already spent
  ones, from `-outindex` when it is enabled and synced, instead of scanning the
  chain backwards. Without the index its behaviour is unchanged.
- `gettxoutproof` now also accepts output hashes. Without a `blockhash`, it
  finds the block through the unspent output's coin or, failing that, through
  `-txindex`, now trying every requested id rather than only the first. The
  proof commits to the transactions the ids name, so `verifytxoutproof` returns
  txids. Without `-txindex` and with no matching unspent output, the error is
  now "Transaction not found in the utxo set; specify the block hash or enable
  -txindex" (#487).
- `scanblocks` and `scantxoutset` now refuse a BLSCT address
  (`addr(<blsct address>)`) with `RPC_INVALID_PARAMETER`. A BLSCT output's
  scriptPubKey is the same for every recipient, so such a descriptor matched
  every block and every BLSCT coin, even for an address that never received
  anything. BLSCT outputs are found by the wallet's view key (#756).
- `generatetoaddress` and `generatetoblsctaddress` now refuse a negative
  `maxtries` ("JSON integer out of range"), as `generatetodescriptor` already
  did. Before, a negative value wrapped around into a practically unlimited
  number of tries. A `maxtries` above 2147483647, which used to be refused, is
  now accepted.

### Other

- `createmultisig` and `addmultisigaddress` now refuse the `blsct` and
  `blsct-stake` address types with "Multisig addresses cannot be created with
  address type". Passing either one used to abort the node.
- `addmultisigaddress` on a BLSCT wallet now fails with "addmultisigaddress
  does not support BLSCT (confidential) wallets". It defaulted to the `blsct`
  address type there and aborted the node. This includes an explicit `legacy`,
  `p2sh-segwit` or `bech32` type, which on a BLSCT wallet used to return an
  address.
- `dumpwallet` on a legacy (non-descriptor, non-BLSCT) wallet no longer aborts
  the node when it runs with `-addresstype=bech32m`. Keys without an address
  book entry now show their `bech32` address instead, or their legacy address
  for an uncompressed key (with `-addresstype=blsct` such keys used to get an
  empty `addr=` field).
- `fundrawtransaction`'s `input_weights` option now works: any numeric `weight`
  used to fail with an internal error. The minimum accepted weight is now 149,
  the weight of an empty navio input.

New RPCs
--------

- `getoutputinfo <outputhash>` (requires `-outindex`) returns the creating
  `txid`, `vout`, `blockhash`, `height` and `confirmations` of a confirmed
  output, whether a block in the active chain has spent it, and if so a
  `spentby` object with the spending `txid`, `vin`, `blockhash` and `height`.

Removed RPCs
------------

- The node-level PSBT RPCs have been removed: `analyzepsbt`, `combinepsbt`,
  `converttopsbt`, `createpsbt`, `decodepsbt`, `descriptorprocesspsbt`,
  `finalizepsbt`, `joinpsbts` and `utxoupdatepsbt`. PSBTs only describe
  transparent transactions, which mainnet, testnet and blsctregtest do not
  accept; BLSCT transactions are built, inspected and signed with the wallet
  RPCs `createblsctrawtransaction`, `fundblsctrawtransaction`,
  `decodeblsctrawtransaction` and `signblsctrawtransaction` instead, so a node
  running with `-disablewallet` has none of them. The node can no longer
  inspect a PSBT before it is signed: `decodepsbt` and `analyzepsbt` have no
  replacement.
- The wallet PSBT RPCs have been removed as well: `walletcreatefundedpsbt`,
  `walletprocesspsbt` and `psbtbumpfee`. With them the node has no RPC left
  that takes a PSBT, so a PSBT can no longer be signed, combined or finalized
  by the node.
- `migratewallet` is removed. It converted Berkeley DB legacy wallets to SQLite
  descriptor wallets, but Berkeley DB support is gone and every wallet is
  stored in SQLite already, so it could only refuse. Legacy wallets still load
  as before.
- `enumeratesigners` and `walletdisplayaddress` are removed with external
  signer support.

Calling one of the removed RPCs now fails with "Method not found".

Startup options
---------------

### New options

- `-outindex` (default off): maintain the output-id index used by
  `getoutputinfo` and `gettxfromoutputhash`. Incompatible with pruning.
- `-peeroutkeys` (default off): serve per-block BLSCT output keys to light
  wallets (`NODE_OUTKEYS`). Incompatible with `-prune`.
- `-p2pwsexternal=<url>`: the public `ws://` or `wss://` URL of the
  `-p2pwsbind` listener when it sits behind a reverse proxy.
- `-blsctpadoutputs` (wallet, default `1`): always give an ordinary BLSCT send
  a change output (see [BLSCT wallet](#transaction-shape)).
- `navio-staker -signetblockkey=<hex>`: the key that signs each staked block on
  signet (required there).

### Updated options

- `-p2pmsgstoresize` is now split into one budget per message scope: inbox (1:1
  messages to the node's prekey), session (replies to keys minted with
  `mintp2pmsgreplykey`) and broadcast (subscribed topics). The shares are set by
  `USER_STORE_INBOX_PERCENT`, `USER_STORE_SESSION_PERCENT` and
  `USER_STORE_BROADCAST_PERCENT` in `src/p2pmsg/user_inbox.h`. Each scope prunes
  only its own oldest messages when it is full, so a flood of one kind can no
  longer evict another. Previously broadcast messages were pruned first and
  inbox and session messages then shared whatever was left. With the default
  `-p2pmsgstoresize=64` the inbox and session scopes each keep about 25.6 MiB
  and the broadcast scope about 12.8 MiB.

  A node that receives only one kind of message now keeps only that scope's
  share of `-p2pmsgstoresize`, not the whole store. An inbox-only node that
  should keep as many messages as before needs a proportionally larger
  `-p2pmsgstoresize`. A store written by an earlier version that holds more
  than a scope's new share is not pruned at startup. The excess is pruned when
  the next message is stored after upgrading; until then `listp2pmsgs` keeps
  returning it.
- `-signet` now requires `-signetchallenge`; there is no default signet.
- `-par` now also caps every BLSCT signature, range-proof, amount-recovery and
  undo-write worker pool. The undo writers used to be capped at 8 regardless
  (#538, #551).
- `-blsctfixedbase` now appears in `-help`, not only in `-help-debug`. The
  precomputed tables it controls are on by default; `-blsctfixedbase=0`
  verifies every range proof with the generic multi-scalar multiplication
  instead, at some verification speed, to free the tables' memory or rule them
  out when debugging.
- `-whitelist` no longer applies to `-p2pwsbind` peers.
- `navio-staker -delegationrefresh` (default 300 seconds) is now capped at one
  day and also bounds the retry wait of a failing `listdelegations` in wallet
  mode.

### Removed options

- `-signer` has been removed with external signer support. Passing it on the
  command line is now an invalid parameter error; a `signer=` line in the
  configuration file is ignored with a log message.
- The legacy `-checkpoints` debug option has been removed along with the
  Bitcoin-era checkpoint data it controlled, which could never reject a navio
  block. Setting `-checkpoints` is still accepted but has no effect: the node
  starts normally and logs the warning "Option '-checkpoints' is set but
  checkpoints were removed. This option has no effect." Remove it from your
  configuration to silence the warning. The finality checkpoints that reject
  forks from the agreed chain are unaffected and, as before, cannot be turned
  off.

Wallet tool
-----------

- The `navio-wallet` option `-mnemonicpassphrase` is renamed to
  `-seedphraseextension`. `-mnemonicpassphrase` is still accepted as a hidden,
  deprecated alias that prints a warning, and will be removed in a future
  release. Passing both options is an error. `-noseedphraseextension` and
  `-nomnemonicpassphrase` are now refused; before, `-nomnemonicpassphrase` was
  accepted and derived the wallet with the extension `0`.
- `navio-wallet create -blsct -seed=<seed>` now checks the seed first, as
  `createwallet` does: it must be hex, 64 characters for a master seed or 160
  for an audit key. Any other value used to create a wallet with no seed, or
  with a random seed whose mnemonic was never shown.
- `navio-wallet create` now exits with a non-zero status when the wallet cannot
  be created, for example because a wallet of that name already exists or its
  database cannot be opened. It used to print the error and still exit 0.
- An error escaping a `navio-wallet` command is now reported and the tool exits
  with status 1, instead of aborting without a message (#749).
- `navio-tx`, `navio-util` and `navio-wallet` now name themselves correctly in
  their `-version` and `-help` output (#740).

libblsct C API
--------------

### Breaking: message length

`build_range_proof`, `sign_message` and `verify_msg_sig` now take the message as
a pointer and an explicit length. This is a breaking signature change: every
libblsct consumer and language binding must pass the new `msg_len` argument and
be rebuilt against the new header.

```c
BlsctRetVal* build_range_proof(
    const void* vp_uint64_vec,
    const BlsctPoint* blsct_nonce,
    const char* blsct_msg,
    size_t msg_len,
    const BlsctTokenId* blsct_token_id
);

const BlsctSignature* sign_message(
    const BlsctScalar* blsct_priv_key,
    const char* blsct_msg,
    size_t msg_len
);

bool verify_msg_sig(
    const BlsctPubKey* blsct_pub_key,
    const char* blsct_msg,
    size_t msg_len,
    const BlsctSignature* blsct_signature
);
```

- The message no longer needs a NUL terminator and is never read past
  `msg_len`.
- It may be NULL only when `msg_len` is 0. NULL with a non-zero length makes
  `build_range_proof` return `BLSCT_FAILURE`, `sign_message` return NULL and
  `verify_msg_sig` return false.
- `sign_message` and `verify_msg_sig` sign and check all `msg_len` bytes,
  including NUL bytes. Before, a message was cut at its first NUL byte, so a
  signature over `"ab\0cd"` also verified for `"ab"`.
- `build_range_proof` returns `BLSCT_FAILURE` for a message containing a NUL
  byte, since amount recovery returns the message as a C string and would cut
  it there.

### Fee-0 cover candidates

Light wallets can now build fee-0 aggregation cover candidates, the
1-input/1-output self-spends that a wallet serving `AGG_ANN` requests sends
back, which another wallet merges into its aggregated send. Until now
`sign_unsigned_transaction` always appended an `OP_RETURN` fee output, and a
candidate with a fee output is rejected by the candidate pool (consensus allows
one fee output per transaction).

```c
void set_unsigned_transaction_emit_fee_output(void* vp_unsigned_transaction, bool emit_fee_output);
bool get_unsigned_transaction_emit_fee_output(const void* vp_unsigned_transaction);
```

- The default is `true`: signing works as before.
- With `false`, `sign_unsigned_transaction` emits neither the fee output nor
  its fee signature. The inputs must balance the outputs exactly. Signing
  returns `BLSCT_FAILURE` if the fee is not 0.
- `get_unsigned_transaction_emit_fee_output` returns `true` for a NULL handle.

The serialized unsigned transaction (`serialize_unsigned_transaction`, and the
blobs `createblsctrawtransaction`/`signblsctrawtransaction` exchange) gains
format version 2, which appends the flag. It is written only when the fee
output is off; every other unsigned transaction keeps the version 1 layout, so
existing blobs and decoders are unaffected. Decoding now rejects unknown format
versions instead of misreading them.

### DATA predicate payloads

New `get_data_predicate_data` returns the payload of a DATA predicate, without
the operation byte and length prefix that frame it in the serialized predicate
(for example as returned by `get_ctx_out_vector_predicate`).

```c
BlsctRetVal* get_data_predicate_data(
    const BlsctVectorPredicate* blsct_vector_predicate,
    size_t obj_size
);
```

- On success, `result` is `BLSCT_SUCCESS`, `value` points to a copy of the
  payload and `value_size` is its length. An empty payload still returns a
  non-NULL `value`, with `value_size` 0.
- It returns `BLSCT_FAILURE` when `blsct_vector_predicate` is NULL, or when the
  bytes do not start with a complete DATA predicate (another predicate type, an
  unknown operation byte, or a length prefix that promises more bytes than
  follow).
- It returns `BLSCT_MEM_ALLOC_FAILED` if the copy of the payload cannot be
  allocated.
- Bytes after the payload are ignored, as core's predicate parser ignores them.
- Free `value` with `free_obj` and the returned `BlsctRetVal` with `free`, as
  for the other getters.

### Stake delegation and standalone outputs

- New entry points let light wallets delegate stakes and recognise their
  delegated stakes after a restore without reimplementing the payload crypto:
  `set_unsigned_output_stake_delegation`, `is_stake_delegation_data`,
  `build_stake_delegation_data`, `recover_stake_delegation_owner_info` and
  `delete_stake_delegation_owner_info`, with the new
  `BlsctStakeDelegationOwnerInfo` struct (#522).
- New `deserialize_ctx_out`, `serialize_ctx_out` and `delete_ctx_out`
  (de)serialize a single `CTxOut` in the encoding it has inside a serialized
  transaction, so a binding can read an output it stores on its own (#543).

Build
-----

- Windows binaries now embed an application manifest that sets UTF-8 as the
  process code page, so non-ASCII paths (for example a `-datadir` or wallet
  path) and command-line arguments work and print correctly instead of being
  mangled through the system ANSI code page. Windows versions before Windows 10
  version 1903 ignore the setting and keep the old behaviour.
- The `ENABLE_EXTERNAL_SIGNER` build option has been removed.
- The depends `MULTIPROCESS` option and its `capnp`/`libmultiprocess` packages,
  the unbuilt multiprocess IPC sources and the never-built `navioconsensus`
  library code have been removed (#681, #682, #717, #721).
- The BLSCT benchmarks, the univalue tests and the mnemonic and sigcache
  fuzzers are built again, and the fuzz binary builds with MSVC (#637, #679,
  #680, #709).

Removed tools and documentation
-------------------------------

- The signet miner (`contrib/signet/miner`) and `contrib/signet/getcoins.py`
  have been removed (see [Signet](#signet)).
- Bitcoin Core's `contrib/verify-commits`, `contrib/verify-binaries` and
  `contrib/windeploy` and the Bitcoin seed-crawling tools in `contrib/seeds`
  have been removed (#683, #685).
- With no RPC left that takes or returns a PSBT, the PSBT documentation
  (`doc/psbt.md`) and the multisig and offline signing tutorials that were
  built on the PSBT workflow (`doc/multisig-tutorial.md`,
  `doc/offline-signing-tutorial.md`) have been removed. `doc/bips.md` now lists
  BIP 174 and BIP 371 as no longer implemented.
- The release signing key is now published in the repository at
  `contrib/release-keys/releases.asc` (#654).

Tests and other
---------------

- The previous-release compatibility tests, which downloaded Bitcoin Core
  binaries that cannot load a navio chain, have been removed together with the
  test framework's `--previous-releases` option (#719).
- Bitcoin's BIP30 block exceptions, which matched only Bitcoin mainnet blocks,
  have been removed; BIP30 itself stays enforced (#718).
- Output ids are now computed once per transaction and reused on the block,
  mempool and wallet paths (#484, #538).

Credits
=======

Thanks to everyone who contributed to this release.
