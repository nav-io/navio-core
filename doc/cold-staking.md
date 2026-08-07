# Delegated Cold Staking

Navio supports delegated cold staking with **no consensus changes**: a wallet
owner can let a third-party "operator" produce blocks with their staked coins
while the coins themselves remain spendable only by the owner's offline spend
key.

## How it works

Navio's BLSCT proof of stake only requires the *opening* of a staked Pedersen
commitment — its `(value, gamma)` pair — to produce a block. It never requires
the spending key, which is only needed to spend or unstake the output. Cold
staking exploits exactly this split:

1. The operator generates a delegation key pair and publishes the public key:

   ```
   navio-staker -gendelegationkey
   ```

2. The owner locks a stake and delegates it:

   ```
   navio-cli delegatestake 1000 <operator_pubkey> [reward_address]
   ```

   This creates a normal staked-commitment output, plus a `DATA` predicate on
   that output containing the commitment's opening and the reward address,
   encrypted to the operator's delegation key (ECDH + ChaCha20-Poly1305 with a
   fresh ephemeral key per delegation). `DATA` predicates are consensus no-ops,
   so the chain accepts the output exactly like any other stake.

3. The operator runs a wallet-less staker:

   ```
   navio-staker -delegated -delegationkeyfile=<path> \
       [-operatoraddress=<addr> -operatorfee=<bps>] [-delegationrefresh=<sec>] \
       [-statsfile=<path>]
   ```

   (`-delegationkey=<hex>` is also accepted, but a key on the command line is
   visible to other users in the process list; prefer `-delegationkeyfile`.)

   The staker periodically scans the chain's staked outputs
   (`liststakedcommitmentsdata` RPC), trial-decrypts each delegation payload,
   verifies the opening against the on-chain commitment, and stakes with the
   standard proof-of-stake path. Block rewards are paid to the owner's reward
   address; if `-operatorfee` is set, that share (in basis points) goes to
   `-operatoraddress` via a second coinbase output.

4. The owner revokes at any time with `stakeunlock` (requires the spend key).
   The commitment leaves the staked set and the delegation dies with it.

## Trust model

| Party    | Can                                                            | Cannot                              |
|----------|----------------------------------------------------------------|-------------------------------------|
| Operator | produce blocks with the delegated stake; see the delegated outputs' amounts; redirect *future* rewards | spend or unstake the principal; see anything else in the owner's wallet |
| Owner    | revoke unilaterally at any time; keep spend key offline        | cryptographically force the reward destination |

Important caveats:

- **Reward routing is advisory.** The operator builds its own coinbase, so
  nothing on-chain forces it to honor the delegated reward address or the
  agreed fee. Owners should monitor payouts and revoke misbehaving operators;
  operators compete on reputation.
- **No view keys are shared.** The operator learns only the `(value, gamma)`
  openings of the outputs explicitly delegated to it.
- **Delegated outputs are publicly distinguishable** (they carry a predicate),
  though the amount and the operator's identity stay hidden from third
  parties.
- **Consolidation is delegation-aware.** Stake consolidation only folds
  commitments that share the same delegation identity (same delegate key and
  reward address, recovered by the owner wallet from the on-chain payload):
  `stakelock` merges only undelegated stakes, and `delegatestake` merges only
  stakes already delegated with identical parameters. A delegation is
  therefore never silently revoked or extended by an unrelated stake
  operation.
- Rewards accumulate in the owner's wallet as ordinary outputs; the spend key
  never leaves the owner's machine, so compounding cannot be automated by the
  operator. The owner can run `compounddelegations` periodically (e.g. from
  cron) to fold accumulated rewards back into the delegation.
- **Owners can audit their delegations from the chain alone.**
  `listdelegations` recovers every active delegation (delegate key, reward
  address, amount) from the on-chain payloads, and — when the reward address
  belongs to the wallet — sums the coinbase rewards received on it, so an
  owner can check the operator is honoring the reward address before deciding
  to revoke. `getbalances` reports the delegated portion of the staked balance
  separately (`delegated_staked_commitment_balance`).
- **Changing operator or reward address does not interrupt staking.**
  `redelegatestake` spends the delegated commitments directly into a new
  staked output carrying the new delegation payload, so the stake never
  leaves the staking set (no unlock/re-lock gap).

## RPC / tool reference

- `delegatestake amount delegate_pubkey [reward_address] [verbose]` — wallet
  RPC; locks `amount` and delegates block production. The delegation is bound
  to a fresh commitment (no consolidation), so each call delegates exactly the
  requested amount.
- `listdelegations` — wallet RPC; lists the wallet's active delegations with
  the delegate key, reward address, amount and (for wallet-owned reward
  addresses) the coinbase rewards received.
- `redelegatestake from_delegate_pubkey delegate_pubkey [reward_address]
  [verbose]` — wallet RPC; moves existing delegations to a new delegate
  and/or reward address in a single transaction, without leaving the staking
  set.
- `compounddelegations [delegate_pubkey] [min_amount]` — wallet RPC; folds the
  wallet's spendable balance (minus a fee margin) into an existing delegation.
  Intended to be run periodically to compound rewards.
- `liststakedcommitmentsdata` — node RPC; lists all unspent staked-commitment
  outputs with their predicate data, creation height and confirmations. Public
  information; used by operators to discover delegations. The scan is cached
  per chain tip, so several polling operators only cost one UTXO iteration
  per block.
- `getblocktemplate {"coinbasedest": A, "coinbasefeedest": B, "coinbasefeebps": N}`
  — the template's coinbase pays `N/10000` of the reward to `B` and the rest
  to `A`.
- `navio-staker -gendelegationkey` — generate an operator key pair.
- `navio-staker -delegated -delegationkeyfile=<path>` — run as a delegation
  operator; no wallet required on the staking machine. With `-statsfile=<path>`
  the staker maintains a JSON file of per-delegation accounting: blocks
  accepted/rejected per delegation, last block hash/time and reward address.
