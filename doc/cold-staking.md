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
   navio-staker -delegated -delegationkey=<hex> \
       [-operatoraddress=<addr> -operatorfee=<bps>] [-delegationrefresh=<sec>]
   ```

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
- **`stakelock` consolidation folds delegated commitments too.** By default
  `stakelock` consolidates all of the wallet's staked commitments into one new
  output, which would consume (and thereby revoke) existing delegations. Run
  the node with `-consolidatestakedcommitments=0`, or delegate from a wallet
  that holds no other stakes.
- Rewards accumulate in the owner's wallet as ordinary outputs; re-staking
  them requires the owner to run `delegatestake` again (the spend key never
  leaves the owner's machine, so compounding cannot be automated by the
  operator).

## RPC / tool reference

- `delegatestake amount delegate_pubkey [reward_address] [verbose]` — wallet
  RPC; locks `amount` and delegates block production. The delegation is bound
  to a fresh commitment (no consolidation), so each call delegates exactly the
  requested amount.
- `liststakedcommitmentsdata` — node RPC; lists all unspent staked-commitment
  outputs with their predicate data. Public information; used by operators to
  discover delegations.
- `getblocktemplate {"coinbasedest": A, "coinbasefeedest": B, "coinbasefeebps": N}`
  — the template's coinbase pays `N/10000` of the reward to `B` and the rest
  to `A`.
- `navio-staker -gendelegationkey` — generate an operator key pair.
- `navio-staker -delegated -delegationkey=<hex>` — run as a delegation
  operator; no wallet required on the staking machine.
