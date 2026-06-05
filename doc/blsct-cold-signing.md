# Navio (BLSCT) Cold-Signing with Two Machines

A Bitcoin-style air-gapped setup for Navio's confidential transactions (BLSCT),
using only `navio-cli` RPC commands.

- **ONLINE machine** — holds only the **audit key** (private view key + public
  spend key). Watches balances, builds and funds the unsigned transaction, and
  broadcasts the signed result. Cannot spend.
- **OFFLINE machine** — holds the real spend keys. Signs the unsigned
  transaction. **Needs no copy of the blockchain**: it derives every spending key
  from the prevout data embedded in the unsigned transaction. Never touches the
  network.

> **How signing works in BLSCT.**
> A BLSCT transaction carries a single aggregated BLS signature rather than a
> per-input `scriptSig`. The online (watch-only) wallet builds and funds the
> transaction and attaches, for every input, the prevout data needed to sign
> (its public `blsctData`, `value` and `gamma`) — but it cannot produce the
> signature because it has no private spend key. The offline wallet then derives
> each input's private spending key from its own view+spend keys plus that
> attached data, and aggregates the signature. `signblsctrawtransaction` falls
> back to looking the output up on-chain only when no prevout data is attached.

---

## Part 1 — OFFLINE: generate the wallet (real spend keys)

```bash
# Create a BLSCT wallet. A fresh 24-word mnemonic is generated and returned.
navio-cli -named createwallet wallet_name="spend" blsct=true

# (optional) encrypt it
navio-cli -rpcwallet=spend encryptwallet "a-strong-passphrase"
```

Back up the secrets and keep them air-gapped:

```bash
navio-cli -rpcwallet=spend dumpmnemonic     # 24-word BIP-39 phrase
navio-cli -rpcwallet=spend getblsctseed     # 64-hex master seed
```

Export the **audit key** to carry to the online machine (this is the *only*
thing that leaves the offline box at setup time):

```bash
navio-cli -rpcwallet=spend getblsctauditkey
# -> 160-hex-char string = <private_view_key (64)> + <public_spend_key (96)>
```

The audit key lets the holder **see** all wallet activity (recover
amounts/blinding factors) but **never spend** — it contains no spend private key.

---

## Part 2 — ONLINE: import the audit key (watch-only)

Pass the audit key as the `seed` to `createwallet`. An 80-byte (160-hex) seed is
auto-detected as a **view key import** and the wallet is created with private
keys disabled:

```bash
navio-cli -named createwallet \
  wallet_name="watch" \
  blsct=true \
  seed="<AUDIT_KEY_FROM_OFFLINE>"
```

This wallet syncs with the chain and tracks balances. Verify it imported as
watch-only (no private keys) and generate addresses to receive funds:

```bash
navio-cli -rpcwallet=watch getwalletinfo            # "blsct": true, "private_keys_enabled": false
navio-cli -rpcwallet=watch getnewaddress "" blsct   # receive address
navio-cli -rpcwallet=watch getblsctbalance
```

The online wallet can recover amounts and blinding factors (it has the view
key), but it cannot sign — `signblsctrawtransaction` on this wallet refuses with
a "watch-only" error.

---

## Part 3 — Spending: online builds, offline signs, online broadcasts

The offline machine here needs **no blockchain** — it only needs its keys and
the unsigned transaction.

### Step 1 — ONLINE: build + fund the unsigned transaction

```bash
# Pick which UTXOs to spend
navio-cli -rpcwallet=watch listblsctunspent
# each entry: { "outid": "...", "amount": ..., ... }

# Build the transaction, choosing the input(s) and output(s).
navio-cli -rpcwallet=watch createblsctrawtransaction \
  '[{"outid":"<OUTID>"}]' \
  '[{"address":"<DEST_ADDR>","amount":<NAVOSHIS>,"memo":"payment"}]'
# -> <RAW_HEX>

# Add change + fee. fundblsctrawtransaction also embeds, for every input, the
# prevout data the offline signer needs (it does NOT and cannot sign).
navio-cli -rpcwallet=watch fundblsctrawtransaction "<RAW_HEX>"
# -> <UNSIGNED_HEX>
```

Transfer `<UNSIGNED_HEX>` to the OFFLINE machine (QR / USB). It contains no
private keys — only public prevout data, amounts and blinding factors.

### Step 2 — OFFLINE: inspect + sign (no blockchain required)

```bash
# (unlock if encrypted)
navio-cli -rpcwallet=spend walletpassphrase "a-strong-passphrase" 600

# Decode + inspect before signing — works fully offline.
navio-cli -rpcwallet=spend decodeblsctrawtransaction "<UNSIGNED_HEX>"

# Sign. Each input's spending key is derived from the attached prevout data
# using this wallet's view+spend keys — no chain lookup needed.
navio-cli -rpcwallet=spend signblsctrawtransaction "<UNSIGNED_HEX>"
# -> <SIGNED_HEX>
```

Carry **only `<SIGNED_HEX>`** back to the ONLINE machine. The signed transaction
carries just the aggregated signature — no spending keys.

> The offline wallet must have generated (from the same seed) a sub-address pool
> that covers the addresses being spent. The default pool covers freshly created
> wallets; if you spend from many sub-addresses, top the pool up first.

### Step 3 — ONLINE: broadcast

```bash
navio-cli sendrawtransaction "<SIGNED_HEX>"
```

---

## How the deferred-key mechanism works

- On a **watch-only** wallet, `createblsctrawtransaction` and
  `fundblsctrawtransaction` cannot derive spending keys, so they leave each
  input's spending key empty and instead **attach the prevout** (`CTxOut`, which
  carries the public `blsctData`) to the unsigned transaction.
- `signblsctrawtransaction`, for each input that has no spending key:
  1. derives it from the **attached prevout** using the wallet's view+spend keys
     and deterministic sub-address pool (the offline, chainless path); or
  2. if no prevout was attached, falls back to looking the output up in the
     wallet/chain (requires a synced node); otherwise it errors.
- On a **full** spend wallet, the keys are still derived at create/fund time as
  before, so existing single-machine flows are unchanged.

---

## Advanced: explicit per-input fields (HTLC / atomic-swap)

For script outputs such as HTLCs you can bypass automatic derivation entirely by
supplying `value`, `gamma` and `spending_key` per input. The offline wallet can
derive the spending key for its top-level address with `deriveblsctspendingkey`
(sub-addresses are not supported by that RPC):

```bash
# ONLINE: recover value + gamma (view key can do this)
navio-cli -rpcwallet=watch getblsctrecoverydata "<OUTID>"
# -> outputs[i]: { "amount_navoshi", "gamma", ... }

# OFFLINE: derive the key, then create with all fields explicit
navio-cli -rpcwallet=spend deriveblsctspendingkey "<BLINDING_KEY_HEX>" "<TOP_LEVEL_ADDR>"
navio-cli -rpcwallet=spend createblsctrawtransaction \
  '[{"outid":"<OUTID>","value":<NAVOSHIS>,"gamma":"<GAMMA_HEX>","spending_key":"<SPENDING_KEY_HEX>"}]' \
  '[{"address":"<DEST_ADDR>","amount":<NAVOSHIS>,"memo":"payment"}]'
navio-cli -rpcwallet=spend signblsctrawtransaction "<UNSIGNED_HEX>"
```

---

## Command reference

| RPC | Machine | Purpose |
|-----|---------|---------|
| `createwallet ... blsct=true` | offline | generate spend wallet |
| `dumpmnemonic` / `getblsctseed` | offline | back up secrets |
| `getblsctauditkey` | offline | export view+pubspend (audit) key |
| `createwallet ... seed=<auditkey>` | online | import watch-only wallet |
| `listblsctunspent` | online | list UTXOs |
| `createblsctrawtransaction` | online | build tx, embed prevout data |
| `fundblsctrawtransaction` | online | add change + fee, embed prevout data |
| `getblsctrecoverydata` | online | recover `amount` + `gamma` |
| `decodeblsctrawtransaction` | offline | inspect before signing |
| `deriveblsctspendingkey` | offline | derive sk (top-level addr only) |
| `signblsctrawtransaction` | offline | derive keys from attached data + sign |
| `sendrawtransaction` | online | broadcast |

---

A functional test exercising this exact flow (online build/fund → offline sign
with no blockchain → online broadcast) lives at
`test/functional/blsct_cold_signing.py`.
