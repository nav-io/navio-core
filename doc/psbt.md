# PSBT Howto for Bitcoin Core

Since Bitcoin Core 0.17, an RPC interface exists for Partially Signed Bitcoin
Transactions (PSBTs, as specified in
[BIP 174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)).

This document describes the overall workflow for producing signed transactions
through the use of PSBT, and the specific RPC commands used in typical
scenarios.

## PSBT in general

PSBT is an interchange format for Bitcoin transactions that are not fully signed
yet, together with relevant metadata to help entities work towards signing it.
It is intended to simplify workflows where multiple parties need to cooperate to
produce a transaction. Examples include hardware wallets, multisig setups, and
[CoinJoin](https://bitcointalk.org/?topic=279249) transactions.

### Overall workflow

Overall, the construction of a fully signed Bitcoin transaction goes through the
following steps:

- A **Creator** proposes a particular transaction to be created. They construct
  a PSBT that contains certain inputs and outputs, but no additional metadata.
- For each input, an **Updater** adds information about the UTXOs being spent by
  the transaction to the PSBT. They also add information about the scripts and
  public keys involved in each of the inputs (and possibly outputs) of the PSBT.
- **Signers** inspect the transaction and its metadata to decide whether they
  agree with the transaction. They can use amount information from the UTXOs to
  assess the values and fees involved. If they agree, they produce a partial
  signature for the inputs for which they have relevant key(s).
- A **Finalizer** is run for each input to convert the partial signatures and
  possibly script information into a final `scriptSig` and/or `scriptWitness`.
- An **Extractor** produces a valid Bitcoin transaction (in network format) from
  a PSBT for which all inputs are finalized.

Generally, each of the above (excluding Creator and Extractor) will simply add
more and more data to a particular PSBT, until all inputs are fully signed. In a
naive workflow, they all have to operate sequentially, passing the PSBT from one
to the next, until the Extractor can convert it to a real transaction. In order
to permit parallel operation, **Combiners** can be employed which merge metadata
from different PSBTs for the same unsigned transaction.

The names above in bold are the names of the roles defined in BIP174. They're
useful in understanding the underlying steps, but in practice, software and
hardware implementations will typically implement multiple roles simultaneously.

## PSBT in Bitcoin Core

### RPCs

The node has no RPCs that create, update, combine, join, finalize, decode or
analyze a PSBT on its own. What remains are the wallet RPCs:

- **`walletcreatefundedpsbt` (Creator, Updater)** is a wallet RPC that creates a
  PSBT with the specified inputs and outputs, adds additional inputs and change
  to it to balance it out, and adds relevant metadata. In particular, for inputs
  that the wallet knows about (counting towards its normal or watch-only
  balance), UTXO information will be added. For outputs and inputs with UTXO
  information present, key and script information will be added which the wallet
  knows about.
- **`walletprocesspsbt` (Updater, Signer, Finalizer, Extractor)** is a wallet
  RPC that takes as input a PSBT, adds UTXO, key, and script data to inputs and
  outputs that miss it, and optionally signs inputs. Where possible it also
  finalizes the partial signatures. Once all inputs are finalized it reports the
  PSBT as `complete` and returns the fully signed transaction in its `hex`
  field, which can be broadcast with `sendrawtransaction`.
- **`psbtbumpfee`** is a wallet RPC that bumps the fee of an opt-in-RBF
  transaction and returns the replacement as a PSBT instead of signing it.
- The `psbt` option of the wallet RPCs `send` and `sendall` makes them return a
  PSBT instead of a signed transaction.

### Workflows

#### Multisig with multiple Bitcoin Core instances

This example uses `addmultisigaddress` and `importaddress`, which only work with
legacy wallets.

Alice, Bob, and Carol want to create a 2-of-3 multisig address. They're all
using Bitcoin Core. We assume their wallets only contain the multisig funds. In
case they also have a personal wallet, this can be accomplished through the
multiwallet feature - possibly resulting in a need to add `-rpcwallet=name` to
the command line in case `navio-cli` is used.

Setup:

- All three call `getnewaddress` to create a new address; call these addresses
  _Aalice_, _Abob_, and _Acarol_.
- All three call `getaddressinfo "X"`, with _X_ their respective address, and
  remember the corresponding public keys. Call these public keys _Kalice_,
  _Kbob_, and _Kcarol_.
- All three now run `addmultisigaddress 2 ["Kalice","Kbob","Kcarol"]` to teach
  their wallet about the multisig script. Call the address produced by this
  command _Amulti_. They may be required to explicitly specify the same
  addresstype option each, to avoid constructing different versions due to
  differences in configuration.
- They also run `importaddress "Amulti" "" false` to make their wallets treat
  payments to _Amulti_ as contributing to the watch-only balance.
- Others can verify the produced address by running
  `createmultisig 2 ["Kalice","Kbob","Kcarol"]`, and expecting _Amulti_ as
  output. Again, it may be necessary to explicitly specify the addresstype in
  order to get a result that matches. This command won't enable them to initiate
  transactions later, however.
- They can now give out _Amulti_ as address others can pay to.

Later, when _V_ BTC has been received on _Amulti_, and Bob and Carol want to
move the coins in their entirety to address _Asend_, with no change. Alice does
not need to be involved.

- One of them - let's assume Carol here - initiates the creation. She runs
  `walletcreatefundedpsbt [] {"Asend":V} 0 {"subtractFeeFromOutputs":[0], "includeWatching":true}`.
  We call the resulting PSBT _P_. _P_ does not contain any signatures.
- Carol needs to sign the transaction herself. In order to do so, she runs
  `walletprocesspsbt "P"`, and gives the resulting PSBT _P2_ to Bob.
- Bob checks that the transaction has indeed just the expected input, and an
  output to _Asend_, and the fee is reasonable. If he agrees, he calls
  `walletprocesspsbt "P2"` to sign. With both Carol's and Bob's signature the
  PSBT is complete, and the result holds the fully signed transaction _T_ in its
  `hex` field.
- Finally anyone can broadcast the transaction using `sendrawtransaction "T"`.

The signers have to sign one after another, passing the PSBT on: without
`combinepsbt`, PSBTs signed in parallel cannot be merged.
