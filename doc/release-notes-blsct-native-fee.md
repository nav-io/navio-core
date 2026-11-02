## P2P and network changes

- The mempool now rejects two BLSCT transaction shapes as non-standard
  (`TX_NOT_STANDARD`, so the sending peer is not penalised):
  - `non-native-fee-output`: a fee output that pays a non-zero value in a
    token other than the native one. The consensus minimum fee is a native
    per-weight rate, so a token issuer could otherwise pay it in a token they
    mint for free.
  - `blsct-vin-empty`: a transaction with no inputs. Only a mint can balance
    one, so it is the zero-input form of the same transaction.

  Block validation is unchanged: blocks carrying either shape stay valid, so
  this is not a consensus change. The checks are not affected by
  `-acceptnonstdtxn`.

## Mining

- A single transaction with a token-denominated fee used to be able to halt
  block production. The block assembler merges every selected transaction
  into one, folding all fees into a single native fee output; a token fee
  folded into it leaves the merged transaction unbalanced, so every template
  that also held another transaction failed `TestBlockValidity`. Besides the
  new mempool rule, the assembler now drops such a transaction (and any
  transaction spending its outputs) before merging, and the merge itself
  refuses a non-native fee instead of building an invalid block transaction.
