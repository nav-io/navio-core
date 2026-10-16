## Updated RPCs

- `createmultisig` and `addmultisigaddress` now refuse the `blsct` and
  `blsct-stake` address types with "Multisig addresses cannot be created with
  address type". Passing either one used to abort the node.
- `addmultisigaddress` on a BLSCT wallet now fails with "addmultisigaddress does
  not support BLSCT (confidential) wallets". It defaulted to the `blsct` address
  type there and aborted the node; it only creates transparent script-hash
  multisig addresses, which a BLSCT wallet does not hand out. This includes an
  explicit `legacy`, `p2sh-segwit` or `bech32` type, which on a BLSCT wallet
  used to return an address.
