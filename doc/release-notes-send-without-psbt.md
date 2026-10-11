## Updated RPCs

- `send` and `sendall` no longer return a `psbt` field. A transaction the wallet
  cannot fully sign, for example one from a wallet with private keys disabled,
  is now returned as a raw transaction in the `hex` field, signed as far as the
  wallet could, with `complete` set to `false`. As with
  `signrawtransactionwithwallet`, any inputs that failed signature verification
  are listed with the reason in an `errors` array, which is omitted when there
  are none. Nothing is broadcast or added to the wallet in that case.
- With `add_to_wallet=false`, `send` and `sendall` return only the signed
  transaction in `hex` and its `txid`, no longer also a `psbt`.
