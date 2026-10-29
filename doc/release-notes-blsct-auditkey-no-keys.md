## RPC

- `getblsctauditkey` on a BLSCT wallet that holds no keys (a blank wallet, or
  one created with private keys disabled and no audit key) now fails with
  `RPC_WALLET_BLANK` (-37) and a message naming the cause, as `getblsctseed`
  does. It used to fail with a generic error (-1) carrying an internal message.
