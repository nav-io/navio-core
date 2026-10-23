## Updated RPCs

On networks that only accept confidential (BLSCT) transactions, which includes
mainnet and testnet, these RPCs now fail with an error saying so instead of
doing work that can never confirm:

- `generatetoaddress`, `generatetodescriptor` and `generateblock` built blocks
  paying a transparent coinbase, which these networks always reject. Up to the
  network's last proof-of-work height, `generatetoblsctaddress` can mine
  instead; above it, blocks must be proof-of-stake, and the error says so.
- `createrawtransaction` and `signrawtransactionwithkey` built and signed
  transparent transactions, which these networks never confirm. Use
  `createblsctrawtransaction` and `signblsctrawtransaction`.
- `addmultisigaddress` and `newkeypool` only created transparent (ECDSA)
  multisig scripts and keys.
- `settxfee` set a rate only transparent transactions use; BLSCT fees follow the
  consensus fee rate, so it silently had no effect.
