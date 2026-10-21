## Updated RPCs

On networks that only accept confidential (BLSCT) transactions, which includes
mainnet and testnet, no wallet can hold a transparent coin, so these wallet RPCs
now fail with an error saying so. The spend RPCs refuse every wallet, not only
BLSCT ones; the BLSCT alternatives they name need a BLSCT wallet.

- `sendmany`, `send` and `sendall` built transparent transactions, which these
  networks never confirm. Use `sendtoblsctaddress`.
- `fundrawtransaction` and `signrawtransactionwithwallet` funded and signed
  transparent transactions. Use `fundblsctrawtransaction` and
  `signblsctrawtransaction`.
- `bumpfee` replaced transparent transactions. There is no BLSCT fee bump; send
  a new confidential transaction with `sendtoblsctaddress` instead.
- `keypoolrefill` on a non-BLSCT wallet only refilled transparent (ECDSA) keys.
  It keeps working on BLSCT wallets, where it refills the BLSCT subaddress pool.

`sendtoaddress` is unchanged: on these networks it already sends a confidential
transaction through `sendtoblsctaddress`.
