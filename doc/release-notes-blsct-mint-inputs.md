## Wallet

- `minttoken` and `mintnft` no longer spend the issuer's existing coins of the
  token being minted. The minted amount comes from the mint predicate, so a
  mint only needs native coins for its fee, but the wallet used to add every
  coin of the minted token (or, for an NFT mint, of the exact NFT id) as an
  input and return it as change. While such a mint was unconfirmed the held
  tokens moved with it, and if it was never mined (dropped from the mempool on
  a restart without rebroadcast, or evicted because another mint filled the
  token's supply cap) `gettokenbalance` reported 0 although the earlier mint
  was confirmed. Mints now spend native coins only.
