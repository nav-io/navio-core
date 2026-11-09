## Signet

- Signet is now a BLSCT network. It used Bitcoin's signet challenge, genesis
  block and assumevalid with BLSCT disabled, so it could only follow Bitcoin's
  signet. It now has its own genesis block, BLSCT addresses with the `snv`
  prefix (matching libblsct's `Signet` chain), proof-of-work blocks up to height
  1000 and proof-of-stake blocks after, and P2P port 48488.
- There is no default signet network: `-signet` now requires `-signetchallenge`,
  and naviod refuses to start without it. The default signet no longer lists
  Bitcoin Core's signet seeds.
- Every block must be signed for the challenge, proof-of-stake blocks included.
  `generatetoblsctaddress` takes the signing key as a new `signetkey` argument
  on signet, and `navio-staker` takes it as `-signetblockkey`. Both take the key
  as 32 bytes of hex.
- Fixed: a signet block's signature did not commit to the block, because the
  signed transaction spent an output identified only by its own hash (zero value
  and the challenge). One valid signature therefore validated any block. It now
  spends the transaction that carries the block data, so the signature covers
  the block's version, previous hash, transactions and time.
- `contrib/signet/getcoins.py`, a client for Bitcoin's signet faucet, has been
  removed; `contrib/signet/README.md` now describes running a navio signet.
