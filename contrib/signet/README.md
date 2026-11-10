# Signet

Navio's signet is a BLSCT test network whose blocks must also carry a signature
satisfying the network's challenge script ([BIP 325]). Only the holders of the
challenge keys can produce blocks, in both the proof-of-work phase (up to
`nLastPOWHeight`) and the proof-of-stake phase, so the chain is as stable as its
operators make it.

There is no public navio signet yet, so every node needs `-signetchallenge`. The
challenge also sets the network magic, so nodes with different challenges cannot
talk to each other.

[BIP 325]: https://github.com/bitcoin/bips/blob/master/bip-0325.mediawiki

## Running a signet

1. Pick a secp256k1 key and build the challenge from it. The signer holds only
   that key and no scripts, so use one that needs nothing else, such as the
   P2WPKH script `0014<hash160(pubkey)>` (the one the tests use).
2. Start every node with `-signet -signetchallenge=<challenge hex>`, and point
   them at each other with `-addnode` or `-signetseednode`.
3. Mine the proof-of-work blocks with the key, given as 32 bytes of hex:

   ```
   navio-cli -signet generatetoblsctaddress <n> <address> 1000000 <key hex>
   ```

4. Stake with `navio-staker -signet -signetblockkey=<key hex> ...`. The staker
   reads the challenge from the node. Put the key in the config file rather than
   on the command line, where other users can see it.

A proof of stake needs a set of at least two staked commitments, so lock at
least two stakes before starting the staker.
