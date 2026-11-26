# Navio Core 0.2.3

Navio Core 0.2.3 is a maintenance release of 0.2.2 with one fix to block
validation. All node operators, especially stakers and anyone serving
peers, should upgrade.

## Block validation

A proof-of-stake block's hash covers its header but not its proof of stake,
so a copy of a block with a changed proof has the same hash as the real
block. Before this release, a node that processed such a copy first marked
the hash invalid and then refused the real block, and the peers sending it,
until an operator ran `reconsiderblock`.

Now a failing proof of stake rejects only that copy:

- A proof-of-stake block that extends the tip has its proof verified before
  it is stored or relayed. A copy whose proof fails is not stored, its hash
  is not marked invalid, and the peer that sent it is disconnected.
- If a stored copy's proof fails when the block is connected, the stored
  copy is discarded and the block is downloaded again.

There is no consensus change: every block valid under 0.2.2 is valid under
0.2.3, and the reverse.

If a node running an earlier version is stuck on a block that the rest of
the network has built on, `reconsiderblock <hash>` makes it try the block
again.
