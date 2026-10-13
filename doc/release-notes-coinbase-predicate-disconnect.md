Block and transaction handling
------------------------------

- A BLSCT block whose coinbase carries a token or NFT predicate that depends on
  another transaction in the same block is now disconnected correctly. Such a
  block connected normally, but disconnecting it failed, so a reorganization
  past it, `invalidateblock` on it and `verifychain` at level 3 or higher all
  failed. The coinbase's predicates are applied after the block's other
  transactions on connect, and are now reverted before them on disconnect. Block
  validity is unchanged: this does not alter which blocks are accepted.
- A node that is already unable to reorganize past such a block needs this
  release to do so.
