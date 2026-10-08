Staking changes
---------------

- `navio-staker` in wallet mode (without `-delegated`) also stakes the
  wallet's own delegated stakes. A block it produces with one of them now pays
  the reward to that delegation's reward address instead of `-coinbasedest`.
  Before, the reward reached the wallet but not the reward address, so
  `listdelegations` kept reporting `rewards_received` as 0. The staker falls
  back to `-coinbasedest` when connected to a node whose `listdelegations`
  lacks the new `commitment` field.

RPC changes
-----------

- `listdelegations` entries carry a new `commitment` field: the staked
  commitment, in the same encoding `liststakedcommitments` uses.
