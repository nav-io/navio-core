## navio-staker

- A wallet-mode staker whose `listdelegations` call keeps failing no longer
  retries it and logs the error on every staking cycle. It logs the first
  failure, retries after about 2 seconds, doubles the wait after each further
  failure up to `-delegationrefresh` (default: 300 seconds, now capped at one
  day), and logs `Listed delegations again after N failed attempt(s)` once the
  call succeeds. A change in the wallet's staked commitments (a stake added,
  delegated or unlocked) is retried on the cycle that sees it, without waiting.
  While the call fails, delegated stakes the staker has not yet looked up pay
  `-coinbasedest`; once the node answers again, that lasts until the next
  scheduled retry (at most `-delegationrefresh`) or the next staked-commitment
  change, whichever comes first. `-delegationrefresh` therefore now also applies
  outside `-delegated` mode.
