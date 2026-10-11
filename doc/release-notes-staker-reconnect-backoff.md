## navio-staker

- A staker that cannot reach its node (with `-rpcwait=0`, or once
  `-rpcwaittimeout` expires) no longer retries and logs the connection error on
  every staking cycle. It logs `Lost connection to the node` once, retries after
  about 2 seconds, doubles the wait after each further failure up to 60 seconds,
  and logs `Reconnected to the node after N failed attempt(s)` once a cycle
  reaches the node again. The dashboard keeps running meanwhile, shows the state
  as `waiting for node`, and still counts every failed attempt under
  `RPC errors`. A connection failure while building a block proposal is now
  handled the same way, instead of being logged as a skipped slot every cycle. A
  `-delegated` staker rescans its delegations on the first cycle after a
  connection failure.
- A `-delegated` staker whose delegation rescan (`liststakedcommitmentsdata`)
  gets an RPC error, for example from a node still warming up after a restart,
  no longer drops the delegations it tracks and their statistics. It keeps
  staking the previous set, logs `Could not load staked commitments data`, and
  retries on the next `-delegationrefresh`.
