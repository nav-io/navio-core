## navio-staker

- `navio-staker` now takes turns between the commitments it stakes, in wallet
  mode and in `-delegated` mode. Each cycle it starts with the commitment after
  the one that produced its last block, instead of always starting with the
  first, so every stake that can produce a block gets its turn. Before, the
  first commitment in the list that could stake produced every block; with
  several stakes, which one earned the rewards depended on the order the wallet
  happened to list them in. In `-delegated` mode the rewards (and the
  per-delegation counts in `-statsfile`) are now spread across the delegations
  instead of going to the most confirmed one.
