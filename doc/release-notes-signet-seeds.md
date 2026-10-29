## P2P and network changes

- The default signet no longer lists Bitcoin Core's signet DNS seed and
  hardcoded nodes, which led a navio signet node to Bitcoin signet peers. It has
  no seeds now: connect with `-addnode`, `-seednode` or `-connect`. A custom
  signet still takes its seeds from `-signetseednode`.
