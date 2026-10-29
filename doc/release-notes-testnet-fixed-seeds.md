## P2P and network changes

- Testnet no longer has any fixed seeds. The built-in testnet list was Bitcoin's
  testnet3 node list, so a testnet node with no known peers dialed Bitcoin
  testnet3 nodes on port 18333, none of which can serve Navio blocks. Navio
  testnet has no known seed nodes yet: connect a testnet node with `-addnode`,
  `-seednode` or `-connect`.
