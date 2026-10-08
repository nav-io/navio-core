P2P and network changes
-----------------------

- `-whitelist` no longer applies to peers that connect through a `-p2pwsbind`
  WebSocket listener. Those connections usually reach the node through a reverse
  proxy, so every client appears to come from the proxy's (often loopback)
  address and an address-based permission cannot single any of them out.
  WebSocket peers now get no permissions, the same as inbound Tor peers. A
  `-whitelist` entry covering the proxy's address still applies to ordinary P2P
  connections from it.
