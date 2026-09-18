P2P and network changes
-----------------------

- A new optional `-p2pwsbind=<addr>[:<port>]` option makes `naviod` accept P2P
  connections carried over WebSocket (RFC 6455), so that browser-based and other
  standalone SDK clients without raw TCP access can connect as ordinary inbound
  peers. The WebSocket connection carries the normal P2P byte stream in binary
  frames. The listener is off by default, speaks plain `ws://` only (front it
  with a TLS-terminating reverse proxy for `wss://`) and is documented in
  `doc/p2p-encrypted-messaging.md`.

Updated RPCs
------------

- `getpeerinfo` gained a `websocket` boolean field.
