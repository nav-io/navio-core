P2P and network changes
-----------------------

- A new optional `-p2pwsbind=<addr>[:<port>]` option makes `naviod` accept P2P
  connections carried over WebSocket (RFC 6455), so that browser-based and other
  standalone SDK clients without raw TCP access can connect as ordinary inbound
  peers. The WebSocket connection carries the normal P2P byte stream in binary
  frames. The listener is off by default, speaks plain `ws://` only (front it
  with a TLS-terminating reverse proxy for `wss://`) and is documented in
  `doc/p2p-encrypted-messaging.md`.

- A node whose WebSocket listener is publicly usable now advertises the new
  `NODE_P2P_WS` service bit (`1 << 30`, `P2P_WS`) and, right after the version
  handshake, sends peers a `wsendpoint` message with the listener's port and,
  when it sits behind a reverse proxy, its public URL. The bit is set when a
  `-p2pwsbind` address is not loopback-only, or when the new
  `-p2pwsexternal=<ws(s)://host[:port][/path]>` option names the public URL
  (its port, or 80/443 by scheme, is the one announced). A loopback-only
  listener without `-p2pwsexternal` is not advertised.

Updated RPCs
------------

- `getpeerinfo` gained a `websocket` boolean field, plus `ws_port` and
  `ws_url` for peers that announced a WebSocket endpoint via `wsendpoint`.
