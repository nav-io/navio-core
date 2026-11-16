# Internal c++ interfaces

The following interfaces are defined here:

- [`Chain`](chain.h) — used by wallet to access blockchain and mempool state.
  Added in [#14437](https://github.com/bitcoin/bitcoin/pull/14437),
  [#14711](https://github.com/bitcoin/bitcoin/pull/14711),
  [#15288](https://github.com/bitcoin/bitcoin/pull/15288), and
  [#10973](https://github.com/bitcoin/bitcoin/pull/10973).

- [`ChainClient`](chain.h) — used by node to start & stop `Chain` clients. Added
  in [#14437](https://github.com/bitcoin/bitcoin/pull/14437).

- [`WalletLoader`](wallet.h) — the wallet's `ChainClient`, which also creates
  and loads wallets.

- [`Wallet`](wallet.h) — a handle on one loaded wallet, passed to
  `handleLoadWallet` callbacks. Added in
  [#10244](https://github.com/bitcoin/bitcoin/pull/10244).

- [`Handler`](handler.h) — returned by `handleEvent` methods on interfaces above
  and used to manage lifetimes of event handlers.

- [`Echo`](echo.h) — a test interface behind the hidden `echoipc` RPC.

- [`Init`](init.h) — used on startup to create the `Chain`, `WalletLoader` and
  `Echo` objects. Added in
  [#19160](https://github.com/bitcoin/bitcoin/pull/19160).

The interfaces above define boundaries between the node and the wallet, so each
can be tested, developed, and understood independently. These interfaces are not
currently designed to be stable or to be used externally.
