# Libraries

The internal libraries are static CMake targets defined in
[`src/CMakeLists.txt`](../../src/CMakeLists.txt) and the `CMakeLists.txt` files
of its subdirectories. They are built only as dependencies of the executables
and are not installed.

| Name                  | Description                                                                                                                                                                                       |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| _navio_crypto_        | Hash functions, ciphers and MACs in `src/crypto/`.                                                                                                                                                |
| _navio_clientversion_ | Client version and build information (`clientversion.cpp`).                                                                                                                                       |
| _navio_util_          | Lower-level common functionality in `src/util/`, plus logging, randomness, streams, synchronization and secure memory support.                                                                    |
| _navio_blsct_core_    | BLSCT primitives in `src/blsct/`: BLS12-381 arithmetic on top of blst, keys and signatures, range proofs, set membership proofs, proof-of-stake proofs and tokens.                                |
| _navio_blsct_wallet_  | BLSCT wallet functionality in `src/blsct/wallet/` (key management, transaction building, wallet RPCs) and the C API in `src/blsct/external_api/`.                                                 |
| _navio_consensus_     | Consensus functionality: transactions, blocks, scripts, merkle roots and context-free transaction checks.                                                                                         |
| _navio_common_        | Higher-level common functionality shared by different executables and libraries: chain parameters, argument and settings handling, key and address encoding, descriptors, signing and policy.     |
| _navio_node_          | P2P and RPC server functionality used by _naviod_: validation, mempool, block storage, indexes, p2p messaging (`src/p2pmsg/`), aggregation and RFQ.                                               |
| _navio_wallet_        | Wallet functionality in `src/wallet/` and `src/mnemonic/`, used by _naviod_ and _navio-wallet_. Built only with `ENABLE_WALLET=ON`.                                                               |
| _navio_cli_           | RPC client functionality used by _navio-cli_, _navio-staker_ and _navio-p2pmsg_.                                                                                                                  |
| _navio_zmq_           | [ZeroMQ](../zmq.md) functionality used by _navio_node_. Built only with `WITH_ZMQ=ON`.                                                                                                            |
| _naviokernel_         | Experimental consensus engine library used by _navio-chainstate_. Built only with `BUILD_KERNEL_LIB=ON`; it compiles its own copy of the sources it needs instead of linking the other libraries. |
| _blsct_               | Standalone `libblsct.a` exposing the BLSCT C API to external consumers. Built only with `BUILD_LIBBLSCT_ONLY=ON`, which disables every other target.                                              |

The vendored subprojects _univalue_, _leveldb_, _minisketch_, _crc32c_,
_secp256k1_ and _blst_ are built as separate targets as well.

## Conventions

- The libraries are internal libraries and have APIs which are completely
  unstable! There are few or no restrictions on backwards compatibility or rules
  about external dependencies. The exception is the C API built into _blsct_ and
  _navio_blsct_wallet_ from `src/blsct/external_api/`, which external consumers
  link against.

- Generally each library should have a corresponding source directory and
  namespace. Source code organization is a work in progress, so it is true that
  some namespaces are applied inconsistently, and if you look at the
  [`add_library(navio_*)`](../../src/CMakeLists.txt) calls you can see that many
  libraries pull in files from outside their source directory. But when working
  with libraries, it is good to follow a consistent pattern like:
  - _navio_node_ code lives in `src/node/` in the `node::` namespace
  - _navio_wallet_ code lives in `src/wallet/` in the `wallet::` namespace
  - _navio_util_ code lives in `src/util/` in the `util::` namespace
  - _navio_consensus_ code lives in `src/consensus/` in the `Consensus::`
    namespace
  - _navio_blsct_core_ and _navio_blsct_wallet_ code lives in `src/blsct/` in
    the `blsct::` namespace

## Dependencies

The internal libraries each target links against, as declared with
`target_link_libraries` in the CMake files:

| Library              | Links against                                                                  |
| -------------------- | ------------------------------------------------------------------------------ |
| _navio_crypto_       | (none)                                                                         |
| _navio_util_         | _navio_clientversion_, _navio_crypto_                                          |
| _navio_blsct_core_   | _navio_crypto_, _navio_util_                                                   |
| _navio_blsct_wallet_ | _navio_blsct_core_, _navio_crypto_, _navio_util_, _navio_node_, _navio_common_ |
| _navio_consensus_    | _navio_blsct_core_, _navio_crypto_, _navio_util_                               |
| _navio_common_       | _navio_blsct_core_, _navio_blsct_wallet_, _navio_consensus_, _navio_util_      |
| _navio_node_         | _navio_common_, _navio_util_, _navio_zmq_ (if built)                           |
| _navio_wallet_       | _navio_blsct_core_, _navio_blsct_wallet_, _navio_common_                       |
| _navio_cli_          | (none)                                                                         |
| _navio_zmq_          | (none)                                                                         |

And the libraries each executable links against:

| Executable   | Links against                                                                |
| ------------ | ---------------------------------------------------------------------------- |
| naviod       | _navio_node_, _navio_wallet_ (if built)                                      |
| navio-cli    | _navio_cli_, _navio_common_, _navio_util_                                    |
| navio-staker | _navio_cli_, _navio_common_, _navio_consensus_, _navio_util_, _navio_crypto_ |
| navio-p2pmsg | _navio_cli_, _navio_common_, _navio_util_                                    |
| navio-tx     | _navio_common_, _navio_util_                                                 |
| navio-util   | _navio_common_, _navio_util_                                                 |
| navio-wallet | _navio_wallet_, _navio_common_, _navio_util_, _navio_node_                   |

- _navio_blsct_wallet_, _navio_common_ and _navio_node_ form a link cycle: the
  BLSCT wallet RPCs call into the p2p messaging, aggregation and RFQ code in
  _navio_node_, which reaches _navio_blsct_wallet_ through _navio_common_.
  `src/CMakeLists.txt` declares the back-edge and sets
  `LINK_INTERFACE_MULTIPLICITY` so single-pass linkers resolve it. Avoid adding
  new edges that widen this cycle.

- The tables show what _linker symbols_ (functions and variables) from each
  library other libraries can call and reference directly, but they are not a
  call graph. For example, _navio_wallet_ does not link against _navio_node_,
  because these libraries are intended to be modular and not depend on each
  other's internal implementation details. But wallet code is still able to call
  node code indirectly through the `interfaces::Chain` abstract class in
  [`interfaces/chain.h`](../../src/interfaces/chain.h) and node code calls
  wallet code through the `interfaces::ChainClient` and
  `interfaces::Chain::Notifications` abstract classes in the same file. In
  general, defining abstract classes in
  [`src/interfaces/`](../../src/interfaces/) can be a convenient way of avoiding
  unwanted direct dependencies or circular dependencies between libraries.

- _navio_crypto_ and _navio_util_ should stay low-level dependencies that any
  library can depend on, and they should not depend on the higher-level
  libraries.

- _navio_common_ is a place for miscellaneous code used by various daemon and
  CLI applications and libraries to live. The boundary between _util_ and
  _common_ is a little fuzzy but historically _util_ has been used for more
  generic, lower-level things like parsing hex, and _common_ has been used for
  higher-level, chain-specific things like parsing base58. If it is ever unclear
  whether it is better to add code to _util_ or _common_, it is probably better
  to add it to _common_ unless it is very generically useful.
