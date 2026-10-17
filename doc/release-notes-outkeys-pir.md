P2P and network changes
-----------------------

- A new optional, experimental `-peerpir` setting (default off, requires
  `-peeroutkeys`) lets light wallets fetch the full data of outputs they found
  with `getoutkeys` without revealing which outputs they fetch. It is
  advertised with the new service bit `NODE_OUTKEYS_PIR` (bit 29, one of the
  bits reserved for experiments). This is a prototype of single-server
  private information retrieval after SimplePIR (Henzinger et al., USENIX
  Security 2023) with the paper's LWE parameters (n = 1024, q = 2^32, discrete
  Gaussian error with standard deviation 6.4, plaintext modulus 2^8); it has
  not been audited.

  The outputs `getoutkeys` reports (every output carrying BLSCT keys, in chain
  order) are split by height into epochs of 10080 blocks (`-pirepochblocks`,
  a debug option). Each epoch is a database of 1152-byte records, one per
  output: a kind byte (1: output, 2: output too large for a record), a
  little-endian `uint16` length and the serialized `CTxOut`, zero padded. A
  wallet checks a retrieved output against its hash from `outkeys`.

  - `getpirhint` (`uint32 epoch`) requests an epoch's hint. It is answered by
    one `pirhint` per slot (one, unless the epoch holds more than 2^19
    outputs), each carrying `uint32 epoch`, `uint32 epoch_blocks`,
    `uint32 start_height`, `uint256 anchor_hash` (the last block the epoch
    data covers), the number of outputs of each block from `start_height` up
    to the anchor (`vector<uint32>`), the public matrix seed (`uint256`, which
    must equal `SHA256d(ser_string("navio/simplepir/A/v1") || genesis hash ||
    uint32 epoch)`), `uint32 record_bytes`, `uint32 num_records`,
    `uint32 records_per_col`, `uint32 slot` and the slot's hint rows
    (`vector<uint32>`, 1152 x 1024 words, about 4.7 MB).
  - `pirquery` (`uint32 epoch`, `uint256 anchor_hash`, `uint32 num_records`,
    `vector<uint32> query`) retrieves one record from the epoch as of the
    anchor block. The node answers with `pirreply` (`uint32 epoch`,
    `uint256 anchor_hash`, `vector<uint32> answer`), or with an empty answer
    if the anchor is no longer in the active chain; the wallet then fetches
    the hint again. A query against an older anchor of the same epoch is
    still answered as long as that anchor is in the active chain.

  A request to a node that does not advertise `NODE_OUTKEYS_PIR`, a hint
  request for an epoch above the tip, and a query with an unknown anchor, an
  anchor outside its epoch, a record count that does not match the anchor or
  a query of the wrong length disconnect the peer. Each query costs the node a
  scan of the epoch database and each hint about 4.7 MB of upload, so each
  peer has a work budget (1 GiB, refilled at 128 MiB/s); a peer that exceeds
  it is disconnected. Building or extending an epoch's hint is charged to a
  budget shared by all peers, and while that is exhausted requests are
  ignored.
