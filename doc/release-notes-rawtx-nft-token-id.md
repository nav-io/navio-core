## Updated RPCs

- `createblsctrawtransaction` now accepts an NFT in an output's `token_id`,
  written as the collection's 64-hex token id followed by `#<subid>`, the form
  the RFQ and order RPCs already take. Before, `token_id` had to be exactly 64
  hex characters, so a raw transaction could not send an NFT. A malformed
  `token_id` is still refused with `RPC_INVALID_PARAMETER`, now with the same
  message those RPCs give.
