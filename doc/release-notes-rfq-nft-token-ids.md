## Updated RPCs

- `setswapintent`, `requestquote`, `sendquote`, `sendorder` and `broadcastorder`
  now accept an NFT as a token argument, written the way `listorders` prints it:
  the 64-hex token id followed by `#<subid>`. Before, every token argument had
  to be exactly 64 hex characters, so no RPC could name an NFT on the RFQ path.
  The subid must be plain decimal with no sign, leading zeros or `0x` prefix;
  NAV (empty or all-zero) cannot carry one, and `#18446744073709551615` (the
  fungible marker) is rejected rather than read as the bare token. The error now
  names the argument (e.g. `buy_token must be a 64-hex token id, ...`) instead
  of the generic `token must be of length 64`.

- `listswapintents` (`token_in`, `token_out`) and `listpendingquoterequests`
  (`buy_token`, `sell_token`) now print the `#<subid>` suffix for an NFT,
  matching `listorders`. Before, the suffix was dropped, so an NFT intent or
  request listed as its fungible token. Output for fungible tokens and NAV is
  unchanged.
