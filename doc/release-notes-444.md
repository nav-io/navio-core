## libblsct C API

`build_tx_out` now takes the memo as a pointer and an explicit length. This is
a breaking signature change: every libblsct consumer and language binding must
pass the new `memo_len` argument and be rebuilt against the new header.

```c
BlsctRetVal* build_tx_out(
    const BlsctSubAddr* blsct_dest,
    uint64_t amount,
    const char* memo,
    size_t memo_len,
    const BlsctTokenId* blsct_token_id,
    TxOutputType output_type,
    uint64_t min_stake,
    bool subtract_fee_from_amount,
    const BlsctScalar* blsct_blinding_key
);
```

- `memo` no longer needs a NUL terminator and is never read past `memo_len`.
- `memo` may be NULL only when `memo_len` is 0; NULL with a non-zero length
  returns `BLSCT_FAILURE`.
- A memo longer than `MAX_MEMO_LEN` returns `BLSCT_MEMO_TOO_LONG`, as before.
- A memo containing a NUL byte now returns `BLSCT_FAILURE` instead of being
  silently truncated at the first NUL.
