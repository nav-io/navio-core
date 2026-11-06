## libblsct C API

`build_range_proof`, `sign_message` and `verify_msg_sig` now take the message as
a pointer and an explicit length. This is a breaking signature change: every
libblsct consumer and language binding must pass the new `msg_len` argument and
be rebuilt against the new header.

```c
BlsctRetVal* build_range_proof(
    const void* vp_uint64_vec,
    const BlsctPoint* blsct_nonce,
    const char* blsct_msg,
    size_t msg_len,
    const BlsctTokenId* blsct_token_id
);

const BlsctSignature* sign_message(
    const BlsctScalar* blsct_priv_key,
    const char* blsct_msg,
    size_t msg_len
);

bool verify_msg_sig(
    const BlsctPubKey* blsct_pub_key,
    const char* blsct_msg,
    size_t msg_len,
    const BlsctSignature* blsct_signature
);
```

- The message no longer needs a NUL terminator and is never read past `msg_len`.
- It may be NULL only when `msg_len` is 0. NULL with a non-zero length makes
  `build_range_proof` return `BLSCT_FAILURE`, `sign_message` return NULL and
  `verify_msg_sig` return false.
- `sign_message` and `verify_msg_sig` sign and check all `msg_len` bytes,
  including NUL bytes. Before, a message was cut at its first NUL byte, so a
  signature over `"ab\0cd"` also verified for `"ab"`.
- `build_range_proof` returns `BLSCT_FAILURE` for a message containing a NUL
  byte, since amount recovery returns the message as a C string and would cut it
  there.
