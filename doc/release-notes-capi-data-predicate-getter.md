## libblsct C API

New `get_data_predicate_data` returns the payload of a DATA predicate, without
the operation byte and length prefix that frame it in the serialized predicate
(for example as returned by `get_ctx_out_vector_predicate`).

```c
BlsctRetVal* get_data_predicate_data(
    const BlsctVectorPredicate* blsct_vector_predicate,
    size_t obj_size
);
```

- On success, `result` is `BLSCT_SUCCESS`, `value` points to a copy of the
  payload and `value_size` is its length. An empty payload still returns a
  non-NULL `value`, with `value_size` 0.
- It returns `BLSCT_FAILURE` when `blsct_vector_predicate` is NULL, or when the
  bytes do not start with a complete DATA predicate (another predicate type, an
  unknown operation byte, or a length prefix that promises more bytes than
  follow).
- It returns `BLSCT_MEM_ALLOC_FAILED` if the copy of the payload cannot be
  allocated.
- Bytes after the payload are ignored, as core's predicate parser ignores them.
- Free `value` with `free_obj` and the returned `BlsctRetVal` with `free`, as
  for the other getters.
