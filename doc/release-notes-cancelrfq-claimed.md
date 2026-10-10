RPC changes
-----------

- `cancelrfq` now fails with an error while one of the RFQ's quotes is being
  accepted. Before, it returned `true` and dropped the request even though the
  in-flight accept could still broadcast the swap. Retry once the accept has
  finished: a successful accept drops the request itself, and a failed one makes
  it cancellable again.
