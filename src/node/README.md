# src/node/

The [`src/node/`](./) directory contains code that needs to access node state
(state in `CChain`, `CBlockIndex`, `CCoinsView`, `CTxMemPool`, and similar
classes).

Code in [`src/node/`](./) is meant to be segregated from code in
[`src/wallet/`](../wallet/), to ensure wallet code changes don't interfere with
node operation, to allow wallet code to run in a separate process, and to
perhaps eventually allow wallet code to be maintained in a separate source
repository.

As a rule of thumb, code in one of the [`src/node/`](./) or
[`src/wallet/`](../wallet/) directories should avoid calling code in the other
directory directly, and only invoke it indirectly through the more limited
[`src/interfaces/`](../interfaces/) classes.

This directory is at the moment sparsely populated. Eventually more substantial
files like [`src/validation.cpp`](../validation.cpp) and
[`src/txmempool.cpp`](../txmempool.cpp) might be moved there.
