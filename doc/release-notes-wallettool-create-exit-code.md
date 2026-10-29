## Wallet tool

- `navio-wallet create` now exits with a non-zero status when the wallet cannot
  be created, for example because a wallet of that name already exists or its
  database cannot be opened. It used to print the error and still exit 0, so
  scripts checking the exit code treated the failure as success.
