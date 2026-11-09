## Removed functionality

- Signet support has been removed. Navio has no signet network: the built-in
  default was Bitcoin's signet (its challenge, genesis block and assumevalid
  values) with BLSCT disabled. This removes `-chain=signet` and the `-signet`,
  `-signetchallenge` and `-signetseednode` options, which are now invalid
  parameters; a `[signet]` section in the configuration file is reported as an
  unrecognized section.
