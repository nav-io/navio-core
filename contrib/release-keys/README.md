Release signing key
===================

[`releases.asc`](releases.asc) is the public key that signs Navio Core release
binaries:

```
Nav.io Releases <releases@nav.io>
ed25519, created 2026-04-22, expires 2029-04-21
Fingerprint: 5E54 2D3B DB5F 4305 7623  30B3 7A17 AA08 3868 0153
```

The same key is published at https://nav.io/releases.asc. Check the
fingerprint against at least one source other than the page you downloaded the
binaries from.

What it signs
-------------

Each GitHub release carries:

- `SHA256SUMS`, the SHA-256 hash of every release file (Linux, macOS and
  Windows), and `SHA256SUMS.asc`, a detached signature over it with this key.
- A detached `.asc` signature next to each Linux tarball.

Verifying a download
--------------------

```sh
gpg --import contrib/release-keys/releases.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --ignore-missing --check SHA256SUMS
```

`gpg --verify` must report `Good signature from "Nav.io Releases
<releases@nav.io>"` made with key `5E542D3BDB5F4305762330B37A17AA0838680153`,
and `sha256sum` must report `OK` for the file you downloaded. On macOS use
`shasum -a 256 --ignore-missing --check SHA256SUMS`.

gpg also warns that the key "is not certified with a trusted signature". That
only means you have not signed the key yourself; the fingerprint check above
is what ties it to the project.
