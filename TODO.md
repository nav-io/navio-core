# TODO

## 1. ~~Fix `GenRandomSeed` bug~~

`MclScalar::Rand()` could produce <32 bytes when serialized, which crashed `derive_master_SK` (requires `seed.size() >= 32`). Fixed by using `GetStrongRandBytes(32)` directly instead of routing through `MclScalar::Rand()`.

**Location:** `src/blsct/wallet/helpers.cpp:81-86`

## 2. ~~Deduplicate encryption logic in `SetupGeneration`~~

Extracted `SetupMnemonicFromEntropy` as a private helper in `src/blsct/wallet/keyman.h` and `src/blsct/wallet/keyman.cpp`. Both the `IMPORT_MNEMONIC` and fresh-generation branches now delegate to it.

## 3. Add BIP-39 passphrase support

The optional "password" parameter for BIP-39 seed derivation is missing. This limits interoperability with other wallets that use BIP-39 passphrases for additional security.
