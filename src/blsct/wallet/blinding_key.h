// Copyright (c) 2026 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Recoverable output blinding keys.
//
// Every BLSCT output is built with a secret blinding scalar k. The wallet used
// to draw it from Scalar::Rand() and throw it away, which left the sender of a
// confidential output with no way to prove, after the fact, that they created
// it -- the only thing on chain that is bound to k is a public point, and
// nobody could produce a signature under it any more.
//
// This derives k deterministically from the wallet's HD seed instead, so a
// wallet restored from nothing but its mnemonic can recompute the scalar for
// any output it created and sign an arbitrary message with it.
//
// The derivation is NORMATIVE and shared with navio-sdk (see the bridge's
// docs/BLINDING-KEY-RECOVERY.md). Its byte layout must not change: a
// divergence between the two implementations would not fail loudly, it would
// surface years later as permanently unrecoverable outputs. The normative test
// vector in blinding_key_tests.cpp is what pins it.

#ifndef NAVIO_BLSCT_WALLET_BLINDING_KEY_H
#define NAVIO_BLSCT_WALLET_BLINDING_KEY_H

#include <blsct/arith/blst/blst.h>
#include <primitives/transaction.h>
#include <span.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace blsct {

//! ASCII domain separator. Exactly 23 bytes, hashed WITHOUT a NUL terminator.
inline constexpr std::string_view BLINDING_KEY_DOMAIN{"navio-blsct-blinding/v1"};

//! ASCII domain separator for authorship signatures (`signblsctoutput`).
//! Exactly 26 bytes, hashed WITHOUT a NUL terminator.
inline constexpr std::string_view OUTPUT_AUTH_DOMAIN{"navio-blsct-output-auth/v1"};

//! The HD seed scalar is hashed as 32 bytes, big-endian, zero-padded.
inline constexpr size_t BLINDING_KEY_SEED_SIZE{32};

//! Total hashed length: 23 (domain) + 32 (seed) + 32 (outid) + 4 (ordinal)
//! + 4 (generation).
inline constexpr size_t BLINDING_KEY_MATERIAL_SIZE{
    BLINDING_KEY_DOMAIN.size() + BLINDING_KEY_SEED_SIZE + 32 + 4 + 4};

//! How many generations RecoverBlindingKey tries per (anchor, ordinal).
//!
//! The generation exists because the derivation is otherwise a pure function
//! of (seed, anchor, ordinal), and a wallet that rebuilds a transaction from
//! the same inputs -- abandon or evict and resend, with coin selection being
//! deterministic -- would derive the SAME k for a DIFFERENT amount. k seeds
//! `nonce = vk * k`, from which the range proof takes gamma and every blinding
//! scalar, so two such published proofs would reuse the prover's entire
//! randomness and leak the committed values. The building wallet therefore
//! keeps a per-anchor counter and bumps it on every build that reuses an
//! anchor (KeyMan::ReserveBlindingGeneration).
//!
//! Recovery cannot read that counter after a seed-only restore, so it searches
//! instead. 32 bounds how many times one wallet can sensibly rebuild on one
//! input set; beyond that the output is not recoverable, which is a lost fast
//! path and never a wrong key, since every candidate is checked against the
//! output's public point.
//!
//! LIMIT, stated plainly: this covers one wallet rebuilding. It does NOT cover
//! two wallets restored from the same seed, which share no counter, both start
//! at generation 0 and will derive the same k from the same inputs. Do not
//! run two wallets on one seed and spend from both.
inline constexpr uint32_t MAX_GENERATION_SEARCH{32};

//! How many sender-assigned output ordinals RecoverBlindingKey tries per
//! candidate anchor input.
//!
//! The ordinal a derivation is keyed on is the one the SENDER assigned while
//! building its transaction, which is not the index the output ends up at:
//! Navio merges every non-coinbase transaction of a block into one
//! (validation.cpp's vtx<=2 rule), so positions shift. Recovery therefore does
//! not trust the on-chain index at all -- it tries every ordinal and checks
//! each candidate against the output's public point, which makes a match a
//! proof rather than an assumption.
//!
//! 16 is ample: it bounds the number of outputs one wallet-built transaction
//! pays (recipient + subtract-fee recipient + one change output per token),
//! and the whole search is a handful of scalar multiplications.
inline constexpr uint32_t MAX_OUTPUT_SEARCH{16};

//! The deterministic blinding scalar for the `ordinal`-th output of a
//! transaction anchored on the outpoint `outid`, on build `generation`.
//!
//!   material = "navio-blsct-blinding/v1"          // 23 bytes ASCII, no NUL
//!            || seed                              // 32 bytes, big-endian, zero-padded
//!            || outid                             // 32 bytes, INTERNAL byte order
//!            || ordinal                           // uint32, big-endian
//!            || generation                        // uint32, big-endian
//!   k        = sha256(material) read big-endian and reduced mod r
//!
//! `generation` distinguishes repeated builds over the same input set; see
//! MAX_GENERATION_SEARCH for why it has to exist.
//!
//! `outid` is `tx.vin[0].prevout.hash`. Note it is NOT a txid: Navio's
//! COutPoint is a bare 32-byte hash of a serialized CTxOut (the class comment
//! in primitives/transaction.h still describes Bitcoin's txid:n form and is
//! stale). There is no output index to hash, and none is invented here.
//!
//! Throws std::runtime_error on a seed of the wrong length, and on the
//! ~2^-255 event that the reduction lands on zero -- a zero scalar would make
//! the output anyone-can-spend, so it fails loudly rather than carrying a
//! retry path that can never be exercised.
BlstScalar DeriveBlindingKey(Span<const unsigned char> seed, const Outid& outid, uint32_t ordinal,
                             uint32_t generation);

//! The digest `signblsctoutput` signs for `message`:
//!
//!   digest = sha256("navio-blsct-output-auth/v1" || message)
//!
//! Signing the caller's bytes directly would make the RPC a signing oracle for
//! a CONSENSUS key. Every BLSCT output commits to a signature under its own
//! `ephemeralKey` -- the very point k*G this signs with -- over the 32-byte
//! `out_hash` (verification.cpp aggregates the pair). A caller who could pick
//! the signed bytes could therefore ask for a valid output signature by
//! handing over a 32-byte "message" that is really an out_hash.
//!
//! Hashing with a domain prefix closes that: the signed value is always
//! sha256 output, so producing a signature over a CHOSEN out_hash needs a
//! sha256 preimage. A bare prefix would not be enough on its own -- it only
//! makes the collision improbable rather than preimage-hard -- and a
//! fixed-length digest also keeps the signed value independent of the
//! message's length.
//!
//! NORMATIVE and shared with navio-sdk: the byte layout must not change.
uint256 OutputAuthDigest(std::string_view message);

//! The canonical anchor of a transaction: the lexicographically smallest
//! outid among `outpoints`, comparing the 32 bytes in INTERNAL order (which
//! is what uint256's memcmp-based ordering does). std::nullopt for an empty
//! set.
//!
//! Callers pass the outpoints of the inputs the SENDER ITSELF contributed --
//! at build time the ones coin selection chose, at recovery time the ones the
//! wallet recognises as spending its own outputs.
//!
//! Canonical rather than positional because no position survives: BuildTx
//! shuffles vin before broadcast to hide coin-selection order, and block
//! aggregation then splices other senders' inputs into the same vin, so the
//! input at index 0 may belong to a stranger. A canonical choice over the
//! sender's own input *set* is invariant under both.
std::optional<Outid> CanonicalAnchor(const std::vector<COutPoint>& outpoints);

//! Recover the blinding scalar of an output whose public blinding point is
//! `publicBlindingKey`, given the inputs of the transaction that contains it.
//! Returns std::nullopt when no candidate matches, i.e. the output was not
//! created by this seed (or predates this feature).
//!
//! `publicBlindingKey` is the output's `blsctData.ephemeralKey`, which is the
//! point k*G -- see RecoverOutputBlindingKey() below, and the note there about
//! blsctData.blindingKey being a different point entirely.
//!
//! `canonicalAnchor`, when known, is tried first and normally hits on the
//! first ordinal, which costs 16 scalar multiplications. The search then falls
//! back to trying EVERY input of `vin` as the anchor. That fallback is
//! deliberate and must stay: the check against the public point is
//! self-verifying, so a wrong anchor can only cost time, never yield a false
//! key -- whereas a purely canonical scheme fails silently whenever the
//! wallet's notion of "my own inputs" differs between building and recovering,
//! a partial rescan being the obvious way that happens.
//!
//! Worst-case cost is |vin| * MAX_OUTPUT_SEARCH * MAX_GENERATION_SEARCH scalar
//! multiplications, and only paid on the explicit recovery path. The common
//! case is far cheaper: the canonical anchor and generation 0 hit first, so an
//! output built by a wallet that never rebuilt costs a single multiplication.
std::optional<BlstScalar> RecoverBlindingKey(Span<const unsigned char> seed,
                                             const std::vector<CTxIn>& vin,
                                             const BlstG1Point& publicBlindingKey,
                                             const std::optional<Outid>& canonicalAnchor = std::nullopt);

} // namespace blsct

#endif // NAVIO_BLSCT_WALLET_BLINDING_KEY_H
