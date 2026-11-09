// Copyright (c) 2026-present The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMMON_SIGNET_H
#define BITCOIN_COMMON_SIGNET_H

#include <primitives/block.h>
#include <script/script.h>

#include <optional>
#include <string>

struct FlatSigningProvider;
class SigningProvider;

/**
 * Decode a private key given as 32 bytes of hex into a provider that signs
 * signet blocks with it (compressed public key), or nullopt if the hex is
 * not a valid secp256k1 secret.
 */
std::optional<FlatSigningProvider> SignetKeyProvider(const std::string& key_hex);

/**
 * Sign a block for a signet whose challenge is `challenge`, using the keys
 * `provider` holds, and store the solution in the coinbase witness
 * commitment (BIP325).
 *
 * Everything the signature commits to must be final first: nVersion,
 * hashPrevBlock, nTime and every transaction. nBits, nNonce and a
 * proof-of-stake proof are not covered, so they may still be set afterwards.
 * On success the block's hashMerkleRoot is updated.
 *
 * Fails, leaving the block unchanged and setting `error`, when the block
 * has no witness commitment, already carries a solution, or the keys cannot
 * satisfy the challenge.
 */
bool SignSignetBlock(CBlock& block, const CScript& challenge, const SigningProvider& provider, std::string& error);

#endif // BITCOIN_COMMON_SIGNET_H
