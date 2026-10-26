// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_TOKENS_PREDICATE_EXEC_H
#define NAVIO_BLSCT_TOKENS_PREDICATE_EXEC_H

#include <blsct/tokens/predicate_parser.h>
#include <coins.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <optional>

namespace blsct {
bool ExecutePredicate(const ParsedPredicate& predicate, CCoinsViewCache& view, const bool& fDisconnect = false);
bool ExecutePredicate(const VectorPredicate& vch, CCoinsViewCache& view, const bool& fDisconnect = false);

/** Whether a predicate reads or writes token state (CREATE_TOKEN, MINT,
 *  NFT_MINT). PAY_FEE and DATA always succeed and touch no state. Only the
 *  operation byte is inspected, so this is cheap enough to call on every
 *  output of every mempool transaction. */
bool IsTokenStatePredicate(const VectorPredicate& vch);

/** The token-set key (hash of the token public key) a token-state predicate
 *  touches, or nullopt for a stateless or unparsable predicate. */
std::optional<uint256> GetPredicateTokenKey(const VectorPredicate& vch);

/** Apply the token-state predicates of a transaction's outputs to view in
 *  output order, as ConnectBlock does. PAY_FEE and DATA are skipped.
 *  Returns false if any predicate fails or does not parse; view may then hold
 *  the effects of earlier outputs, so callers that need all-or-nothing pass a
 *  child CCoinsViewCache and flush it only on success. */
bool ApplyTokenPredicates(const CTransaction& tx, CCoinsViewCache& view);
} // namespace blsct

#endif // NAVIO_BLSCT_TOKENS_PREDICATE_EXEC_H