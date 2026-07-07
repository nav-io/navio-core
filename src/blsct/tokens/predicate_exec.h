// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_TOKENS_PREDICATE_EXEC_H
#define NAVIO_BLSCT_TOKENS_PREDICATE_EXEC_H

#include <blsct/bridge/logic.h>
#include <blsct/tokens/predicate_parser.h>
#include <coins.h>

namespace blsct {
//! `nbpCtx` is required for NBP bridge predicates (they need the consensus
//! params, height and carrying output); token predicates ignore it. The
//! connect path (VerifyTxCoreImpl) executes bridge predicates directly via
//! nbp::ExecuteNbpPredicate to collect balance terms; these overloads carry
//! the context so the DisconnectBlock path can invert them.
bool ExecutePredicate(const ParsedPredicate& predicate, CCoinsViewCache& view, const bool& fDisconnect = false, const nbp::PredicateContext* nbpCtx = nullptr);
bool ExecutePredicate(const VectorPredicate& vch, CCoinsViewCache& view, const bool& fDisconnect = false, const nbp::PredicateContext* nbpCtx = nullptr);
} // namespace blsct

#endif // NAVIO_BLSCT_TOKENS_PREDICATE_EXEC_H
