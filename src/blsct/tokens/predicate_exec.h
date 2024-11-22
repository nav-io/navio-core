// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_TOKENS_PREDICATE_EXEC_H
#define NAVIO_BLSCT_TOKENS_PREDICATE_EXEC_H

#include <blsct/tokens/predicate_parser.h>
#include <coins.h>

namespace blsct {
bool ExecutePredicate(const ParsedPredicate& predicate, CCoinsViewCache& view, const bool& fDisconnect = false);
bool ExecutePredicate(const VectorPredicate& vch, CCoinsViewCache& view, const bool& fDisconnect = false);
} // namespace blsct

#endif // NAVIO_BLSCT_TOKENS_PREDICATE_EXEC_H