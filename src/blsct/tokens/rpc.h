// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_TOKENS_RPC_H
#define NAVIO_BLSCT_TOKENS_RPC_H

#include <span.h>

class CRPCCommand;

namespace blsct {
Span<const CRPCCommand> GetTokenRPCCommands();
} // namespace blsct

#endif // NAVIO_BLSCT_TOKENS_RPC_H