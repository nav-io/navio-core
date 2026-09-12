// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_TOKENS_RPC_H
#define NAVIO_BLSCT_TOKENS_RPC_H

#include <rpc/util.h>
#include <span.h>

#include <vector>

class CRPCCommand;
class UniValue;
namespace blsct {
class TokenEntry;
} // namespace blsct

//! Serialize a token entry's chain-wide fields (publicKey, type, metadata,
//! supply/minted NFTs) into `obj`. Shared by the node token RPCs and the
//! wallet's ismine-aware variants.
void TokenToUniValue(UniValue& obj, const blsct::TokenEntry& token);

//! The RPCResult schema for a serialized token (tokenId + TokenToUniValue's
//! fields); shared so the wallet's ismine-aware variants stay in sync.
extern std::vector<RPCResult> tokenInfoResult;

namespace blsct {
} // namespace blsct

#endif // NAVIO_BLSCT_TOKENS_RPC_H