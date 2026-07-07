// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_BRIDGE_RPC_H
#define NAVIO_BLSCT_BRIDGE_RPC_H

#include <blsct/bridge/checkpoint_data.h>

#include <optional>

class CRPCTable;

void RegisterNbpRPCCommands(CRPCTable& t);

namespace nbp {

//! Pending checkpoint queued via submitnbpcheckpoint; embedded into the
//! next assembled block (dropped automatically once its epoch has a
//! checkpoint on chain, or if it fails block validity).
void SetPendingCheckpoint(const CheckpointData& cp);
std::optional<CheckpointData> GetPendingCheckpoint();
void ClearPendingCheckpoint();

} // namespace nbp

#endif // NAVIO_BLSCT_BRIDGE_RPC_H
