// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_BRIDGE_CHECKPOINT_DATA_H
#define NAVIO_BLSCT_BRIDGE_CHECKPOINT_DATA_H

#include <blsct/signature.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

namespace nbp {

//! Aggregate committee checkpoint embedded in a block (DESIGN.md §5.2).
//! Carried like posProof: a CBlock-level field gated by a version bit,
//! outside the header hash; its integrity is enforced by consensus
//! validation in ConnectBlock, never required for block validity.
struct CheckpointData {
    uint64_t epoch{0};
    uint256 hashT;   // epoch-boundary block this checkpoint finalizes
    uint64_t heightT{0};
    uint256 committeeRoot;
    uint256 pegOutRoot;
    std::vector<unsigned char> bitfield; // signer set over the committee (canonical order)
    blsct::Signature aggSig;             // aggregate over DST_CKPT ‖ cp_bytes (augmentation scheme)

    SERIALIZE_METHODS(CheckpointData, obj)
    {
        READWRITE(obj.epoch, obj.hashT, obj.heightT, obj.committeeRoot,
                  obj.pegOutRoot, obj.bitfield, obj.aggSig);
    }
};

} // namespace nbp

#endif // NAVIO_BLSCT_BRIDGE_CHECKPOINT_DATA_H
