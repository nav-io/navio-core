// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_OUTKEYS_H
#define BITCOIN_NODE_OUTKEYS_H

#include <blsct/arith/blst/blst_g1point.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

class CBlock;

namespace node {

/** Maximum number of blocks that may be requested with one getoutkeys. */
static constexpr uint32_t MAX_GETOUTKEYS_SIZE{1000};

/**
 * Default budget, in bytes of outkeys payload, for the reply to one
 * getoutkeys. The reply stops before the first block whose outkeys would take
 * it over the budget; the requester continues from the height after the last
 * block it received. The first block is always sent, so every request makes
 * progress. Overridable for testing with -outkeysmaxbytes.
 */
static constexpr uint64_t DEFAULT_OUTKEYS_MAX_REPLY_BYTES{4'000'000};

/**
 * The fields a BLSCT wallet needs to decide whether an output is its own:
 * the view tag and blinding key give the expected nonce and a cheap prefilter,
 * the spending key (or, when the output carries none, its scriptPubKey) gives
 * the subaddress hash id. The range proof, which dominates an output's size,
 * is only needed to recover the amount of an output already known to be ours,
 * so it is left out.
 */
struct OutKeysEntry {
    uint256 out_id;
    BlstG1Point blinding_key;
    BlstG1Point spending_key;
    uint16_t view_tag{0};
    //! Empty unless spending_key is the zero point: the wallet then reads the
    //! spending key(s) from the script.
    CScript script;

    SERIALIZE_METHODS(OutKeysEntry, obj)
    {
        READWRITE(obj.out_id, obj.blinding_key, obj.spending_key, obj.view_tag, obj.script);
    }
};

/** Payload of an outkeys message: one block's output keys and spends. */
struct BlockOutKeys {
    uint256 block_hash;
    //! Every output carrying BLSCT keys, in block order.
    std::vector<OutKeysEntry> outputs;
    //! Every output hash spent by the block's inputs, in block order.
    std::vector<uint256> spent;

    SERIALIZE_METHODS(BlockOutKeys, obj)
    {
        READWRITE(obj.block_hash, obj.outputs, obj.spent);
    }
};

/** Extract the outkeys payload for a block. */
BlockOutKeys BuildBlockOutKeys(const CBlock& block);

} // namespace node

#endif // BITCOIN_NODE_OUTKEYS_H
