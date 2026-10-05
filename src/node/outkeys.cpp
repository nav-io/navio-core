// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/outkeys.h>

#include <primitives/block.h>

namespace node {

BlockOutKeys BuildBlockOutKeys(const CBlock& block)
{
    BlockOutKeys ret;
    ret.block_hash = block.GetHash();
    for (const auto& tx : block.vtx) {
        for (const CTxOut& out : tx->vout) {
            if (!out.HasBLSCTKeys()) continue;
            OutKeysEntry& entry{ret.outputs.emplace_back()};
            entry.out_id = out.GetHash();
            entry.blinding_key = out.blsctData.blindingKey;
            entry.spending_key = out.blsctData.spendingKey;
            entry.view_tag = out.blsctData.viewTag;
            if (out.blsctData.spendingKey.IsZero()) entry.script = out.scriptPubKey;
        }
        if (tx->IsCoinBase()) continue;
        for (const CTxIn& in : tx->vin) {
            ret.spent.push_back(in.prevout.hash.ToUint256());
        }
    }
    return ret;
}

} // namespace node
