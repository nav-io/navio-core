// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/bridge/messages.h>

#include <crypto/sha256.h>

#include <cassert>

namespace nbp {

namespace {

void AppendU64BE(std::vector<unsigned char>& out, uint64_t v)
{
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<unsigned char>((v >> (8 * i)) & 0xff));
    }
}

void AppendU32BE(std::vector<unsigned char>& out, uint32_t v)
{
    for (int i = 3; i >= 0; --i) {
        out.push_back(static_cast<unsigned char>((v >> (8 * i)) & 0xff));
    }
}

void AppendHash(std::vector<unsigned char>& out, const uint256& h)
{
    out.insert(out.end(), h.begin(), h.end());
}

} // namespace

std::vector<unsigned char> CheckpointBytes(
    const uint256& chain_id,
    uint64_t epoch,
    const uint256& block_hash,
    uint64_t height,
    const uint256& committee_root,
    const uint256& pegout_root)
{
    std::vector<unsigned char> out;
    out.reserve(144);
    AppendHash(out, chain_id);
    AppendU64BE(out, epoch);
    AppendHash(out, block_hash);
    AppendU64BE(out, height);
    AppendHash(out, committee_root);
    AppendHash(out, pegout_root);
    return out;
}

std::vector<unsigned char> AttestationBytes(
    const uint256& chain_id,
    uint64_t eth_chain_id,
    const uint256& deposit_id,
    const std::vector<unsigned char>& token,
    uint64_t amount,
    const uint256& claim_commit)
{
    assert(token.size() == 20);
    std::vector<unsigned char> out;
    out.reserve(132);
    AppendHash(out, chain_id);
    AppendU64BE(out, eth_chain_id);
    AppendHash(out, deposit_id);
    out.insert(out.end(), token.begin(), token.end());
    AppendU64BE(out, amount);
    AppendHash(out, claim_commit);
    return out;
}

std::vector<unsigned char> ResolutionBytes(
    const uint256& chain_id,
    const uint256& challenge_txid,
    const uint256& deposit_id,
    uint8_t verdict)
{
    std::vector<unsigned char> out;
    out.reserve(97);
    AppendHash(out, chain_id);
    AppendHash(out, challenge_txid);
    AppendHash(out, deposit_id);
    out.push_back(verdict);
    return out;
}

std::vector<unsigned char> PopBytes(const std::vector<unsigned char>& pk_g)
{
    return pk_g;
}

uint256 BridgeTokenId(uint64_t eth_chain_id, const std::vector<unsigned char>& token)
{
    assert(token.size() == 20);
    static const std::string prefix{"nbp/v1"};
    std::vector<unsigned char> preimage;
    preimage.reserve(prefix.size() + 8 + 20);
    preimage.insert(preimage.end(), prefix.begin(), prefix.end());
    AppendU64BE(preimage, eth_chain_id);
    preimage.insert(preimage.end(), token.begin(), token.end());
    uint256 out;
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(out.begin());
    return out;
}

std::vector<unsigned char> PegOutLeaf(
    const uint256& txid,
    const uint256& token_id,
    uint64_t amount,
    const std::vector<unsigned char>& eth_recipient,
    uint32_t out_index)
{
    assert(eth_recipient.size() == 20);
    std::vector<unsigned char> out;
    out.reserve(32 + 32 + 8 + 20 + 4);
    AppendHash(out, txid);
    AppendHash(out, token_id);
    AppendU64BE(out, amount);
    out.insert(out.end(), eth_recipient.begin(), eth_recipient.end());
    AppendU32BE(out, out_index);
    return out;
}

std::vector<unsigned char> CommitteeLeaf(const std::vector<unsigned char>& pk_g, uint64_t bond)
{
    assert(pk_g.size() == 48);
    std::vector<unsigned char> out;
    out.reserve(48 + 8);
    out.insert(out.end(), pk_g.begin(), pk_g.end());
    AppendU64BE(out, bond);
    return out;
}

} // namespace nbp
