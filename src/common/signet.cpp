// Copyright (c) 2026-present The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/signet.h>

#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <key.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <signet.h>
#include <span.h>
#include <streams.h>
#include <support/cleanse.h>
#include <util/strencodings.h>

#include <optional>
#include <vector>

std::optional<FlatSigningProvider> SignetKeyProvider(const std::string& key_hex)
{
    std::optional<std::vector<uint8_t>> secret{TryParseHex<uint8_t>(key_hex)};
    if (!secret || secret->size() != 32) return std::nullopt;
    CKey key;
    key.Set(secret->begin(), secret->end(), /*fCompressedIn=*/true);
    memory_cleanse(secret->data(), secret->size());
    if (!key.IsValid()) return std::nullopt;
    FlatSigningProvider provider;
    const CPubKey pubkey{key.GetPubKey()};
    provider.keys.emplace(pubkey.GetID(), key);
    provider.pubkeys.emplace(pubkey.GetID(), pubkey);
    return provider;
}

bool SignSignetBlock(CBlock& block, const CScript& challenge, const SigningProvider& provider, std::string& error)
{
    if (block.vtx.empty()) {
        error = "block has no coinbase transaction";
        return false;
    }
    const int cidx = GetWitnessCommitmentIndex(block);
    if (cidx == NO_WITNESS_COMMITMENT) {
        error = "block has no witness commitment to carry the signet solution";
        return false;
    }
    const CScript commitment = block.vtx[0]->vout[cidx].scriptPubKey;
    opcodetype opcode;
    std::vector<uint8_t> pushdata;
    for (CScript::const_iterator pc = commitment.begin(); commitment.GetOp(pc, opcode, pushdata);) {
        if (pushdata.size() >= sizeof(SIGNET_HEADER) && Span{pushdata}.first(sizeof(SIGNET_HEADER)) == Span{SIGNET_HEADER}) {
            error = "block already carries a signet solution";
            return false;
        }
    }

    const std::vector<uint8_t> header(std::begin(SIGNET_HEADER), std::end(SIGNET_HEADER));

    // The signature commits to the block with a bare header push in place of
    // the solution: that is what CheckSignetBlockSolution reconstructs after
    // stripping the solution from the header push.
    CBlock to_sign_block{block};
    CMutableTransaction cb{*block.vtx[0]};
    cb.vout[cidx].scriptPubKey = commitment;
    cb.vout[cidx].scriptPubKey << header;
    to_sign_block.vtx[0] = MakeTransactionRef(cb);

    const std::optional<SignetTxs> signet_txs = SignetTxs::Create(to_sign_block, challenge);
    if (!signet_txs) {
        error = "could not build the signet transactions for this block";
        return false;
    }

    CMutableTransaction to_sign{signet_txs->m_to_sign};
    PrecomputedTransactionData txdata;
    txdata.Init(to_sign, {signet_txs->m_to_spend.vout[0]});
    MutableTransactionSignatureCreator creator{to_sign, /*input_idx=*/0, signet_txs->m_to_spend.vout[0].nValue, &txdata, SIGHASH_ALL};
    SignatureData sigdata;
    if (!ProduceSignature(provider, creator, challenge, sigdata)) {
        error = "the signing keys cannot satisfy the signet challenge";
        return false;
    }

    std::vector<uint8_t> solution{header};
    VectorWriter writer{solution, solution.size()};
    writer << sigdata.scriptSig;
    writer << sigdata.scriptWitness.stack;

    cb.vout[cidx].scriptPubKey = commitment;
    cb.vout[cidx].scriptPubKey << solution;
    block.vtx[0] = MakeTransactionRef(std::move(cb));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return true;
}
