// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <index/txindex.h>
#include <merkleblock.h>
#include <node/blockstorage.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <validation.h>

using node::GetTransaction;

static RPCHelpMan gettxoutproof()
{
    return RPCHelpMan{"gettxoutproof",
        "\nReturns a hex-encoded proof that \"txid\" was included in a block.\n"
        "\nEach entry of \"txids\" may be a transaction hash or the hash of one of the\n"
        "transaction's outputs; the proof always commits to the transaction hashes.\n"
        "\nNOTE: Without a blockhash the block is located either through an entry that\n"
        "is the hash of an unspent output in the utxo set, or through the transaction\n"
        "index (-txindex). To make it always work, maintain a transaction index or\n"
        "specify the block in which the transaction is included manually (by blockhash).\n",
        {
            {"txids", RPCArg::Type::ARR, RPCArg::Optional::NO, "The txids to filter",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A transaction hash, or the hash of one of its outputs"},
                },
            },
            {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "If specified, looks for txid in the block with this hash"},
        },
        RPCResult{
            RPCResult::Type::STR, "data", "A string that is a serialized, hex-encoded data for the proof."
        },
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::set<uint256> setIds;
            UniValue txids = request.params[0].get_array();
            if (txids.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Parameter 'txids' cannot be empty");
            }
            for (unsigned int idx = 0; idx < txids.size(); idx++) {
                auto ret{setIds.insert(ParseHashV(txids[idx], "txid"))};
                if (!ret.second) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated txid: ") + txids[idx].get_str());
                }
            }

            const CBlockIndex* pblockindex = nullptr;
            uint256 hashBlock;
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            if (!request.params[1].isNull()) {
                LOCK(cs_main);
                hashBlock = ParseHashV(request.params[1], "blockhash");
                pblockindex = chainman.m_blockman.LookupBlockIndex(hashBlock);
                if (!pblockindex) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
                }
            } else {
                LOCK(cs_main);
                Chainstate& active_chainstate = chainman.ActiveChainstate();

                // Coins are keyed by output hash, so only an entry that is the
                // hash of an unspent output can be located through the coins
                // view. Exit the loop once a block is found.
                for (const auto& id : setIds) {
                    const Coin& coin{active_chainstate.CoinsTip().AccessCoin(COutPoint(id))};
                    if (!coin.IsSpent()) {
                        pblockindex = active_chainstate.m_chain[coin.nHeight];
                        if (pblockindex) break;
                    }
                }
            }

            if (pblockindex == nullptr) {
                if (!g_txindex) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not found in the utxo set; specify the block hash or enable -txindex");
                }
                // Allow txindex to catch up before we query it.
                g_txindex->BlockUntilSyncedToCurrentChain();

                for (const auto& id : setIds) {
                    const CTransactionRef tx = GetTransaction(/*block_index=*/nullptr, /*mempool=*/nullptr, Txid::FromUint256(id), hashBlock, chainman.m_blockman);
                    if (tx && !hashBlock.IsNull()) break;
                    hashBlock.SetNull();
                }
                if (hashBlock.IsNull()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not yet in block");
                }

                LOCK(cs_main);
                pblockindex = chainman.m_blockman.LookupBlockIndex(hashBlock);
                if (!pblockindex) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Transaction index corrupt");
                }
            }

            CBlock block;
            if (!chainman.m_blockman.ReadBlockFromDisk(block, *pblockindex)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
            }

            // Resolve every requested id to the transaction it names in this
            // block: either the transaction itself or one of its outputs.
            std::set<Txid> setTxids;
            std::set<uint256> found;
            for (const auto& tx : block.vtx) {
                if (setIds.contains(tx->GetHash().ToUint256())) {
                    setTxids.insert(tx->GetHash());
                    found.insert(tx->GetHash().ToUint256());
                }
            }
            if (found.size() != setIds.size()) {
                for (const auto& tx : block.vtx) {
                    for (const auto& txout : tx->vout) {
                        const uint256 out_hash{txout.GetHash()};
                        if (setIds.contains(out_hash)) {
                            setTxids.insert(tx->GetHash());
                            found.insert(out_hash);
                        }
                    }
                }
            }
            if (found.size() != setIds.size()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Not all transactions found in specified or retrieved block");
            }

            DataStream ssMB{};
            CMerkleBlock mb(block, setTxids);
            ssMB << mb;
            std::string strHex = HexStr(ssMB);
            return strHex;
        },
    };
}

static RPCHelpMan verifytxoutproof()
{
    return RPCHelpMan{"verifytxoutproof",
        "\nVerifies that a proof points to a transaction in a block, returning the transaction it commits to\n"
        "and throwing an RPC error if the block is not in our best chain\n",
        {
            {"proof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded proof generated by gettxoutproof"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The txid(s) which the proof commits to, or empty array if the proof cannot be validated."},
            }
        },
        RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            DataStream ssMB{ParseHexV(request.params[0], "proof")};
            CMerkleBlock merkleBlock;
            ssMB >> merkleBlock;

            UniValue res(UniValue::VARR);

            std::vector<uint256> vMatch;
            std::vector<unsigned int> vIndex;
            if (merkleBlock.txn.ExtractMatches(vMatch, vIndex) != merkleBlock.header.hashMerkleRoot)
                return res;

            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);

            const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(merkleBlock.header.GetHash());
            if (!pindex || !chainman.ActiveChain().Contains(pindex) || pindex->nTx == 0) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found in chain");
            }

            // Check if proof is valid, only add results if so
            if (pindex->nTx == merkleBlock.txn.GetNumTransactions()) {
                for (const uint256& hash : vMatch) {
                    res.push_back(hash.GetHex());
                }
            }

            return res;
        },
    };
}

void RegisterTxoutProofRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"blockchain", &gettxoutproof},
        {"blockchain", &verifytxoutproof},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
