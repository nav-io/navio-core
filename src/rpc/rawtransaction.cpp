// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <index/outindex.h>
#include <index/txindex.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <node/blockstorage.h>
#include <node/coin.h>
#include <node/context.h>
#include <node/transaction.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <primitives/transaction.h>
#include <rpc/blockchain.h>
#include <rpc/rawtransaction_util.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <uint256.h>
#include <undo.h>
#include <util/check.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/vector.h>
#include <validation.h>
#include <validationinterface.h>

#include <numeric>
#include <cstdint>
#include <optional>

#include <univalue.h>

using node::FindCoins;
using node::GetTransaction;
using node::NodeContext;

static void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry,
                     Chainstate& active_chainstate, const CTxUndo* txundo = nullptr,
                     TxVerbosity verbosity = TxVerbosity::SHOW_DETAILS)
{
    CHECK_NONFATAL(verbosity >= TxVerbosity::SHOW_DETAILS);
    // Call into TxToUniv() in bitcoin-common to decode the transaction hex.
    //
    // Blockchain contextual information (confirmations and blocktime) is not
    // available to code in bitcoin-common, so we query them here and push the
    // data into the returned UniValue.
    TxToUniv(tx, /*block_hash=*/uint256(), entry, /*include_hex=*/true, txundo, verbosity);

    if (!hashBlock.IsNull()) {
        LOCK(cs_main);

        entry.pushKV("blockhash", hashBlock.GetHex());
        const CBlockIndex* pindex = active_chainstate.m_blockman.LookupBlockIndex(hashBlock);
        if (pindex) {
            if (active_chainstate.m_chain.Contains(pindex)) {
                entry.pushKV("confirmations", 1 + active_chainstate.m_chain.Height() - pindex->nHeight);
                entry.pushKV("time", pindex->GetBlockTime());
                entry.pushKV("blocktime", pindex->GetBlockTime());
            } else
                entry.pushKV("confirmations", 0);
        }
    }
}

static std::vector<RPCResult> ScriptPubKeyDoc()
{
    return {
        {RPCResult::Type::STR, "asm", "Disassembly of the public key script"},
        {RPCResult::Type::STR, "desc", "Inferred descriptor for the output"},
        {RPCResult::Type::STR_HEX, "hex", "The raw public key script bytes, hex-encoded"},
        {RPCResult::Type::STR, "address", /*optional=*/true, "The Navio address (only if a well-defined address exists)"},
        {RPCResult::Type::STR, "type", "The type (one of: " + GetAllOutputTypes() + ")"},
    };
}

static std::vector<RPCResult> DecodeTxDoc(const std::string& txid_field_doc)
{
    return {
        {RPCResult::Type::STR_HEX, "txid", txid_field_doc},
        {RPCResult::Type::STR_HEX, "hash", "The transaction hash (differs from txid for witness transactions)"},
        {RPCResult::Type::NUM, "size", "The serialized transaction size"},
        {RPCResult::Type::NUM, "vsize", "The virtual transaction size (differs from size for witness transactions)"},
        {RPCResult::Type::NUM, "weight", "The transaction's weight (between vsize*4-3 and vsize*4)"},
        {RPCResult::Type::NUM, "version", "The version"},
        {RPCResult::Type::NUM_TIME, "locktime", "The lock time"},
        {RPCResult::Type::ARR, "vin", "", {
                                              {RPCResult::Type::OBJ, "", "", {
                                                                                 {RPCResult::Type::STR_HEX, "coinbase", /*optional=*/true, "The coinbase value (only if coinbase transaction)"},
                                                                                 {RPCResult::Type::STR_HEX, "outid", /*optional=*/true, "The output id (if not coinbase transaction)"},
                                                                                 {RPCResult::Type::OBJ, "scriptSig", /*optional=*/true, "The script (if not coinbase transaction)", {
                                                                                                                                                                                        {RPCResult::Type::STR, "asm", "Disassembly of the signature script"},
                                                                                                                                                                                        {RPCResult::Type::STR_HEX, "hex", "The raw signature script bytes, hex-encoded"},
                                                                                                                                                                                    }},
                                                                                 {RPCResult::Type::ARR, "txinwitness", /*optional=*/true, "", {
                                                                                                                                                  {RPCResult::Type::STR_HEX, "hex", "hex-encoded witness data (if any)"},
                                                                                                                                              }},
                                                                                 {RPCResult::Type::NUM, "sequence", "The script sequence number"},
                                                                             }},
                                          }},
        {RPCResult::Type::ARR, "vout", "", {
                                               {RPCResult::Type::OBJ, "", "", {
                                                                                  {RPCResult::Type::STR_AMOUNT, "value", "The value in " + CURRENCY_UNIT},
                                                                                  {RPCResult::Type::STR_HEX, "hash", /*optional=*/true, "the output hash"},
                                                                                  {RPCResult::Type::NUM, "n", "index"},
                                                                                  {RPCResult::Type::OBJ, "scriptPubKey", "", ScriptPubKeyDoc()},
                                                                                  {RPCResult::Type::STR_HEX, "blindingKey", /*optional=*/true, "hex-encoded blinding key"},
                                                                                  {RPCResult::Type::STR_HEX, "ephemeralKey", /*optional=*/true, "hex-encoded ephemeral key"},
                                                                                  {RPCResult::Type::STR_HEX, "spendingKey", /*optional=*/true, "hex-encoded spending key"},
                                                                                  {RPCResult::Type::OBJ, "rangeProof", /*optional=*/true, "output's range proof", {
                                                                                                                                                                      {RPCResult::Type::ARR, "Vs", true, "Vs", {
                                                                                                                                                                                                                   {RPCResult::Type::STR_HEX, "", "hex-encoded point (if any)"},
                                                                                                                                                                                                               }},
                                                                                                                                                                      {RPCResult::Type::ARR, "Ls", /*optional=*/true, "Ls", {
                                                                                                                                                                                                                                {RPCResult::Type::STR_HEX, "", "hex-encoded point (if any)"},
                                                                                                                                                                                                                            }},
                                                                                                                                                                      {RPCResult::Type::ARR, "Rs", /*optional=*/true, "Rs", {
                                                                                                                                                                                                                                {RPCResult::Type::STR_HEX, "", "hex-encoded point (if any)"},
                                                                                                                                                                                                                            }},
                                                                                  {RPCResult::Type::STR_HEX, "A", /*optional=*/true, "hex-encoded point"},
                                                                                  {RPCResult::Type::STR_HEX, "S", /*optional=*/true, "hex-encoded point"},
                                                                                  {RPCResult::Type::STR_HEX, "T1", /*optional=*/true, "hex-encoded point"},
                                                                                  {RPCResult::Type::STR_HEX, "T2", /*optional=*/true, "hex-encoded point"},
                                                                                  {RPCResult::Type::STR_HEX, "tau_x", /*optional=*/true, "hex-encoded scalar"},
                                                                                                                                                                      {RPCResult::Type::STR_HEX, "mu", /*optional=*/true, "hex-encoded scalar"},
                                                                                                                                                                      {RPCResult::Type::STR_HEX, "a", /*optional=*/true, "hex-encoded scalar"},
                                                                                                                                                                  {RPCResult::Type::STR_HEX, "b", /*optional=*/true, "hex-encoded scalar"},
                                                                                                                                                                  {RPCResult::Type::STR_HEX, "t_hat", /*optional=*/true, "hex-encoded scalar"},
                                                                                                                                                              }},
                                                                                  {RPCResult::Type::STR, "tokenId", /*optional=*/true, "output's token id"},
                                                                                  {RPCResult::Type::STR_HEX, "predicateHex", /*optional=*/true, "hex-encoded output predicate"},
                                                                                  {RPCResult::Type::STR, "predicate", /*optional=*/true, "human friendly output predicate"},
                                                                                  {RPCResult::Type::NUM, "viewTag", /*optional=*/true, "output's view tag"},
                                                                              }},
                                           }},
        {RPCResult::Type::STR_HEX, "txSig", /*optional=*/true, "hex-encoded transaction signature"},
    };
}

static std::vector<RPCArg> CreateTxDoc()
{
    return {
        {
            "inputs",
            RPCArg::Type::ARR,
            RPCArg::Optional::NO,
            "The inputs",
            {
                {
                    "",
                    RPCArg::Type::OBJ,
                    RPCArg::Optional::OMITTED,
                    "",
                    {
                        {"outid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The output id"},
                        {"sequence", RPCArg::Type::NUM, RPCArg::DefaultHint{"depends on the value of the 'replaceable' and 'locktime' arguments"}, "The sequence number"},
                    },
                },
            },
        },
        {"outputs", RPCArg::Type::ARR, RPCArg::Optional::NO, "The outputs specified as key-value pairs.\n"
                "Each key may only appear once, i.e. there can only be one 'data' output, and no address may be duplicated.\n"
                "At least one output of either type must be specified.\n"
                "For compatibility reasons, a dictionary, which holds the key-value pairs directly, is also\n"
                "                             accepted as second parameter.",
            {
                {"", RPCArg::Type::OBJ_USER_KEYS, RPCArg::Optional::OMITTED, "",
                    {
                        {"address", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "A key-value pair. The key (string) is the Navio address, the value (float or string) is the amount in " + CURRENCY_UNIT},
                    },
                },
                {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                    {
                        {"data", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A key-value pair. The key must be \"data\", the value is hex-encoded data"},
                    },
                },
            },
         RPCArgOptions{.skip_type_check = true}},
        {"locktime", RPCArg::Type::NUM, RPCArg::Default{0}, "Raw locktime. Non-0 value also locktime-activates inputs"},
        {"replaceable", RPCArg::Type::BOOL, RPCArg::Default{true}, "Marks this transaction as BIP125-replaceable.\n"
                                                                   "Allows this transaction to be replaced by a transaction with higher fees. If provided, it is an error if explicit sequence numbers are incompatible."},
    };
}

static RPCHelpMan getrawtransaction()
{
    return RPCHelpMan{
                "getrawtransaction",

                "By default, this call only returns a transaction if it is in the mempool. If -txindex is enabled\n"
                "and no blockhash argument is passed, it will return the transaction if it is in the mempool or any block.\n"
                "If a blockhash argument is passed, it will return the transaction if\n"
                "the specified block is available and the transaction is in that block.\n\n"
                "Hint: Use gettransaction for wallet transactions.\n\n"

                "If verbosity is 0 or omitted, returns the serialized transaction as a hex-encoded string.\n"
                "If verbosity is 1, returns a JSON Object with information about the transaction.\n"
                "If verbosity is 2, returns a JSON Object with information about the transaction, including fee and prevout information.",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                    {"verbosity|verbose", RPCArg::Type::NUM, RPCArg::Default{0}, "0 for hex-encoded data, 1 for a JSON object, and 2 for JSON object with fee and prevout",
                     RPCArgOptions{.skip_type_check = true}},
                    {"blockhash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The block in which to look for the transaction"},
                },
                {
                    RPCResult{"if verbosity is not set or set to 0",
                         RPCResult::Type::STR, "data", "The serialized transaction as a hex-encoded string for 'txid'"
                     },
                     RPCResult{"if verbosity is set to 1",
                         RPCResult::Type::OBJ, "", "",
                         Cat<std::vector<RPCResult>>(
                         {
                             {RPCResult::Type::BOOL, "in_active_chain", /*optional=*/true, "Whether specified block is in the active chain or not (only present with explicit \"blockhash\" argument)"},
                             {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "the block hash"},
                             {RPCResult::Type::NUM, "confirmations", /*optional=*/true, "The confirmations"},
                             {RPCResult::Type::NUM_TIME, "blocktime", /*optional=*/true, "The block time expressed in " + UNIX_EPOCH_TIME},
                             {RPCResult::Type::NUM, "time", /*optional=*/true, "Same as \"blocktime\""},
                             {RPCResult::Type::STR_HEX, "hex", "The serialized, hex-encoded data for 'txid'"},
                         },
                         DecodeTxDoc(/*txid_field_doc=*/"The transaction id (same as provided)")),
                    },
                    RPCResult{"for verbosity = 2",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::ELISION, "", "Same output as verbosity = 1"},
                            {RPCResult::Type::NUM, "fee", /*optional=*/true, "transaction fee in " + CURRENCY_UNIT + ", omitted if block undo data is not available"},
                            {RPCResult::Type::ARR, "vin", "",
                            {
                                {RPCResult::Type::OBJ, "", "utxo being spent",
                                {
                                    {RPCResult::Type::ELISION, "", "Same output as verbosity = 1"},
                                    {RPCResult::Type::OBJ, "prevout", /*optional=*/true, "The previous output, omitted if block undo data is not available",
                                    {
                                        {RPCResult::Type::BOOL, "generated", "Coinbase or not"},
                                        {RPCResult::Type::NUM, "height", "The height of the prevout"},
                                        {RPCResult::Type::STR_AMOUNT, "value", "The value in " + CURRENCY_UNIT},
                                        {RPCResult::Type::OBJ, "scriptPubKey", "", ScriptPubKeyDoc()},
                                    }},
                                }},
                            }},
                        }},
                },
                RPCExamples{
                    HelpExampleCli("getrawtransaction", "\"mytxid\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 1")
            + HelpExampleRpc("getrawtransaction", "\"mytxid\", 1")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 0 \"myblockhash\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 1 \"myblockhash\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 2 \"myblockhash\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);

    uint256 hash = ParseHashV(request.params[0], "parameter 1");
    const CBlockIndex* blockindex = nullptr;

    if (hash == chainman.GetParams().GenesisBlock().hashMerkleRoot) {
        // Special exception for the genesis block coinbase transaction
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "The genesis block coinbase is not considered an ordinary transaction and cannot be retrieved");
    }

    // Accept either a bool (true) or a num (>=0) to indicate verbosity.
    int verbosity{0};
    if (!request.params[1].isNull()) {
        if (request.params[1].isBool()) {
            verbosity = request.params[1].get_bool();
        } else {
            verbosity = request.params[1].getInt<int>();
        }
    }

    if (!request.params[2].isNull()) {
        LOCK(cs_main);

        uint256 blockhash = ParseHashV(request.params[2], "parameter 3");
        blockindex = chainman.m_blockman.LookupBlockIndex(blockhash);
        if (!blockindex) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block hash not found");
        }
    }

    bool f_txindex_ready = false;
    if (g_txindex && !blockindex) {
        f_txindex_ready = g_txindex->BlockUntilSyncedToCurrentChain();
    }

    uint256 hash_block;
    const CTransactionRef tx = GetTransaction(blockindex, node.mempool.get(), hash, hash_block, chainman.m_blockman);
    if (!tx) {
        std::string errmsg;
        if (blockindex) {
            const bool block_has_data = WITH_LOCK(::cs_main, return blockindex->nStatus & BLOCK_HAVE_DATA);
            if (!block_has_data) {
                throw JSONRPCError(RPC_MISC_ERROR, "Block not available");
            }
            errmsg = "No such transaction found in the provided block";
        } else if (!g_txindex) {
            errmsg = "No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries";
        } else if (!f_txindex_ready) {
            errmsg = "No such mempool transaction. Blockchain transactions are still in the process of being indexed";
        } else {
            errmsg = "No such mempool or blockchain transaction";
        }
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, errmsg + ". Use gettransaction for wallet transactions.");
    }

    if (verbosity <= 0) {
        return EncodeHexTx(*tx);
    }

    UniValue result(UniValue::VOBJ);
    if (blockindex) {
        LOCK(cs_main);
        result.pushKV("in_active_chain", chainman.ActiveChain().Contains(blockindex));
    }
    // If request is verbosity >= 1 but no blockhash was given, then look up the blockindex
    if (request.params[2].isNull()) {
        LOCK(cs_main);
        blockindex = chainman.m_blockman.LookupBlockIndex(hash_block); // May be nullptr for mempool transactions
    }
    if (verbosity == 1) {
        TxToJSON(*tx, hash_block, result, chainman.ActiveChainstate());
        return result;
    }

    CBlockUndo blockUndo;
    CBlock block;

    if (tx->IsCoinBase() || !blockindex || WITH_LOCK(::cs_main, return chainman.m_blockman.IsBlockPruned(*blockindex)) ||
        !(chainman.m_blockman.UndoReadFromDisk(blockUndo, *blockindex) && chainman.m_blockman.ReadBlockFromDisk(block, *blockindex))) {
        TxToJSON(*tx, hash_block, result, chainman.ActiveChainstate());
        return result;
    }

    CTxUndo* undoTX {nullptr};
    auto it = std::find_if(block.vtx.begin(), block.vtx.end(), [tx](CTransactionRef t){ return *t == *tx; });
    if (it != block.vtx.end()) {
        // -1 as blockundo does not have coinbase tx
        undoTX = &blockUndo.vtxundo.at(it - block.vtx.begin() - 1);
    }
    TxToJSON(*tx, hash_block, result, chainman.ActiveChainstate(), undoTX, TxVerbosity::SHOW_DETAILS_AND_PREVOUT);
    return result;
},
    };
}

static RPCHelpMan createrawtransaction()
{
    return RPCHelpMan{
        "createrawtransaction",
        "\nCreate a transaction spending the given inputs and creating new outputs.\n"
        "Outputs can be addresses or data.\n"
        "Returns hex-encoded raw transaction.\n"
        "Note that the transaction's inputs are not signed, and\n"
        "it is not stored in the wallet or transmitted to the network.\n",
        CreateTxDoc(),
        RPCResult{
            RPCResult::Type::STR_HEX, "transaction", "hex string of the transaction"},
        RPCExamples{
            HelpExampleCli("createrawtransaction", "\"[{\\\"outid\\\":\\\"myoutid\\\"}]\" \"[{\\\"address\\\":0.01}]\"") + HelpExampleCli("createrawtransaction", "\"[{\\\"outid\\\":\\\"myoutid\\\"}]\" \"[{\\\"data\\\":\\\"00010203\\\"}]\"") + HelpExampleRpc("createrawtransaction", "\"[{\\\"outid\\\":\\\"myoutid\\\"}]\", \"[{\\\"address\\\":0.01}]\"") + HelpExampleRpc("createrawtransaction", "\"[{\\\"outid\\\":\\\"myoutid\\\"}]\", \"[{\\\"data\\\":\\\"00010203\\\"}]\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::optional<bool> rbf;
            if (!request.params[3].isNull()) {
                rbf = request.params[3].get_bool();
            }
            CMutableTransaction rawTx = ConstructTransaction(request.params[0], request.params[1], request.params[2], rbf);

            return EncodeHexTx(CTransaction(rawTx));
        },
    };
}

static RPCHelpMan decoderawtransaction()
{
    return RPCHelpMan{
        "decoderawtransaction",
        "Return a JSON object representing the serialized, hex-encoded transaction.",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction hex string"},
            {"iswitness", RPCArg::Type::BOOL, RPCArg::DefaultHint{"depends on heuristic tests"}, "Whether the transaction hex is a serialized witness transaction.\n"
                                                                                                 "If iswitness is not present, heuristic tests will be used in decoding.\n"
                                                                                                 "If true, only witness deserialization will be tried.\n"
                                                                                                 "If false, only non-witness deserialization will be tried.\n"
                                                                                                 "This boolean should reflect whether the transaction has inputs\n"
                                                                                                 "(e.g. fully valid, or on-chain transactions), if known by the caller."},
        },
        RPCResult{
            RPCResult::Type::OBJ,
            "",
            "",
            DecodeTxDoc(/*txid_field_doc=*/"The transaction id"),
        },
        RPCExamples{
            HelpExampleCli("decoderawtransaction", "\"hexstring\"") + HelpExampleRpc("decoderawtransaction", "\"hexstring\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            CMutableTransaction mtx;

            bool try_witness = request.params[1].isNull() ? true : request.params[1].get_bool();
            bool try_no_witness = request.params[1].isNull() ? true : !request.params[1].get_bool();

            if (!DecodeHexTx(mtx, request.params[0].get_str(), try_no_witness, try_witness)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }

            UniValue result(UniValue::VOBJ);
            TxToUniv(CTransaction(std::move(mtx)), /*block_hash=*/uint256(), /*entry=*/result, /*include_hex=*/false);

            return result;
        },
    };
}

static RPCHelpMan decodescript()
{
    return RPCHelpMan{
        "decodescript",
        "\nDecode a hex-encoded script.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded script"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "asm", "Script public key"},
                {RPCResult::Type::STR, "desc", "Inferred descriptor for the script"},
                {RPCResult::Type::STR, "type", "The output type (e.g. " + GetAllOutputTypes() + ")"},
                {RPCResult::Type::STR, "address", /*optional=*/true, "The Navio address (only if a well-defined address exists)"},
                {RPCResult::Type::STR, "p2sh", /*optional=*/true,
                 "address of P2SH script wrapping this redeem script (not returned for types that should not be wrapped)"},
                {RPCResult::Type::OBJ, "segwit", /*optional=*/true,
                 "Result of a witness script public key wrapping this redeem script (not returned for types that should not be wrapped)",
                 {
                     {RPCResult::Type::STR, "asm", "String representation of the script public key"},
                     {RPCResult::Type::STR_HEX, "hex", "Hex string of the script public key"},
                     {RPCResult::Type::STR, "type", "The type of the script public key (e.g. witness_v0_keyhash or witness_v0_scripthash)"},
                     {RPCResult::Type::STR, "address", /*optional=*/true, "The Navio address (only if a well-defined address exists)"},
                     {RPCResult::Type::STR, "desc", "Inferred descriptor for the script"},
                     {RPCResult::Type::STR, "p2sh-segwit", "address of the P2SH script wrapping this witness redeem script"},
                 }},
            },
        },
        RPCExamples{
            HelpExampleCli("decodescript", "\"hexstring\"")
          + HelpExampleRpc("decodescript", "\"hexstring\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue r(UniValue::VOBJ);
    CScript script;
    if (request.params[0].get_str().size() > 0){
        std::vector<unsigned char> scriptData(ParseHexV(request.params[0], "argument"));
        script = CScript(scriptData.begin(), scriptData.end());
    } else {
        // Empty scripts are valid
    }
    ScriptToUniv(script, /*out=*/r, /*include_hex=*/false, /*include_address=*/true);

    std::vector<std::vector<unsigned char>> solutions_data;
    const TxoutType which_type{Solver(script, solutions_data)};

    const bool can_wrap{[&] {
        switch (which_type) {
        case TxoutType::MULTISIG:
        case TxoutType::NONSTANDARD:
        case TxoutType::PUBKEY:
        case TxoutType::PUBKEYHASH:
        case TxoutType::WITNESS_V0_KEYHASH:
        case TxoutType::WITNESS_V0_SCRIPTHASH:
            // Can be wrapped if the checks below pass
            break;
        case TxoutType::NULL_DATA:
        case TxoutType::SCRIPTHASH:
        case TxoutType::WITNESS_UNKNOWN:
        case TxoutType::WITNESS_V1_TAPROOT:
            // Should not be wrapped
            return false;
        } // no default case, so the compiler can warn about missing cases
        if (!script.HasValidOps() || script.IsUnspendable()) {
            return false;
        }
        for (CScript::const_iterator it{script.begin()}; it != script.end();) {
            opcodetype op;
            CHECK_NONFATAL(script.GetOp(it, op));
            if (op == OP_CHECKSIGADD || IsOpSuccess(op)) {
                return false;
            }
        }
        return true;
    }()};

    if (can_wrap) {
        r.pushKV("p2sh", EncodeDestination(ScriptHash(script)));
        // P2SH and witness programs cannot be wrapped in P2WSH, if this script
        // is a witness program, don't return addresses for a segwit programs.
        const bool can_wrap_P2WSH{[&] {
            switch (which_type) {
            case TxoutType::MULTISIG:
            case TxoutType::PUBKEY:
            // Uncompressed pubkeys cannot be used with segwit checksigs.
            // If the script contains an uncompressed pubkey, skip encoding of a segwit program.
                for (const auto& solution : solutions_data) {
                    if ((solution.size() != 1) && !CPubKey(solution).IsCompressed()) {
                        return false;
                    }
                }
                return true;
            case TxoutType::NONSTANDARD:
            case TxoutType::PUBKEYHASH:
                // Can be P2WSH wrapped
                return true;
            case TxoutType::NULL_DATA:
            case TxoutType::SCRIPTHASH:
            case TxoutType::WITNESS_UNKNOWN:
            case TxoutType::WITNESS_V0_KEYHASH:
            case TxoutType::WITNESS_V0_SCRIPTHASH:
            case TxoutType::WITNESS_V1_TAPROOT:
                // Should not be wrapped
                return false;
            } // no default case, so the compiler can warn about missing cases
            NONFATAL_UNREACHABLE();
        }()};
        if (can_wrap_P2WSH) {
            UniValue sr(UniValue::VOBJ);
            CScript segwitScr;
            FlatSigningProvider provider;
            if (which_type == TxoutType::PUBKEY) {
                segwitScr = GetScriptForDestination(WitnessV0KeyHash(Hash160(solutions_data[0])));
            } else if (which_type == TxoutType::PUBKEYHASH) {
                segwitScr = GetScriptForDestination(WitnessV0KeyHash(uint160{solutions_data[0]}));
            } else {
                // Scripts that are not fit for P2WPKH are encoded as P2WSH.
                provider.scripts[CScriptID(script)] = script;
                segwitScr = GetScriptForDestination(WitnessV0ScriptHash(script));
            }
            ScriptToUniv(segwitScr, /*out=*/sr, /*include_hex=*/true, /*include_address=*/true, /*provider=*/&provider);
            sr.pushKV("p2sh-segwit", EncodeDestination(ScriptHash(segwitScr)));
            r.pushKV("segwit", sr);
        }
    }

    return r;
},
    };
}

static RPCHelpMan combinerawtransaction()
{
    return RPCHelpMan{
        "combinerawtransaction",
        "\nCombine multiple partially signed transactions into one transaction.\n"
        "The combined transaction may be another partially signed transaction or a \n"
        "fully signed transaction.",
        {
            {
                "txs",
                RPCArg::Type::ARR,
                RPCArg::Optional::NO,
                "The hex strings of partially signed transactions",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A hex-encoded raw transaction"},
                },
            },
        },
        RPCResult{
            RPCResult::Type::STR, "", "The hex-encoded raw transaction with signature(s)"},
        RPCExamples{
            HelpExampleCli("combinerawtransaction", R"('["myhex1", "myhex2", "myhex3"]')")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            UniValue txs = request.params[0].get_array();
            std::vector<CMutableTransaction> txVariants(txs.size());

            for (unsigned int idx = 0; idx < txs.size(); idx++) {
                if (!DecodeHexTx(txVariants[idx], txs[idx].get_str())) {
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("TX decode failed for tx %d. Make sure the tx has at least one input.", idx));
                }
            }

            if (txVariants.empty()) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Missing transactions");
            }

            // mergedTx will end up with all the signatures; it
            // starts as a clone of the rawtx:
            CMutableTransaction mergedTx(txVariants[0]);

            // Fetch previous transactions (inputs):
            CCoinsView viewDummy;
            CCoinsViewCache view(&viewDummy);
            {
                NodeContext& node = EnsureAnyNodeContext(request.context);
                const CTxMemPool& mempool = EnsureMemPool(node);
                ChainstateManager& chainman = EnsureChainman(node);
                LOCK2(cs_main, mempool.cs);
                CCoinsViewCache& viewChain = chainman.ActiveChainstate().CoinsTip();
                CCoinsViewMemPool viewMempool(&viewChain, mempool);
                view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

                for (const CTxIn& txin : mergedTx.vin) {
                    view.AccessCoin(txin.prevout); // Load entries from viewChain into view; can fail.
                }

                view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
            }

            // Use CTransaction for the constant parts of the
            // transaction to avoid rehashing.
            const CTransaction txConst(mergedTx);
            // Sign what we can:
            for (unsigned int i = 0; i < mergedTx.vin.size(); i++) {
                CTxIn& txin = mergedTx.vin[i];
                const Coin& coin = view.AccessCoin(txin.prevout);
                if (coin.IsSpent()) {
                    throw JSONRPCError(RPC_VERIFY_ERROR, "Input not found or already spent");
                }
                SignatureData sigdata;

                // ... and merge in other signatures:
                for (const CMutableTransaction& txv : txVariants) {
                    if (txv.vin.size() > i) {
                        sigdata.MergeSignatureData(DataFromTransaction(txv, i, coin.out));
                    }
                }
                ProduceSignature(DUMMY_SIGNING_PROVIDER, MutableTransactionSignatureCreator(mergedTx, i, coin.out.nValue, 1), coin.out.scriptPubKey, sigdata);

                UpdateInput(txin, sigdata);
            }

            return EncodeHexTx(CTransaction(mergedTx));
        },
    };
}

static RPCHelpMan signrawtransactionwithkey()
{
    return RPCHelpMan{
        "signrawtransactionwithkey",
        "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
        "The second argument is an array of base58-encoded private\n"
        "keys that will be the only keys used to sign the transaction.\n"
        "The third optional argument (may be null) is an array of previous transaction outputs that\n"
        "this transaction depends on but may not yet be in the block chain.\n",
        {
            {"hexstring", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction hex string"},
            {
                "privkeys",
                RPCArg::Type::ARR,
                RPCArg::Optional::NO,
                "The base58-encoded private keys for signing",
                {
                    {"privatekey", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "private key in base58-encoding"},
                },
            },
            {
                "prevtxs",
                RPCArg::Type::ARR,
                RPCArg::Optional::OMITTED,
                "The previous dependent transaction outputs",
                {
                    {
                        "",
                        RPCArg::Type::OBJ,
                        RPCArg::Optional::OMITTED,
                        "",
                        {
                            {"outid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The output id"},
                            {"scriptPubKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "script key"},
                            {"redeemScript", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "(required for P2SH) redeem script"},
                            {"witnessScript", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "(required for P2WSH or P2SH-P2WSH) witness script"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED, "(required for Segwit inputs) the amount spent"},
                        },
                    },
                },
            },
            {"sighashtype", RPCArg::Type::STR, RPCArg::Default{"DEFAULT for Taproot, ALL otherwise"}, "The signature hash type. Must be one of:\n"
                                                                                                      "       \"DEFAULT\"\n"
                                                                                                      "       \"ALL\"\n"
                                                                                                      "       \"NONE\"\n"
                                                                                                      "       \"SINGLE\"\n"
                                                                                                      "       \"ALL|ANYONECANPAY\"\n"
                                                                                                      "       \"NONE|ANYONECANPAY\"\n"
                                                                                                      "       \"SINGLE|ANYONECANPAY\"\n"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                                              {RPCResult::Type::STR_HEX, "hex", "The hex-encoded raw transaction with signature(s)"},
                                              {RPCResult::Type::BOOL, "complete", "If the transaction has a complete set of signatures"},
                                              {RPCResult::Type::ARR, "errors", /*optional=*/true, "Script verification errors (if there are any)", {
                                                                                                                                                       {RPCResult::Type::OBJ, "", "", {
                                                                                                                                                                                          {RPCResult::Type::STR_HEX, "outid", "The hash of the referenced, previous output"},
                                                                                                                                                                                          {RPCResult::Type::ARR, "witness", "", {
                                                                                                                                                                                                                                    {RPCResult::Type::STR_HEX, "witness", ""},
                                                                                                                                                                                                                                }},
                                                                                                                                                                                          {RPCResult::Type::STR_HEX, "scriptSig", "The hex-encoded signature script"},
                                                                                                                                                                                          {RPCResult::Type::NUM, "sequence", "Script sequence number"},
                                                                                                                                                                                          {RPCResult::Type::STR, "error", "Verification or signing error related to the input"},
                                                                                                                                                                                      }},
                                                                                                                                                   }},
                                          }},
        RPCExamples{HelpExampleCli("signrawtransactionwithkey", "\"myhex\" \"[\\\"key1\\\",\\\"key2\\\"]\"") + HelpExampleRpc("signrawtransactionwithkey", "\"myhex\", \"[\\\"key1\\\",\\\"key2\\\"]\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, request.params[0].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Make sure the tx has at least one input.");
            }

            FillableSigningProvider keystore;
            const UniValue& keys = request.params[1].get_array();
            for (unsigned int idx = 0; idx < keys.size(); ++idx) {
                UniValue k = keys[idx];
                CKey key = DecodeSecret(k.get_str());
                if (!key.IsValid()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
                }
                keystore.AddKey(key);
            }

            // Fetch previous transactions (inputs):
            std::map<COutPoint, Coin> coins;
            for (const CTxIn& txin : mtx.vin) {
                coins[txin.prevout]; // Create empty map entry keyed by prevout.
            }
            NodeContext& node = EnsureAnyNodeContext(request.context);
            FindCoins(node, coins);

            // Parse the prevtxs array
            ParsePrevouts(request.params[2], &keystore, coins);

            UniValue result(UniValue::VOBJ);
            SignTransaction(mtx, &keystore, coins, request.params[3], result);
            return result;
        },
    };
}

//! Everything gettxfromoutputhash needs from a block index entry, copied out
//! under cs_main so the block itself can be read from disk with the lock
//! released.
struct OutputHashBlockRef {
    FlatFilePos pos;
    uint256 hash;
    int height;
    const CBlockIndex* prev;
};

//! Copy out the block index fields the output-hash search needs. Throws if the
//! block's data has been pruned: the output may well be in that block, and
//! answering "not found" would be a wrong answer rather than a missing one.
static OutputHashBlockRef GetOutputHashBlockRef(node::BlockManager& blockman, const CBlockIndex& index)
{
    LOCK(cs_main);
    if (blockman.IsBlockPruned(index)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Output hash not found in unpruned blocks (pruned data)");
    }
    return {index.GetBlockPos(), index.GetBlockHash(), index.nHeight, index.pprev};
}

//! Describe where output_hash sits in an already-read block, or nullopt if the
//! block does not contain it.
static std::optional<UniValue> FindOutputHashInBlock(const CBlock& block, const uint256& output_hash, const uint256& block_hash, int confirmations)
{
    for (const auto& tx : block.vtx) {
        for (size_t i = 0; i < tx->vout.size(); i++) {
            if (tx->vout[i].GetHash() == output_hash) {
                UniValue result(UniValue::VOBJ);
                result.pushKV("txid", tx->GetHash().GetHex());
                result.pushKV("vout", (int)i);
                result.pushKV("blockhash", block_hash.GetHex());
                result.pushKV("confirmations", confirmations);
                return result;
            }
        }
    }
    return std::nullopt;
}

//! An output located through -outindex, with the block data read back and
//! checked against the index entry.
struct IndexedOutput {
    CTransactionRef tx;
    uint32_t out_pos;
    uint256 block_hash;
    int height;
    struct Spend {
        CTransactionRef tx;
        uint32_t in_pos;
        uint256 block_hash;
        int height;
    };
    std::optional<Spend> spent;
};

enum class OutIndexLookup {
    FOUND,
    NOT_FOUND,   //!< the index is synced and has no entry for the output
    UNAVAILABLE, //!< no index, not synced, or its entry did not match the chain
};

//! Read the transaction at tx_pos of the active-chain block at height.
//! Returns nullptr if there is no such block or position.
static CTransactionRef ReadIndexedTx(ChainstateManager& chainman, int height, uint32_t tx_pos, uint256& block_hash)
{
    FlatFilePos pos;
    {
        LOCK(cs_main);
        const CBlockIndex* pindex{chainman.ActiveChain()[height]};
        if (!pindex) return nullptr;
        if (chainman.m_blockman.IsBlockPruned(*pindex)) {
            throw JSONRPCError(RPC_MISC_ERROR, "Output hash not found in unpruned blocks (pruned data)");
        }
        pos = pindex->GetBlockPos();
        block_hash = pindex->GetBlockHash();
    }
    CBlock block;
    if (!chainman.m_blockman.ReadBlockFromDisk(block, pos)) return nullptr;
    if (block.GetHash() != block_hash || tx_pos >= block.vtx.size()) return nullptr;
    return block.vtx[tx_pos];
}

//! Look output_hash up in -outindex. Anything that does not line up with the
//! active chain (the index lagging a reorg, say) is reported as UNAVAILABLE so
//! callers can fall back to a slower search rather than return a wrong answer.
static OutIndexLookup LookupIndexedOutput(ChainstateManager& chainman, const uint256& output_hash, IndexedOutput& out)
{
    if (!g_outindex || !g_outindex->BlockUntilSyncedToCurrentChain()) return OutIndexLookup::UNAVAILABLE;

    const std::optional<OutIndexEntry> entry{g_outindex->FindOutput(output_hash)};
    if (!entry) return OutIndexLookup::NOT_FOUND;

    out.tx = ReadIndexedTx(chainman, entry->height, entry->tx_pos, out.block_hash);
    if (!out.tx || entry->out_pos >= out.tx->vout.size() ||
        out.tx->vout[entry->out_pos].GetHash() != output_hash) {
        return OutIndexLookup::UNAVAILABLE;
    }
    out.out_pos = entry->out_pos;
    out.height = entry->height;

    out.spent.reset();
    if (entry->spent) {
        IndexedOutput::Spend spend;
        spend.tx = ReadIndexedTx(chainman, entry->spent->height, entry->spent->tx_pos, spend.block_hash);
        if (!spend.tx || entry->spent->in_pos >= spend.tx->vin.size() ||
            spend.tx->vin[entry->spent->in_pos].prevout.hash.ToUint256() != output_hash) {
            return OutIndexLookup::UNAVAILABLE;
        }
        spend.in_pos = entry->spent->in_pos;
        spend.height = entry->spent->height;
        out.spent = std::move(spend);
    }
    return OutIndexLookup::FOUND;
}

static RPCHelpMan gettxfromoutputhash()
{
    return RPCHelpMan{
        "gettxfromoutputhash",
        "\nReturns the transaction hash that contains the specified output hash.\n"
        "\nThis command searches through the blockchain and mempool to find which transaction contains an output with the given hash.\n"
        "\nWith -outindex enabled and synced, confirmed outputs (spent or not) are answered from the index.\n"
        "\nOtherwise an output that is still unspent is answered from the UTXO set, which names its block directly. An output already spent in a\n"
        "block is no longer in the UTXO set, so it is looked up by scanning the chain backwards from the tip, which is expensive.\n"
        "\nOn a pruned node the scan fails once it reaches a block whose data was pruned, rather than reporting the output as missing.\n",
        {
            {"outputhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hash of the output to search for"},
            {"include_mempool", RPCArg::Type::BOOL, RPCArg::Default{true}, "Include mempool transactions in the search"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                                              {RPCResult::Type::STR_HEX, "txid", "The transaction hash that contains the output"},
                                              {RPCResult::Type::NUM, "vout", "The output index within the transaction"},
                                              {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "The block hash containing the transaction (if confirmed)"},
                                              {RPCResult::Type::NUM, "confirmations", /*optional=*/true, "The number of confirmations (if confirmed)"},
                                          }},
        RPCExamples{HelpExampleCli("gettxfromoutputhash", "\"outputhash\"") + HelpExampleRpc("gettxfromoutputhash", "\"outputhash\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);

            uint256 output_hash = ParseHashV(request.params[0], "outputhash");
            bool include_mempool = request.params[1].isNull() ? true : request.params[1].get_bool();

            // BlockUntilSyncedToCurrentChain() requires cs_main to NOT be held
            if (g_txindex) {
                g_txindex->BlockUntilSyncedToCurrentChain();
            }

            // First, search in mempool if requested
            if (include_mempool && node.mempool) {
                LOCK(node.mempool->cs);
                for (const auto& entry : node.mempool->mapTx) {
                    const CTransaction& tx = *entry.GetSharedTx();
                    for (size_t i = 0; i < tx.vout.size(); i++) {
                        if (tx.vout[i].GetHash() == output_hash) {
                            UniValue result(UniValue::VOBJ);
                            result.pushKV("txid", tx.GetHash().GetHex());
                            result.pushKV("vout", (int)i);
                            result.pushKV("confirmations", 0);
                            return result;
                        }
                    }
                }
            }

            // The output index answers directly, including for outputs already
            // spent in a block. A synced index without an entry means the output
            // is not in the active chain, so there is nothing to scan for.
            {
                IndexedOutput indexed;
                switch (LookupIndexedOutput(chainman, output_hash, indexed)) {
                case OutIndexLookup::FOUND: {
                    const int tip_height{WITH_LOCK(cs_main, return chainman.ActiveChain().Height())};
                    UniValue result(UniValue::VOBJ);
                    result.pushKV("txid", indexed.tx->GetHash().GetHex());
                    result.pushKV("vout", (int)indexed.out_pos);
                    result.pushKV("blockhash", indexed.block_hash.GetHex());
                    result.pushKV("confirmations", 1 + tip_height - indexed.height);
                    return result;
                }
                case OutIndexLookup::NOT_FOUND:
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Output hash not found in blockchain or mempool");
                case OutIndexLookup::UNAVAILABLE:
                    break;
                }
            }

            // An outpoint on this chain is the bare output hash, so the UTXO set
            // can name the block that created any output not yet spent in a
            // block: Coin::nHeight is that block's height. Reading just that one
            // block answers the common lookup without touching the rest of the
            // chain. An output spent only by a mempool transaction is still in
            // CoinsTip, so it is covered here too.
            const CBlockIndex* coin_block{nullptr};
            const CBlockIndex* scan_tip{nullptr};
            int tip_height{0};
            {
                LOCK(cs_main);
                Chainstate& active_chainstate = chainman.ActiveChainstate();
                scan_tip = active_chainstate.m_chain.Tip();
                tip_height = active_chainstate.m_chain.Height();
                Coin coin;
                if (active_chainstate.CoinsTip().GetCoin(COutPoint(output_hash), coin)) {
                    coin_block = active_chainstate.m_chain[coin.nHeight];
                }
            }

            if (coin_block) {
                const OutputHashBlockRef ref{GetOutputHashBlockRef(chainman.m_blockman, *coin_block)};
                CBlock block;
                if (chainman.m_blockman.ReadBlockFromDisk(block, ref.pos)) {
                    if (auto result{FindOutputHashInBlock(block, output_hash, ref.hash, 1 + tip_height - ref.height)}) {
                        return *result;
                    }
                }
            }

            // Otherwise the output was spent in a block and is gone from the UTXO
            // set, so fall back to walking the chain backwards from the tip
            // captured above. cs_main is taken per block to resolve that block's
            // position on disk and dropped again before the read, so the scan
            // never holds the lock across disk I/O.
            for (const CBlockIndex* pindex = scan_tip; pindex != nullptr;) {
                const OutputHashBlockRef ref{GetOutputHashBlockRef(chainman.m_blockman, *pindex)};
                CBlock block;
                if (chainman.m_blockman.ReadBlockFromDisk(block, ref.pos)) {
                    if (auto result{FindOutputHashInBlock(block, output_hash, ref.hash, 1 + tip_height - ref.height)}) {
                        return *result;
                    }
                }
                pindex = ref.prev;
            }

            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Output hash not found in blockchain or mempool");
        },
    };
}

static RPCHelpMan getoutputinfo()
{
    return RPCHelpMan{
        "getoutputinfo",
        "\nReturns where a confirmed output was created and, if a block has spent it, where it was spent.\n"
        "\nRequires -outindex. Only the active chain is consulted: outputs created or spent only in the mempool are not reported.\n",
        {
            {"outputhash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hash of the output (its outpoint)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "txid", "The hash of the transaction that created the output"},
                {RPCResult::Type::NUM, "vout", "The output index within that transaction"},
                {RPCResult::Type::STR_HEX, "blockhash", "The hash of the block that created the output"},
                {RPCResult::Type::NUM, "height", "The height of that block"},
                {RPCResult::Type::NUM, "confirmations", "The number of confirmations of that block"},
                {RPCResult::Type::BOOL, "spent", "Whether a block in the active chain spends the output"},
                {RPCResult::Type::OBJ, "spentby", /*optional=*/true, "Where the output was spent (only if spent)", {
                    {RPCResult::Type::STR_HEX, "txid", "The hash of the spending transaction"},
                    {RPCResult::Type::NUM, "vin", "The input index within the spending transaction"},
                    {RPCResult::Type::STR_HEX, "blockhash", "The hash of the block that spent the output"},
                    {RPCResult::Type::NUM, "height", "The height of that block"},
                }},
            }},
        RPCExamples{HelpExampleCli("getoutputinfo", "\"outputhash\"") + HelpExampleRpc("getoutputinfo", "\"outputhash\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);

            const uint256 output_hash{ParseHashV(request.params[0], "outputhash")};

            if (!g_outindex) {
                throw JSONRPCError(RPC_MISC_ERROR, "Requires -outindex");
            }

            IndexedOutput indexed;
            switch (LookupIndexedOutput(chainman, output_hash, indexed)) {
            case OutIndexLookup::FOUND:
                break;
            case OutIndexLookup::NOT_FOUND:
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Output hash not found in blockchain");
            case OutIndexLookup::UNAVAILABLE:
                throw JSONRPCError(RPC_MISC_ERROR, "Output index is not in sync with the active chain yet");
            }

            const int tip_height{WITH_LOCK(cs_main, return chainman.ActiveChain().Height())};
            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", indexed.tx->GetHash().GetHex());
            result.pushKV("vout", (int)indexed.out_pos);
            result.pushKV("blockhash", indexed.block_hash.GetHex());
            result.pushKV("height", indexed.height);
            result.pushKV("confirmations", 1 + tip_height - indexed.height);
            result.pushKV("spent", indexed.spent.has_value());
            if (indexed.spent) {
                UniValue spentby(UniValue::VOBJ);
                spentby.pushKV("txid", indexed.spent->tx->GetHash().GetHex());
                spentby.pushKV("vin", (int)indexed.spent->in_pos);
                spentby.pushKV("blockhash", indexed.spent->block_hash.GetHex());
                spentby.pushKV("height", indexed.spent->height);
                result.pushKV("spentby", std::move(spentby));
            }
            return result;
        },
    };
}

void RegisterRawTransactionRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"rawtransactions", &getrawtransaction},
        {"rawtransactions", &createrawtransaction},
        {"rawtransactions", &decoderawtransaction},
        {"rawtransactions", &decodescript},
        {"rawtransactions", &combinerawtransaction},
        {"rawtransactions", &signrawtransactionwithkey},
        {"rawtransactions", &gettxfromoutputhash},
        {"rawtransactions", &getoutputinfo},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
