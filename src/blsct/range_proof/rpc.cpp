// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/balance_proof.h>
#include <blsct/wallet/rpc.h>
#include <blsct/wallet/unsigned_transaction.h>
#include <coins.h>
#include <core_io.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <univalue.h>
#include <validation.h>

RPCHelpMan verifyblsctbalanceproof()
{
    return RPCHelpMan{
        "verifyblsctbalanceproof",
        "Verifies a zero-knowledge balance proof\n",
        {
            {"proof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The serialized balance proof"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                                              {RPCResult::Type::BOOL, "valid", "Whether the proof is valid"},
                                              {RPCResult::Type::NUM, "min_amount", "The minimum amount proven"},
                                          }},
        RPCExamples{HelpExampleCli("verifyblsctbalanceproof", "\"<hex>\"") + HelpExampleRpc("verifyblsctbalanceproof", "\"<hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            LOCK(cs_main);
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            Chainstate& active_chainstate = chainman.ActiveChainstate();

            CCoinsViewCache* coins_view;
            coins_view = &active_chainstate.CoinsTip();

            // Deserialize the proof
            std::vector<unsigned char> proof_data = ParseHex(request.params[0].get_str());
            DataStream ss{proof_data};
            blsct::BalanceProof proof;
            try {
                ss >> proof;
            } catch (const std::exception) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid proof format");
            }

            // Verify the proof
            bool valid = proof.Verify(coins_view);

            UniValue result(UniValue::VOBJ);
            result.pushKV("valid", valid);
            result.pushKV("min_amount", ValueFromAmount(proof.GetMinAmount()));

            return result;
        },
    };
}

void RegisterRangeProofRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"blsct", &verifyblsctbalanceproof},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}

Span<const CRPCCommand> GetRangeProofRPCCommands()
{
    static const CRPCCommand commands[]{
        {"blsct", &verifyblsctbalanceproof},
    };
    return commands;
}