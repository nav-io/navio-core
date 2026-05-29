// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/public_key.h>
#include <p2pmsg/transport.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <univalue.h>
#include <util/strencodings.h>

static RPCHelpMan getp2pmsginfo()
{
    return RPCHelpMan{
        "getp2pmsginfo",
        "\nReturn state of the encrypted p2p messaging subsystem (debug).\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "enabled", "Whether the subsystem is active"},
                {RPCResult::Type::STR_HEX, "inbox_pubkey", /*optional=*/true, "This node's inbound session pubkey (peers encrypt to it)"},
                {RPCResult::Type::NUM, "pings_received", /*optional=*/true, "PING payloads decrypted and dispatched to us"},
            }},
        RPCExamples{HelpExampleCli("getp2pmsginfo", "") + HelpExampleRpc("getp2pmsginfo", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            UniValue obj(UniValue::VOBJ);
            p2pmsg::Transport* t = p2pmsg::GetActiveTransport();
            if (t == nullptr) {
                obj.pushKV("enabled", false);
                return obj;
            }
            obj.pushKV("enabled", true);
            obj.pushKV("inbox_pubkey", HexStr(t->InboxPubKey().GetVch()));
            obj.pushKV("pings_received", (uint64_t)t->PingsReceived());
            return obj;
        },
    };
}

static RPCHelpMan sendp2pping()
{
    return RPCHelpMan{
        "sendp2pping",
        "\nEncrypt a PING to the given inbox pubkey and broadcast it over p2pmsg (debug).\n",
        {
            {"inbox_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Recipient inbox pubkey (hex), from getp2pmsginfo"},
            {"stem", RPCArg::Type::BOOL, RPCArg::Default{true}, "Send via the Dandelion stem variant"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "Whether the message was queued for broadcast"},
        RPCExamples{HelpExampleCli("sendp2pping", "\"<hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            p2pmsg::Transport* t = p2pmsg::GetActiveTransport();
            if (t == nullptr) throw JSONRPCError(RPC_MISC_ERROR, "p2pmsg disabled");

            const std::vector<unsigned char> vch = ParseHex(request.params[0].get_str());
            blsct::PublicKey recipient;
            if (!recipient.SetVch(vch)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "invalid inbox_pubkey");
            }
            const bool stem = request.params[1].isNull() ? true : request.params[1].get_bool();

            t->Send(recipient, p2pmsg::PayloadKind::PING, /*body=*/{0x70, 0x69, 0x6e, 0x67}, stem);
            return true;
        },
    };
}

void RegisterP2PMsgRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"hidden", &getp2pmsginfo},
        {"hidden", &sendp2pping},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
