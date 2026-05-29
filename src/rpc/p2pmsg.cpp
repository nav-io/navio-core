// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/public_key.h>
#include <ctokens/tokenid.h>
#include <node/context.h>
#include <p2pmsg/transport.h>
#include <rfq/intent_store.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
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

static rfq::IntentStore& EnsureIntentStore(const JSONRPCRequest& request)
{
    node::NodeContext& node = EnsureAnyNodeContext(request.context);
    if (!node.rfq_intents) throw JSONRPCError(RPC_MISC_ERROR, "p2pmsg disabled");
    return *node.rfq_intents;
}

static RPCHelpMan setswapintent()
{
    return RPCHelpMan{
        "setswapintent",
        "\nConfigure a local swap intent: offer to pay out `token_in` for `token_out`.\n"
        "Never gossiped; used to answer matching RFQ requests.\n",
        {
            {"token_in", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Token the maker pays out (hex token hash, empty for NAV)"},
            {"token_out", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Token the maker wants to receive (hex, empty for NAV)"},
            {"min_size", RPCArg::Type::NUM, RPCArg::Optional::NO, "Minimum fill size"},
            {"max_size", RPCArg::Type::NUM, RPCArg::Optional::NO, "Maximum fill size"},
            {"price_min", RPCArg::Type::NUM, RPCArg::Optional::NO, "Minimum price, sell-units per buy-unit scaled by 1e8"},
            {"expiry", RPCArg::Type::NUM, RPCArg::Optional::NO, "Unix time the intent expires"},
        },
        RPCResult{RPCResult::Type::NUM, "intent_id", "The new intent's id"},
        RPCExamples{HelpExampleCli("setswapintent", "\"\" \"abcd...\" 100 1000 100000000 1893456000")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            rfq::IntentStore& store = EnsureIntentStore(request);
            auto parse_token = [](const UniValue& v) -> TokenId {
                const std::string s = v.get_str();
                if (s.empty()) return TokenId();
                return TokenId(uint256(ParseHashV(v, "token")));
            };
            TokenId in = parse_token(request.params[0]);
            TokenId out = parse_token(request.params[1]);
            const CAmount min_size = request.params[2].getInt<int64_t>();
            const CAmount max_size = request.params[3].getInt<int64_t>();
            const CAmount price_min = request.params[4].getInt<int64_t>();
            const int64_t expiry = request.params[5].getInt<int64_t>();
            if (min_size < 0 || max_size < min_size) throw JSONRPCError(RPC_INVALID_PARAMETER, "bad size band");
            return (uint64_t)store.Add(in, out, min_size, max_size, price_min, expiry);
        },
    };
}

static RPCHelpMan clearswapintent()
{
    return RPCHelpMan{
        "clearswapintent",
        "\nRemove a local swap intent by id.\n",
        {{"intent_id", RPCArg::Type::NUM, RPCArg::Optional::NO, "The intent id"}},
        RPCResult{RPCResult::Type::BOOL, "", "Whether an intent was removed"},
        RPCExamples{HelpExampleCli("clearswapintent", "1")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            rfq::IntentStore& store = EnsureIntentStore(request);
            return store.Clear(request.params[0].getInt<int64_t>());
        },
    };
}

static RPCHelpMan listswapintents()
{
    return RPCHelpMan{
        "listswapintents",
        "\nList all local swap intents.\n",
        {},
        RPCResult{RPCResult::Type::ARR, "", "", {{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "id", "Intent id"},
            {RPCResult::Type::STR_HEX, "token_in", "Token paid out"},
            {RPCResult::Type::STR_HEX, "token_out", "Token received"},
            {RPCResult::Type::NUM, "min_size", "Minimum fill"},
            {RPCResult::Type::NUM, "max_size", "Maximum fill"},
            {RPCResult::Type::NUM, "price_min", "Minimum price (scaled 1e8)"},
            {RPCResult::Type::NUM, "expiry", "Expiry unix time"},
        }}}},
        RPCExamples{HelpExampleCli("listswapintents", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            rfq::IntentStore& store = EnsureIntentStore(request);
            UniValue arr(UniValue::VARR);
            for (const auto& it : store.List()) {
                UniValue o(UniValue::VOBJ);
                o.pushKV("id", (uint64_t)it.id);
                o.pushKV("token_in", it.token_in.token.GetHex());
                o.pushKV("token_out", it.token_out.token.GetHex());
                o.pushKV("min_size", it.min_size);
                o.pushKV("max_size", it.max_size);
                o.pushKV("price_min", it.price_min);
                o.pushKV("expiry", it.expiry);
                arr.push_back(o);
            }
            return arr;
        },
    };
}

void RegisterP2PMsgRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"hidden", &getp2pmsginfo},
        {"hidden", &sendp2pping},
        {"p2pmsg", &setswapintent},
        {"p2pmsg", &clearswapintent},
        {"p2pmsg", &listswapintents},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
