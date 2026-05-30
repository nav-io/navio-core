// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <aggregation/combine.h>
#include <aggregation/pool.h>
#include <aggregation/session.h>
#include <blsct/public_key.h>
#include <blsct/wallet/txfactory_global.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <ctokens/tokenid.h>
#include <node/context.h>
#include <node/transaction.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <util/transaction_identifier.h>
#include <p2pmsg/transport.h>
#include <rfq/intent_store.h>
#include <rfq/order_cache.h>
#include <util/time.h>
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

static RPCHelpMan listorders()
{
    return RPCHelpMan{
        "listorders",
        "\nReport the standing-order cache state (debug).\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "enabled", "Whether the cache exists"},
            {RPCResult::Type::NUM, "count", /*optional=*/true, "Cached standing orders"},
            {RPCResult::Type::NUM, "bytes", /*optional=*/true, "Approximate cache footprint"},
        }},
        RPCExamples{HelpExampleCli("listorders", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            node::NodeContext& node = EnsureAnyNodeContext(request.context);
            UniValue o(UniValue::VOBJ);
            if (!node.rfq_orders) { o.pushKV("enabled", false); return o; }
            o.pushKV("enabled", true);
            o.pushKV("count", (uint64_t)node.rfq_orders->Size());
            o.pushKV("bytes", (uint64_t)node.rfq_orders->Bytes());
            return o;
        },
    };
}

static RPCHelpMan addaggregationcandidate()
{
    return RPCHelpMan{
        "addaggregationcandidate",
        "\nInject a fee-0 cover candidate half-transaction into the local pool (debug).\n"
        "Normally candidates arrive encrypted over the network; this is for testing.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The candidate half-transaction"},
            {"peer", RPCArg::Type::NUM, RPCArg::Default{0}, "Source peer id for per-peer accounting"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "Whether the candidate was accepted"},
        RPCExamples{HelpExampleCli("addaggregationcandidate", "\"<hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            node::NodeContext& node = EnsureAnyNodeContext(request.context);
            if (!node.agg_pool) throw JSONRPCError(RPC_MISC_ERROR, "p2pmsg disabled");
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, request.params[0].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }
            const int64_t peer = request.params[1].isNull() ? 0 : request.params[1].getInt<int64_t>();
            return node.agg_pool->AddCandidate(MakeTransactionRef(std::move(mtx)), peer);
        },
    };
}

static RPCHelpMan getaggregationhint()
{
    return RPCHelpMan{
        "getaggregationhint",
        "\nReturn the parameters a wallet needs to size an aggregated send: how\n"
        "many cover candidates are available and the per-candidate fee to add.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "enabled", "Whether the candidate pool exists"},
            {RPCResult::Type::NUM, "available", /*optional=*/true, "Candidates currently in the pool"},
            {RPCResult::Type::NUM, "candidate_weight", /*optional=*/true, "Assumed per-candidate weight for fee sizing"},
            {RPCResult::Type::NUM, "blsct_default_fee", /*optional=*/true, "Per-weight fee rate"},
            {RPCResult::Type::NUM, "extra_fee_per_candidate", /*optional=*/true, "candidate_weight * blsct_default_fee"},
        }},
        RPCExamples{HelpExampleCli("getaggregationhint", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            node::NodeContext& node = EnsureAnyNodeContext(request.context);
            UniValue o(UniValue::VOBJ);
            if (!node.agg_pool) { o.pushKV("enabled", false); return o; }
            const CAmount rate = BLSCT_DEFAULT_FEE;
            o.pushKV("enabled", true);
            o.pushKV("available", (uint64_t)node.agg_pool->Size());
            o.pushKV("candidate_weight", (int64_t)aggregation::CANDIDATE_WEIGHT_ESTIMATE);
            o.pushKV("blsct_default_fee", rate);
            o.pushKV("extra_fee_per_candidate", (CAmount)(aggregation::CANDIDATE_WEIGHT_ESTIMATE * rate));
            return o;
        },
    };
}

static RPCHelpMan getp2pmsgaggregate()
{
    return RPCHelpMan{
        "getp2pmsgaggregate",
        "\nAggregate a wallet-built BLSCT half-transaction with up to `max_candidates`\n"
        "fee-0 cover candidates from the node's pool, then broadcast it.\n"
        "The submitted half must already over-fund the fee to cover the combined\n"
        "weight (see getaggregationhint). Used candidates are evicted from the pool.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The wallet's signed own half-transaction"},
            {"max_candidates", RPCArg::Type::NUM, RPCArg::Default{16}, "Maximum cover candidates to merge"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "txid", "The broadcast aggregate transaction id"},
            {RPCResult::Type::NUM, "candidates_merged", "How many cover candidates were merged"},
        }},
        RPCExamples{HelpExampleCli("getp2pmsgaggregate", "\"<signedhalfhex>\" 16")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            node::NodeContext& node = EnsureAnyNodeContext(request.context);
            if (!node.agg_pool) throw JSONRPCError(RPC_MISC_ERROR, "p2pmsg disabled");

            CMutableTransaction own;
            if (!DecodeHexTx(own, request.params[0].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }
            size_t max_k = request.params[1].isNull() ? aggregation::POOL_MAX_COMBINED
                                                      : request.params[1].getInt<int64_t>();
            if (max_k > aggregation::POOL_MAX_COMBINED) max_k = aggregation::POOL_MAX_COMBINED;

            std::vector<CTransactionRef> halves;
            halves.push_back(MakeTransactionRef(own));
            for (const auto& c : node.agg_pool->PickForAggregate(max_k)) halves.push_back(c);

            auto combined = aggregation::CombineHalves(halves);
            if (!combined) throw JSONRPCError(RPC_VERIFY_ERROR, "combine failed (duplicate input?)");

            CTransactionRef tx = MakeTransactionRef(std::move(*combined));
            std::string err_string;
            const TransactionError err = node::BroadcastTransaction(
                node, tx, err_string, /*max_tx_fee=*/0, /*relay=*/true, /*wait_callback=*/true);
            if (TransactionError::OK != err) throw JSONRPCTransactionError(err, err_string);

            // Evict the candidates we just spent so they are not reused.
            size_t merged = halves.size() - 1;
            for (size_t i = 1; i < halves.size(); ++i) {
                for (const CTxIn& in : halves[i]->vin) node.agg_pool->EvictByInput(in.prevout);
            }

            UniValue o(UniValue::VOBJ);
            o.pushKV("txid", tx->GetHash().GetHex());
            o.pushKV("candidates_merged", (uint64_t)merged);
            return o;
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
        {"p2pmsg", &listorders},
        {"p2pmsg", &getaggregationhint},
        {"p2pmsg", &getp2pmsgaggregate},
        {"hidden", &addaggregationcandidate},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
