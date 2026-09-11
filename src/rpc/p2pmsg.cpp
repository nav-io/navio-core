// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <aggregation/combine.h>
#include <aggregation/pool.h>
#include <aggregation/pull.h>
#include <aggregation/session.h>
#include <blsct/arith/blst/blst_scalar.h>
#include <blsct/private_key.h>
#include <blsct/public_key.h>
#include <blsct/wallet/txfactory_global.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <ctokens/tokenid.h>
#include <net.h>
#include <node/context.h>
#include <node/transaction.h>
#include <protocol.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <util/transaction_identifier.h>
#include <p2pmsg/crypto.h>
#include <p2pmsg/transport.h>
#include <p2pmsg/user_inbox.h>
#include <rfq/intent_store.h>
#include <rfq/matcher.h>
#include <rfq/order_cache.h>
#include <rfq/quote.h>
#include <rfq/request.h>
#include <random.h>
#include <streams.h>
#include <util/time.h>

#include <algorithm>
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
                {RPCResult::Type::STR_HEX, "identity_pubkey", /*optional=*/true, "This node's stable identity pubkey (its address; signs the rotating prekey)"},
                {RPCResult::Type::STR_HEX, "inbox_pubkey", /*optional=*/true, "The current inbox PREKEY peers encrypt confidential messages to (rotates; authenticate it with prekey_sig under identity_pubkey)"},
                {RPCResult::Type::STR_HEX, "prekey_sig", /*optional=*/true, "identity_pubkey's signature over inbox_pubkey, so a fetched prekey can be verified as belonging to this identity"},
                {RPCResult::Type::NUM, "pings_received", /*optional=*/true, "PING payloads decrypted and dispatched to us"},
                {RPCResult::Type::NUM, "relay_capable_peers", /*optional=*/true, "Connected peers advertising NODE_P2PMSG (can relay the overlay for us). Note this is a lower bound on network participation: capability rides ADDR gossip, so many more nodes may be reachable indirectly."},
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
            obj.pushKV("identity_pubkey", HexStr(t->IdentityPubKey().GetVch()));
            obj.pushKV("inbox_pubkey", HexStr(t->InboxPubKey().GetVch()));
            obj.pushKV("prekey_sig", HexStr(t->PrekeySig().GetVch()));
            obj.pushKV("pings_received", (uint64_t)t->PingsReceived());
            node::NodeContext& node = EnsureAnyNodeContext(request.context);
            if (node.connman) {
                uint64_t capable = 0;
                node.connman->ForEachNode([&capable](CNode* pnode) {
                    if ((pnode->m_their_services.load() & NODE_P2PMSG) != 0) ++capable;
                });
                obj.pushKV("relay_capable_peers", capable);
            }
            return obj;
        },
    };
}

static RPCHelpMan rotatep2pmsginbox()
{
    return RPCHelpMan{
        "rotatep2pmsginbox",
        "\nRotate the p2p-messaging inbox prekey now (manual privacy reset). The\n"
        "stable node identity is unchanged; only the encryption prekey peers\n"
        "target is replaced and re-signed. The previous prekey stays decryptable\n"
        "for a short grace window so in-flight messages are not lost.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "inbox_pubkey", "The new inbox prekey"},
            {RPCResult::Type::STR_HEX, "prekey_sig", "identity's signature over the new prekey"},
        }},
        RPCExamples{HelpExampleCli("rotatep2pmsginbox", "") + HelpExampleRpc("rotatep2pmsginbox", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            p2pmsg::Transport* t = p2pmsg::GetActiveTransport();
            if (t == nullptr) throw JSONRPCError(RPC_MISC_ERROR, "p2pmsg disabled");
            t->RotatePrekey();
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("inbox_pubkey", HexStr(t->InboxPubKey().GetVch()));
            obj.pushKV("prekey_sig", HexStr(t->PrekeySig().GetVch()));
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

static p2pmsg::UserInbox& EnsureUserInbox(const JSONRPCRequest& request)
{
    node::NodeContext& node = EnsureAnyNodeContext(request.context);
    if (!node.p2pmsg_user_inbox) throw JSONRPCError(RPC_MISC_ERROR, "p2pmsg disabled");
    return *node.p2pmsg_user_inbox;
}

static RPCHelpMan sendp2pmsg()
{
    return RPCHelpMan{
        "sendp2pmsg",
        "\nEncrypt an application message to a recipient key and broadcast it over the p2pmsg bus.\n"
        "`recipient` selects the delivery mode:\n"
        " - an inbox (prekey) pubkey hex: confidential 1:1 delivery. Obtain it from the recipient's\n"
        "   getp2pmsginfo and verify its prekey_sig against their stable identity_pubkey.\n"
        " - a reply pubkey minted with mintp2pmsgreplykey on the other side: 1:1 delivery to that\n"
        "   one-shot session key (the RFQ reply pattern; does not expose the recipient's inbox).\n"
        " - the literal string \"broadcast\": public pub/sub — every node can read it, and nodes\n"
        "   SUBSCRIBED to `topic` (subscribep2pmsgtopic) store it.\n"
        "With stem propagation (default) observers cannot tell where a message entered the network.\n"
        "\nThe node interprets only `topic` (the pub/sub routing key). Everything else an application\n"
        "needs — sender identity, a reply key, threading, content type — must be framed inside the\n"
        "payload by the application; the transport deliberately adds no sender information.\n",
        {
            {"recipient", RPCArg::Type::STR, RPCArg::Optional::NO, "Recipient pubkey hex (inbox prekey or minted reply key), or \"broadcast\""},
            {"topic", RPCArg::Type::STR, RPCArg::Optional::NO, strprintf("Topic string, 1-%d bytes. Routing key for broadcast subscriptions and the store's filter column", p2pmsg::MAX_USER_MSG_TOPIC_BYTES)},
            {"payload", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, strprintf("Payload hex; topic and payload together must serialize to at most %d bytes. Applications needing more chunk and reassemble", p2pmsg::MAX_USER_MSG_BYTES)},
            {"stem", RPCArg::Type::BOOL, RPCArg::Default{true}, "Send via the Dandelion stem variant (hides the entry point)"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "Whether the message was queued for broadcast"},
        RPCExamples{HelpExampleCli("sendp2pmsg", "\"<inboxhex>\" \"chat\" \"<payloadhex>\"") +
                    HelpExampleCli("sendp2pmsg", "\"broadcast\" \"my-app-announce\" \"<payloadhex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            p2pmsg::Transport* t = p2pmsg::GetActiveTransport();
            if (t == nullptr) throw JSONRPCError(RPC_MISC_ERROR, "p2pmsg disabled");

            const std::string recipient_str = request.params[0].get_str();
            blsct::PublicKey recipient;
            if (recipient_str == "broadcast") {
                recipient = p2pmsg::BroadcastPubKey();
            } else if (!recipient.SetVch(ParseHex(recipient_str))) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "invalid recipient (pubkey hex or \"broadcast\")");
            }

            p2pmsg::UserMsgFrame frame;
            frame.topic = request.params[1].get_str();
            if (frame.topic.empty() || frame.topic.size() > p2pmsg::MAX_USER_MSG_TOPIC_BYTES) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   strprintf("topic must be 1-%d bytes", p2pmsg::MAX_USER_MSG_TOPIC_BYTES));
            }
            const auto body_hex = TryParseHex<uint8_t>(request.params[2].get_str());
            if (!body_hex) throw JSONRPCError(RPC_INVALID_PARAMETER, "payload is not valid hex");
            frame.body = *body_hex;
            if (frame.body.empty()) throw JSONRPCError(RPC_INVALID_PARAMETER, "payload must not be empty");

            DataStream ss;
            ss << frame;
            if (ss.size() > p2pmsg::MAX_USER_MSG_BYTES) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   strprintf("topic + payload serialize to %d bytes, max %d", ss.size(), p2pmsg::MAX_USER_MSG_BYTES));
            }
            const bool stem = request.params[3].isNull() ? true : request.params[3].get_bool();

            auto bytes = MakeUCharSpan(ss);
            t->Send(recipient, p2pmsg::PayloadKind::USER_DATA,
                    std::vector<uint8_t>(bytes.begin(), bytes.end()), stem);
            return true;
        },
    };
}

static RPCHelpMan mintp2pmsgreplykey()
{
    return RPCHelpMan{
        "mintp2pmsgreplykey",
        "\nMint a fresh one-shot session keypair and register it with the transport so USER_DATA\n"
        "messages encrypted to it are decrypted and stored (scope \"session\"). Hand the returned\n"
        "pubkey to a counterparty (e.g. framed inside a broadcast) to receive 1:1 replies without\n"
        "exposing this node's inbox prekey — the RFQ reply pattern, for applications.\n"
        "The key expires after `ttl` seconds and is then pruned; messages already stored remain.\n",
        {
            {"ttl", RPCArg::Type::NUM, RPCArg::Default{3600}, "Seconds the key stays registered (1-86400)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "reply_pubkey", "The minted session pubkey counterparties encrypt to"},
            {RPCResult::Type::NUM_TIME, "expiry", "Unix time the key is pruned"},
        }},
        RPCExamples{HelpExampleCli("mintp2pmsgreplykey", "600")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            p2pmsg::Transport* t = p2pmsg::GetActiveTransport();
            if (t == nullptr) throw JSONRPCError(RPC_MISC_ERROR, "p2pmsg disabled");

            const int64_t ttl = request.params[0].isNull() ? 3600 : request.params[0].getInt<int64_t>();
            if (ttl < 1 || ttl > 86400) throw JSONRPCError(RPC_INVALID_PARAMETER, "ttl must be 1-86400 seconds");

            const blsct::PrivateKey priv(BlstScalar::Rand(/*exclude_zero=*/true));
            const blsct::PublicKey pub = priv.GetPublicKey();
            const int64_t expiry = GetTime<std::chrono::seconds>().count() + ttl;
            t->AddSessionKey(pub, priv, expiry);

            UniValue o(UniValue::VOBJ);
            o.pushKV("reply_pubkey", HexStr(pub.GetVch()));
            o.pushKV("expiry", expiry);
            return o;
        },
    };
}

static RPCHelpMan subscribep2pmsgtopic()
{
    return RPCHelpMan{
        "subscribep2pmsgtopic",
        "\nSubscribe to a broadcast topic: broadcast USER_DATA messages carrying this topic are\n"
        "stored in the inbox (they are relayed either way). 1:1 inbox and session-keyed messages\n"
        "are always stored regardless of subscriptions. Persisted across restarts; seed at startup\n"
        "with -p2pmsgtopic=<topic>.\n",
        {
            {"topic", RPCArg::Type::STR, RPCArg::Optional::NO, strprintf("Topic string, 1-%d bytes", p2pmsg::MAX_USER_MSG_TOPIC_BYTES)},
        },
        RPCResult{RPCResult::Type::BOOL, "", "True if newly subscribed, false if already subscribed"},
        RPCExamples{HelpExampleCli("subscribep2pmsgtopic", "\"my-app-announce\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            p2pmsg::UserInbox& inbox = EnsureUserInbox(request);
            const std::string topic = request.params[0].get_str();
            if (topic.empty() || topic.size() > p2pmsg::MAX_USER_MSG_TOPIC_BYTES) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   strprintf("topic must be 1-%d bytes", p2pmsg::MAX_USER_MSG_TOPIC_BYTES));
            }
            return inbox.Subscribe(topic);
        },
    };
}

static RPCHelpMan unsubscribep2pmsgtopic()
{
    return RPCHelpMan{
        "unsubscribep2pmsgtopic",
        "\nUnsubscribe from a broadcast topic. Messages already stored remain until cleared or pruned.\n",
        {
            {"topic", RPCArg::Type::STR, RPCArg::Optional::NO, "Topic string"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "True if removed, false if it was not subscribed"},
        RPCExamples{HelpExampleCli("unsubscribep2pmsgtopic", "\"my-app-announce\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            p2pmsg::UserInbox& inbox = EnsureUserInbox(request);
            return inbox.Unsubscribe(request.params[0].get_str());
        },
    };
}

static RPCHelpMan listp2pmsgtopics()
{
    return RPCHelpMan{
        "listp2pmsgtopics",
        "\nList the broadcast topics this node is subscribed to.\n",
        {},
        RPCResult{RPCResult::Type::ARR, "", "", {{RPCResult::Type::STR, "topic", "A subscribed topic"}}},
        RPCExamples{HelpExampleCli("listp2pmsgtopics", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            p2pmsg::UserInbox& inbox = EnsureUserInbox(request);
            UniValue ret(UniValue::VARR);
            for (const auto& t : inbox.Topics()) ret.push_back(t);
            return ret;
        },
    };
}

static RPCHelpMan listp2pmsgs()
{
    return RPCHelpMan{
        "listp2pmsgs",
        "\nList stored USER_DATA messages, oldest first.\n"
        "Ids increase monotonically and never repeat, so a client can poll with the last id it has\n"
        "seen. The store is on disk and survives restarts; it is bounded by -p2pmsgstoresize (oldest\n"
        "pruned first) and -p2pmsgstoreexpiry. Multiple applications can read concurrently with their\n"
        "own cursors; clearp2pmsgs is optional early compaction, not an ack.\n",
        {
            {"since_id", RPCArg::Type::NUM, RPCArg::Default{0}, "Only return messages with id greater than this"},
            {"max_count", RPCArg::Type::NUM, RPCArg::Default{100}, "Maximum messages to return (0 = all)"},
            {"topic", RPCArg::Type::STR, RPCArg::Default{""}, "Only return messages with this topic (\"\" = all topics)"},
        },
        RPCResult{RPCResult::Type::ARR, "", "", {
            {RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::NUM, "id", "Monotonic message id (poll cursor)"},
                {RPCResult::Type::NUM_TIME, "received_at", "Local unix time the message was decrypted"},
                {RPCResult::Type::STR, "scope", "How the message reached us: \"inbox\" (1:1 to our prekey), \"broadcast\" (subscribed topic), or \"session\" (a minted reply key)"},
                {RPCResult::Type::STR, "topic", "The frame's topic"},
                {RPCResult::Type::STR_HEX, "sender_session", "The envelope's per-message ephemeral pubkey. Fresh every message by design; NOT a reply address — a reply key must be framed inside the payload"},
                {RPCResult::Type::STR_HEX, "payload", "The opaque payload body"},
            }},
        }},
        RPCExamples{HelpExampleCli("listp2pmsgs", "0 50") + HelpExampleCli("listp2pmsgs", "0 50 \"chat\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            p2pmsg::UserInbox& inbox = EnsureUserInbox(request);
            const int64_t since_raw = request.params[0].isNull() ? 0 : request.params[0].getInt<int64_t>();
            if (since_raw < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "since_id must be >= 0");
            const uint64_t since_id = static_cast<uint64_t>(since_raw);
            const int64_t max_raw = request.params[1].isNull() ? 100 : request.params[1].getInt<int64_t>();
            if (max_raw < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "max_count must be >= 0");
            const std::string topic = request.params[2].isNull() ? "" : request.params[2].get_str();

            UniValue ret(UniValue::VARR);
            for (const auto& e : inbox.List(since_id, static_cast<size_t>(max_raw), topic)) {
                UniValue o(UniValue::VOBJ);
                o.pushKV("id", e.id);
                o.pushKV("received_at", e.received_at);
                switch (static_cast<p2pmsg::MsgScope>(e.scope)) {
                case p2pmsg::MsgScope::BROADCAST: o.pushKV("scope", "broadcast"); break;
                case p2pmsg::MsgScope::SESSION: o.pushKV("scope", "session"); break;
                default: o.pushKV("scope", "inbox"); break;
                }
                o.pushKV("topic", e.topic);
                o.pushKV("sender_session", HexStr(e.sender_session));
                o.pushKV("payload", HexStr(e.payload));
                ret.push_back(o);
            }
            return ret;
        },
    };
}

static RPCHelpMan clearp2pmsgs()
{
    return RPCHelpMan{
        "clearp2pmsgs",
        "\nDrop stored USER_DATA messages up to a cursor. Optional early compaction — the store\n"
        "also prunes itself by -p2pmsgstoresize/-p2pmsgstoreexpiry.\n",
        {
            {"up_to_id", RPCArg::Type::NUM, RPCArg::Default{0}, "Drop messages with id up to and including this (0 = drop all)"},
        },
        RPCResult{RPCResult::Type::NUM, "removed", "How many messages were dropped"},
        RPCExamples{HelpExampleCli("clearp2pmsgs", "42")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            p2pmsg::UserInbox& inbox = EnsureUserInbox(request);
            const int64_t up_raw = request.params[0].isNull() ? 0 : request.params[0].getInt<int64_t>();
            if (up_raw < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "up_to_id must be >= 0");
            return static_cast<uint64_t>(inbox.Clear(static_cast<uint64_t>(up_raw)));
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
                const std::string& s = v.get_str();
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
            if (price_min < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "price_min must be non-negative");
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
            return node.agg_pool->AddCandidate(MakeTransactionRef(std::move(mtx)));
        },
    };
}

static RPCHelpMan listpendingcandidaterequests()
{
    return RPCHelpMan{
        "listpendingcandidaterequests",
        "\nFetch and REMOVE (one-shot) queued candidate pull requests received via\n"
        "AGG_ANN. Each entry is a requester's fresh reply session pubkey; answer\n"
        "it with the wallet RPC replycandidate, which sends a CANDIDATE_TX\n"
        "encrypted 1:1 to that key. Stale requests (older than the requester's\n"
        "reply-key TTL) are pruned, not returned.\n",
        {
            {"max", RPCArg::Type::NUM, RPCArg::Default{16}, "Maximum requests to claim"},
        },
        RPCResult{RPCResult::Type::ARR, "", "", {
            {RPCResult::Type::STR_HEX, "reply_pubkey", "A requester's reply session pubkey"},
        }},
        RPCExamples{HelpExampleCli("listpendingcandidaterequests", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            node::NodeContext& node = EnsureAnyNodeContext(request.context);
            if (!node.agg_requests) throw JSONRPCError(RPC_MISC_ERROR, "p2pmsg disabled");
            size_t max_n = request.params[0].isNull() ? 16 : request.params[0].getInt<int64_t>();
            if (max_n > aggregation::REQUEST_QUEUE_CAP) max_n = aggregation::REQUEST_QUEUE_CAP;
            const int64_t now = GetTime<std::chrono::seconds>().count();
            UniValue arr(UniValue::VARR);
            for (const auto& key : node.agg_requests->Claim(max_n, now)) {
                arr.push_back(HexStr(key.GetVch()));
            }
            return arr;
        },
    };
}

static RPCHelpMan sendcandidate()
{
    return RPCHelpMan{
        "sendcandidate",
        "\nEncrypt a cover candidate half-transaction to `reply_pubkey` and send it\n"
        "as a CANDIDATE_TX over p2pmsg (debug). The requester decrypts it under\n"
        "its registered pull session key and adds it to its candidate pool;\n"
        "recipients reject candidates not encrypted to one of their pull keys.\n",
        {
            {"reply_pubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Requester's reply session pubkey (from its AGG_ANN pull request)"},
            {"tx_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The candidate half-transaction"},
            {"stem", RPCArg::Type::BOOL, RPCArg::Default{true}, "Send via the Dandelion stem variant"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "Whether the message was queued for broadcast"},
        RPCExamples{HelpExampleCli("sendcandidate", "\"<inboxhex>\" \"<txhex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            p2pmsg::Transport* t = p2pmsg::GetActiveTransport();
            if (t == nullptr) throw JSONRPCError(RPC_MISC_ERROR, "p2pmsg disabled");

            blsct::PublicKey recipient;
            if (!recipient.SetVch(ParseHex(request.params[0].get_str()))) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "invalid reply_pubkey");
            }
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, request.params[1].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
            }
            const bool stem = request.params[2].isNull() ? true : request.params[2].get_bool();

            // Serialize the tx with witness params into the encrypted body.
            DataStream ss;
            ParamsStream ps{TX_WITH_WITNESS, ss};
            CTransactionRef tx = MakeTransactionRef(std::move(mtx));
            ps << tx;
            auto bytes = MakeUCharSpan(ss);
            std::vector<uint8_t> body(bytes.begin(), bytes.end());

            t->Send(recipient, p2pmsg::PayloadKind::CANDIDATE_TX, std::move(body), stem);
            return true;
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

            // Evict picked candidates whether the aggregate succeeds or not, so
            // a malformed/stale candidate cannot be re-picked on every call
            // (permanent DoS) and a used one cannot be double-spent.
            const size_t merged = halves.size() - 1;
            const auto evict_candidates = [&]() {
                for (size_t i = 1; i < halves.size(); ++i)
                    for (const CTxIn& in : halves[i]->vin) node.agg_pool->EvictByInput(in.prevout);
            };

            auto combined = aggregation::CombineHalves(halves);
            if (!combined) {
                evict_candidates();
                throw JSONRPCError(RPC_VERIFY_ERROR, "combine failed (duplicate input?)");
            }

            CTransactionRef tx = MakeTransactionRef(std::move(*combined));
            std::string err_string;
            const TransactionError err = node::BroadcastTransaction(
                node, tx, err_string, /*max_tx_fee=*/0, /*relay=*/true, /*wait_callback=*/true);
            if (TransactionError::OK != err) {
                evict_candidates();
                throw JSONRPCTransactionError(err, err_string);
            }

            evict_candidates();

            UniValue o(UniValue::VOBJ);
            o.pushKV("txid", tx->GetHash().GetHex());
            o.pushKV("candidates_merged", (uint64_t)merged);
            return o;
        },
    };
}

static rfq::MatcherRegistry& EnsureMatcher(const JSONRPCRequest& request)
{
    node::NodeContext& node = EnsureAnyNodeContext(request.context);
    if (!node.rfq_matcher) throw JSONRPCError(RPC_MISC_ERROR, "p2pmsg disabled");
    return *node.rfq_matcher;
}

static rfq::RfqRequest ParseRequestArgs(const JSONRPCRequest& request, const uint256& uuid,
                                        const blsct::PublicKey& reply_key)
{
    auto parse_token = [](const UniValue& v) -> TokenId {
        const std::string& s = v.get_str();
        if (s.empty()) return TokenId();
        return TokenId(uint256(ParseHashV(v, "token")));
    };
    rfq::RfqRequest r;
    r.uuid = uuid;
    r.buy = parse_token(request.params[0]);
    r.sell = parse_token(request.params[1]);
    r.size = request.params[2].getInt<int64_t>();
    r.expiry = request.params[3].getInt<int64_t>();
    r.reply_key = reply_key;
    if (r.size <= 0 || !MoneyRange(r.size)) throw JSONRPCError(RPC_INVALID_PARAMETER, "size out of range");
    return r;
}

static RPCHelpMan requestquote()
{
    return RPCHelpMan{
        "requestquote",
        "\nOpen a request-for-quote: collect maker quotes to buy `size` of `buy_token`\n"
        "paying with `sell_token`. Returns a uuid + the session pubkey makers encrypt\n"
        "their quotes to. (Broadcast over the wire is handled by the orchestrator.)\n",
        {
            {"buy_token", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Token to receive (hex, empty for NAV)"},
            {"sell_token", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Token to pay with (hex, empty for NAV)"},
            {"size", RPCArg::Type::NUM, RPCArg::Optional::NO, "Amount of buy_token wanted"},
            {"expiry", RPCArg::Type::NUM, RPCArg::Optional::NO, "Unix time the collection window closes"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "uuid", "Identifier for this request"},
            {RPCResult::Type::STR_HEX, "reply_key", "Session pubkey makers encrypt quotes to"},
        }},
        RPCExamples{HelpExampleCli("requestquote", "\"\" \"01...\" 100 1893456000")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            node::NodeContext& node = EnsureAnyNodeContext(request.context);
            if (!node.rfq_matcher || !node.p2pmsg_transport) throw JSONRPCError(RPC_MISC_ERROR, "p2pmsg disabled");

            const uint256 uuid = GetRandHash();
            // Mint a fresh per-request session keypair so makers' quotes are
            // encrypted to a key unlinkable to this node's inbox. Register the
            // private half with the transport so inbound RFQ_QUOTE messages
            // addressed to it are decrypted; it is auto-pruned at the request
            // expiry.
            const blsct::PrivateKey reply_priv(BlstScalar::Rand(/*exclude_zero=*/true));
            const blsct::PublicKey reply_key = reply_priv.GetPublicKey();
            rfq::RfqRequest r = ParseRequestArgs(request, uuid, reply_key);
            if (!node.rfq_matcher->OpenRequest(r)) throw JSONRPCError(RPC_MISC_ERROR, "uuid collision");
            node.p2pmsg_transport->AddSessionKey(reply_key, reply_priv, r.expiry);

            // Broadcast the request publicly over the bus (encrypted to the
            // well-known broadcast key so every node can read it). Makers that
            // hold a matching intent reply (encrypted to reply_key).
            DataStream ss;
            ss << r;
            auto bytes = MakeUCharSpan(ss);
            std::vector<uint8_t> body(bytes.begin(), bytes.end());
            node.p2pmsg_transport->Send(p2pmsg::BroadcastPubKey(),
                                        p2pmsg::PayloadKind::RFQ_REQ, std::move(body), /*stem=*/false);

            UniValue o(UniValue::VOBJ);
            o.pushKV("uuid", uuid.GetHex());
            o.pushKV("reply_key", HexStr(reply_key.GetVch()));
            return o;
        },
    };
}

static UniValue QuoteToUni(const rfq::RfqQuote& q)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("quote_id", q.quote_id.GetHex());
    // Surface the token pair: the taker must be able to see WHICH assets a quote
    // trades, not just the amounts. AddQuote rejects pair-mismatched quotes, but
    // showing buy/sell here lets a caller confirm the asset it will pay/receive.
    o.pushKV("buy", q.buy.ToString());
    o.pushKV("sell", q.sell.ToString());
    o.pushKV("fill", q.fill);
    o.pushKV("sell_cost", q.sell_cost);
    o.pushKV("price", q.Price());
    o.pushKV("order_expiry", q.order_expiry);
    return o;
}

static RPCHelpMan listquotes()
{
    return RPCHelpMan{
        "listquotes",
        "\nList quotes collected for an open RFQ, ranked cheapest-price first.\n",
        {
            {"uuid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The request uuid"},
            {"min_fill_ratio", RPCArg::Type::NUM, RPCArg::Default{1}, "Drop quotes filling less than this fraction of size"},
        },
        RPCResult{RPCResult::Type::ARR, "", "", {{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "quote_id", "Quote id"},
            {RPCResult::Type::STR, "buy", "Token delivered to the taker"},
            {RPCResult::Type::STR, "sell", "Token charged to the taker"},
            {RPCResult::Type::NUM, "fill", "Units of buy token offered"},
            {RPCResult::Type::NUM, "sell_cost", "Units of sell token charged"},
            {RPCResult::Type::NUM, "price", "sell_cost / fill"},
            {RPCResult::Type::NUM, "order_expiry", "Quote expiry"},
        }}}},
        RPCExamples{HelpExampleCli("listquotes", "\"<uuid>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            rfq::MatcherRegistry& reg = EnsureMatcher(request);
            const uint256 uuid(ParseHashV(request.params[0], "uuid"));
            auto req = reg.GetRequest(uuid);
            if (!req) throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown uuid");
            const double min_fill_ratio = request.params[1].isNull() ? 1.0 : request.params[1].get_real();

            auto quotes = reg.GetQuotes(uuid);
            // Rank: best (cheapest) first by repeatedly picking and removing.
            UniValue arr(UniValue::VARR);
            std::vector<rfq::RfqQuote> remaining = quotes;
            while (true) {
                auto best = rfq::PickBest(remaining, req->size, min_fill_ratio, rfq::RankBy::Price);
                if (!best) break;
                arr.push_back(QuoteToUni(*best));
                remaining.erase(std::remove_if(remaining.begin(), remaining.end(),
                    [&](const rfq::RfqQuote& q) { return q.quote_id == best->quote_id; }), remaining.end());
            }
            return arr;
        },
    };
}

static RPCHelpMan acceptquote()
{
    return RPCHelpMan{
        "acceptquote",
        "\nCombine the taker's signed half-transaction with a collected maker quote's\n"
        "half and broadcast the resulting swap. The taker half must already balance\n"
        "the multi-TokenId sums and fund the fee for the combined weight.\n",
        {
            {"uuid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The request uuid"},
            {"quote_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The chosen quote id"},
            {"taker_half_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The taker's signed half"},
        },
        RPCResult{RPCResult::Type::STR_HEX, "txid", "The broadcast swap transaction id"},
        RPCExamples{HelpExampleCli("acceptquote", "\"<uuid>\" \"<quote_id>\" \"<takerhalfhex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            node::NodeContext& node = EnsureAnyNodeContext(request.context);
            if (!node.rfq_matcher) throw JSONRPCError(RPC_MISC_ERROR, "p2pmsg disabled");
            const uint256 uuid(ParseHashV(request.params[0], "uuid"));
            const uint256 quote_id(ParseHashV(request.params[1], "quote_id"));

            auto quote = node.rfq_matcher->GetQuote(uuid, quote_id);
            if (!quote || !quote->half_tx) throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown quote");

            CMutableTransaction taker;
            if (!DecodeHexTx(taker, request.params[2].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "taker half decode failed");
            }

            std::vector<CTransactionRef> halves{MakeTransactionRef(taker), quote->half_tx};
            auto combined = aggregation::CombineHalves(halves);
            if (!combined) throw JSONRPCError(RPC_VERIFY_ERROR, "combine failed");

            CTransactionRef tx = MakeTransactionRef(std::move(*combined));
            std::string err_string;
            const TransactionError err = node::BroadcastTransaction(
                node, tx, err_string, /*max_tx_fee=*/0, /*relay=*/true, /*wait_callback=*/true);
            if (TransactionError::OK != err) throw JSONRPCTransactionError(err, err_string);

            node.rfq_matcher->Cancel(uuid); // one-shot per request
            return tx->GetHash().GetHex();
        },
    };
}

static RPCHelpMan listrfqs()
{
    return RPCHelpMan{
        "listrfqs", "\nList open RFQ request uuids.\n", {},
        RPCResult{RPCResult::Type::ARR, "", "", {{RPCResult::Type::STR_HEX, "uuid", "Open request uuid"}}},
        RPCExamples{HelpExampleCli("listrfqs", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            rfq::MatcherRegistry& reg = EnsureMatcher(request);
            UniValue arr(UniValue::VARR);
            for (const auto& uuid : reg.ListRequests()) arr.push_back(uuid.GetHex());
            return arr;
        },
    };
}

static RPCHelpMan cancelrfq()
{
    return RPCHelpMan{
        "cancelrfq", "\nCancel an open RFQ, discarding its collected quotes.\n",
        {{"uuid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The request uuid"}},
        RPCResult{RPCResult::Type::BOOL, "", "Whether a request was cancelled"},
        RPCExamples{HelpExampleCli("cancelrfq", "\"<uuid>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            rfq::MatcherRegistry& reg = EnsureMatcher(request);
            return reg.Cancel(uint256(ParseHashV(request.params[0], "uuid")));
        },
    };
}

static RPCHelpMan addrfqquote()
{
    return RPCHelpMan{
        "addrfqquote",
        "\nInject a maker quote for an open RFQ (debug). Normally quotes arrive\n"
        "encrypted over the network.\n",
        {
            {"uuid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The request uuid"},
            {"quote_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Unique quote id"},
            {"fill", RPCArg::Type::NUM, RPCArg::Optional::NO, "Units of buy token offered"},
            {"sell_cost", RPCArg::Type::NUM, RPCArg::Optional::NO, "Units of sell token charged"},
            {"half_tx_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Maker's half-transaction"},
            {"order_expiry", RPCArg::Type::NUM, RPCArg::Default{0}, "Quote expiry"},
        },
        RPCResult{RPCResult::Type::BOOL, "", "Whether the quote was accepted"},
        RPCExamples{HelpExampleCli("addrfqquote", "\"<uuid>\" \"<qid>\" 1000 100 \"<halfhex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            rfq::MatcherRegistry& reg = EnsureMatcher(request);
            rfq::RfqQuote q;
            q.uuid = uint256(ParseHashV(request.params[0], "uuid"));
            q.quote_id = uint256(ParseHashV(request.params[1], "quote_id"));
            q.fill = request.params[2].getInt<int64_t>();
            q.sell_cost = request.params[3].getInt<int64_t>();
            if (q.fill < 0 || !MoneyRange(q.fill) || q.sell_cost < 0 || !MoneyRange(q.sell_cost)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "fill/sell_cost out of range");
            }
            // Echo the open request's token pair so OrderCache matching and the
            // taker's re-validation see a self-describing quote.
            if (auto req = reg.GetRequest(q.uuid)) {
                q.buy = req->buy;
                q.sell = req->sell;
            }
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, request.params[4].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "half decode failed");
            }
            q.half_tx = MakeTransactionRef(std::move(mtx));
            q.order_expiry = request.params[5].isNull() ? 0 : request.params[5].getInt<int64_t>();
            return reg.AddQuote(q);
        },
    };
}

static RPCHelpMan listpendingquoterequests()
{
    return RPCHelpMan{
        "listpendingquoterequests",
        "\nList inbound RFQ requests that matched one of this node's local swap\n"
        "intents and are awaiting a wallet reply (see replyquote).\n",
        {},
        RPCResult{RPCResult::Type::ARR, "", "", {{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "uuid", "The request uuid"},
            {RPCResult::Type::STR_HEX, "buy_token", "Token the taker wants (we deliver)"},
            {RPCResult::Type::STR_HEX, "sell_token", "Token the taker pays (we receive)"},
            {RPCResult::Type::NUM, "fill", "Amount of buy_token to deliver"},
            {RPCResult::Type::NUM, "sell_cost", "Amount of sell_token to charge"},
            {RPCResult::Type::STR_HEX, "reply_key", "Encrypt the quote to this key"},
        }}}},
        RPCExamples{HelpExampleCli("listpendingquoterequests", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            node::NodeContext& node = EnsureAnyNodeContext(request.context);
            if (!node.rfq_matcher) throw JSONRPCError(RPC_MISC_ERROR, "p2pmsg disabled");
            UniValue arr(UniValue::VARR);
            for (const auto& pm : node.rfq_matcher->ListPendingMatches()) {
                UniValue o(UniValue::VOBJ);
                o.pushKV("uuid", pm.req.uuid.GetHex());
                o.pushKV("buy_token", pm.req.buy.token.GetHex());
                o.pushKV("sell_token", pm.req.sell.token.GetHex());
                o.pushKV("fill", pm.fill);
                o.pushKV("sell_cost", pm.sell_cost);
                o.pushKV("reply_key", HexStr(pm.req.reply_key.GetVch()));
                arr.push_back(o);
            }
            return arr;
        },
    };
}

static RPCHelpMan sendquote()
{
    return RPCHelpMan{
        "sendquote",
        "\nSend an externally built maker quote for an RFQ request over the p2pmsg\n"
        "bus. The caller (e.g. a light wallet that built and signed its own\n"
        "unbalanced half-transaction) supplies the half and the economic terms;\n"
        "this node wraps them in a quote, authenticates it under its session\n"
        "identity, encrypts it to the requester's reply key and broadcasts it.\n"
        "If the uuid matches a pending matched request on this node (see\n"
        "listpendingquoterequests) the pending entry is consumed.\n",
        {
            {"uuid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The RFQ request uuid being answered"},
            {"reply_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The requester's reply session pubkey (from the RFQ request)"},
            {"half_tx_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The maker's signed unbalanced half-transaction"},
            {"buy_token", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Token delivered to the taker (hex, empty for NAV)"},
            {"sell_token", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Token charged to the taker (hex, empty for NAV)"},
            {"fill", RPCArg::Type::NUM, RPCArg::Optional::NO, "Units of buy_token delivered"},
            {"sell_cost", RPCArg::Type::NUM, RPCArg::Optional::NO, "Units of sell_token charged"},
            {"order_expiry", RPCArg::Type::NUM, RPCArg::Optional::NO, "Unix time the quote expires"},
        },
        RPCResult{RPCResult::Type::STR_HEX, "quote_id", "Identifier of the sent quote"},
        RPCExamples{HelpExampleCli("sendquote", "\"<uuid>\" \"<replykeyhex>\" \"<halfhex>\" \"\" \"01...\" 100000000 10000000 1893456000")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            node::NodeContext& node = EnsureAnyNodeContext(request.context);
            p2pmsg::Transport* transport = p2pmsg::GetActiveTransport();
            if (!transport) throw JSONRPCError(RPC_MISC_ERROR, "p2pmsg disabled");

            const uint256 uuid(ParseHashV(request.params[0], "uuid"));
            blsct::PublicKey reply_key;
            if (!reply_key.SetVch(ParseHex(request.params[1].get_str()))) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "invalid reply_key");
            }
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, request.params[2].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "half decode failed");
            }
            auto parse_token = [](const UniValue& v) -> TokenId {
                const std::string& s = v.get_str();
                if (s.empty()) return TokenId();
                return TokenId(uint256(ParseHashV(v, "token")));
            };

            rfq::RfqQuote q;
            q.uuid = uuid;
            q.quote_id = GetRandHash();
            q.half_tx = MakeTransactionRef(std::move(mtx));
            q.buy = parse_token(request.params[3]);
            q.sell = parse_token(request.params[4]);
            q.fill = request.params[5].getInt<int64_t>();
            q.sell_cost = request.params[6].getInt<int64_t>();
            q.order_expiry = request.params[7].getInt<int64_t>();
            if (q.fill <= 0 || !MoneyRange(q.fill) || q.sell_cost <= 0 || !MoneyRange(q.sell_cost)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "fill/sell_cost out of range");
            }
            // Fresh single-use signing key: unlinkable from our other quotes.
            std::tie(q.session_eph, q.maker_sig) = transport->SignEphemeral(q.SigningHash());

            // One-shot: if this node queued the request as a pending local match,
            // consume it so a maker driving this RPC does not answer twice.
            if (node.rfq_matcher) node.rfq_matcher->TakePendingMatch(uuid);

            DataStream ss;
            ParamsStream ps{TX_WITH_WITNESS, ss};
            ps << q;
            auto bytes = MakeUCharSpan(ss);
            std::vector<uint8_t> body(bytes.begin(), bytes.end());
            transport->Send(reply_key, p2pmsg::PayloadKind::RFQ_QUOTE, std::move(body), /*stem=*/false);

            return q.quote_id.GetHex();
        },
    };
}

static RPCHelpMan sendorder()
{
    return RPCHelpMan{
        "sendorder",
        "\nPublish an externally built standing swap order over the p2pmsg bus.\n"
        "The caller (e.g. a light wallet) supplies its signed unbalanced\n"
        "half-transaction offering `offer_amount` of `offer_token` for\n"
        "`want_amount` of `want_token`; this node wraps it in a quote,\n"
        "authenticates it under its session identity, caches it locally and\n"
        "broadcasts it as an ORDER_ANN so peers can answer RFQs on the maker's\n"
        "behalf while the maker is offline.\n",
        {
            {"half_tx_hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The maker's signed unbalanced half-transaction"},
            {"offer_token", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Token the maker offers (hex, empty for NAV)"},
            {"offer_amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Units of offer_token delivered to the taker"},
            {"want_token", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Token the maker wants (hex, empty for NAV)"},
            {"want_amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "Units of want_token charged to the taker"},
            {"expiry", RPCArg::Type::NUM, RPCArg::Optional::NO, "Unix time the order expires (capped to 14 days)"},
        },
        RPCResult{RPCResult::Type::STR_HEX, "quote_id", "Identifier of the broadcast standing order"},
        RPCExamples{HelpExampleCli("sendorder", "\"<halfhex>\" \"\" 100000000 \"01...\" 10000000 1893456000")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            p2pmsg::Transport* transport = p2pmsg::GetActiveTransport();
            rfq::OrderCache* orders = rfq::GetActiveOrderCache();
            if (!transport || !orders) throw JSONRPCError(RPC_MISC_ERROR, "p2pmsg disabled");

            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, request.params[0].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "half decode failed");
            }
            auto parse_token = [](const UniValue& v) -> TokenId {
                const std::string& s = v.get_str();
                if (s.empty()) return TokenId();
                return TokenId(uint256(ParseHashV(v, "token")));
            };

            rfq::RfqQuote q;
            q.uuid = uint256(); // standing order: bound to an RFQ at match time
            q.quote_id = GetRandHash();
            q.half_tx = MakeTransactionRef(std::move(mtx));
            q.buy = parse_token(request.params[1]);
            q.sell = parse_token(request.params[3]);
            q.fill = request.params[2].getInt<int64_t>();
            q.sell_cost = request.params[4].getInt<int64_t>();
            q.order_expiry = request.params[5].getInt<int64_t>();
            if (q.fill <= 0 || !MoneyRange(q.fill) || q.sell_cost <= 0 || !MoneyRange(q.sell_cost)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "offer_amount/want_amount out of range");
            }
            // Fresh single-use signing key: unlinkable from our other quotes.
            std::tie(q.session_eph, q.maker_sig) = transport->SignEphemeral(q.SigningHash());

            const int64_t now = GetTime<std::chrono::seconds>().count();
            if (!orders->StoreOrder(q, now)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "order rejected (expired, duplicate, or input conflict)");
            }

            DataStream ss;
            ParamsStream ps{TX_WITH_WITNESS, ss};
            ps << q;
            auto bytes = MakeUCharSpan(ss);
            std::vector<uint8_t> body(bytes.begin(), bytes.end());
            transport->Send(p2pmsg::BroadcastPubKey(), p2pmsg::PayloadKind::ORDER_ANN,
                            std::move(body), /*stem=*/false);

            return q.quote_id.GetHex();
        },
    };
}

void RegisterP2PMsgRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"hidden", &getp2pmsginfo},
        {"hidden", &rotatep2pmsginbox},
        {"p2pmsg", &listpendingquoterequests},
        {"hidden", &sendp2pping},
        {"p2pmsg", &sendp2pmsg},
        {"p2pmsg", &listp2pmsgs},
        {"p2pmsg", &clearp2pmsgs},
        {"p2pmsg", &mintp2pmsgreplykey},
        {"p2pmsg", &subscribep2pmsgtopic},
        {"p2pmsg", &unsubscribep2pmsgtopic},
        {"p2pmsg", &listp2pmsgtopics},
        {"p2pmsg", &setswapintent},
        {"p2pmsg", &clearswapintent},
        {"p2pmsg", &listswapintents},
        {"p2pmsg", &listorders},
        {"p2pmsg", &getaggregationhint},
        {"p2pmsg", &getp2pmsgaggregate},
        {"p2pmsg", &listpendingcandidaterequests},
        {"hidden", &addaggregationcandidate},
        {"hidden", &sendcandidate},
        {"p2pmsg", &requestquote},
        {"p2pmsg", &listquotes},
        {"p2pmsg", &acceptquote},
        {"p2pmsg", &listrfqs},
        {"p2pmsg", &cancelrfq},
        {"hidden", &addrfqquote},
        {"p2pmsg", &sendquote},
        {"p2pmsg", &sendorder},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
