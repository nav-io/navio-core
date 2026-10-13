// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <p2pmsg/user_data.h>

#include <logging.h>
#include <p2pmsg/transport.h>
#include <span.h>
#include <streams.h>
#include <util/time.h>

#include <chrono>
#include <exception>
#include <utility>
#include <vector>

namespace p2pmsg {

std::optional<UserInbox::Entry> StoreUserData(const InboundMessage& m, UserInbox& inbox, int64_t now)
{
    if (m.body.empty() || m.body.size() > MAX_USER_MSG_BYTES) return std::nullopt;
    UserMsgFrame frame;
    try {
        DataStream ss{MakeByteSpan(m.body)};
        ss >> frame;
        if (!ss.empty()) return std::nullopt; // trailing bytes: malformed
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (frame.topic.empty() || frame.topic.size() > MAX_USER_MSG_TOPIC_BYTES) return std::nullopt;
    if (!IsValidTopic(frame.topic)) return std::nullopt; // network-controlled; keep RPC/JSON output valid
    if (frame.body.empty()) return std::nullopt;

    MsgScope scope{MsgScope::INBOX};
    std::vector<uint8_t> reply_pubkey;
    switch (m.recipient) {
    case RecipientKey::INBOX: scope = MsgScope::INBOX; break;
    case RecipientKey::SESSION:
        // A user reply key: the transport drops USER_DATA
        // under an internal session key before this runs.
        scope = MsgScope::SESSION;
        reply_pubkey = m.recipient_session.GetVch();
        break;
    case RecipientKey::BROADCAST:
        if (!inbox.IsSubscribed(frame.topic)) return std::nullopt;
        scope = MsgScope::BROADCAST;
        break;
    }

    try {
        return inbox.Add(now, scope, frame.topic, m.sender_session, std::move(frame.body), reply_pubkey);
    } catch (const std::exception& e) {
        // CDBWrapper throws dbwrapper_error on any LevelDB
        // failure (e.g. full disk). This handler runs on a
        // p2pmsg worker with no try/catch above it, so an
        // escape is std::terminate for the whole node --
        // one inbound message must never be able to do
        // that. Drop the message and log.
        LogPrintf("p2pmsg: user inbox store failed, message dropped: %s\n", e.what());
        return std::nullopt;
    }
}

void RegisterUserDataHandler(Transport& transport, UserInbox& inbox, UserDataStoredFn on_stored)
{
    transport.RegisterHandler(
        PayloadKind::USER_DATA, RECIPIENTS_USER_DATA,
        [&inbox, on_stored = std::move(on_stored)](const InboundMessage& m) {
            const std::optional<UserInbox::Entry> stored =
                StoreUserData(m, inbox, GetTime<std::chrono::seconds>().count());
            if (!stored) return;
            on_stored(*stored);
        });
}

} // namespace p2pmsg
