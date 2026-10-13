// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_P2PMSG_USER_DATA_H
#define BITCOIN_P2PMSG_USER_DATA_H

#include <p2pmsg/user_inbox.h>

#include <cstdint>
#include <functional>
#include <optional>

namespace p2pmsg {

struct InboundMessage;
class Transport;

//! An application message. The node parses only the frame's topic; the body
//! is stored untouched. Delivery rules by decrypting key:
//!  - our rotating inbox prekey: always stored (scope "inbox"),
//!  - a user reply key (mintp2pmsgreplykey): always stored ("session") — the
//!    key was minted deliberately to receive exactly this (internal session
//!    keys are not accepted, see RECIPIENTS_USER_DATA),
//!  - the well-known broadcast key: public pub/sub; stored only when the
//!    topic is subscribed ("broadcast"), so every public app's traffic does
//!    not accumulate on every node.
//!
//! Stores `m` in `inbox` at time `now` and returns the stored entry, or
//! std::nullopt when the message was dropped (malformed frame, invalid topic,
//! unsubscribed broadcast topic, or a store write that failed). Which key
//! classes reach this is the transport's decision, made by the set
//! RegisterUserDataHandler registers it with.
std::optional<UserInbox::Entry> StoreUserData(const InboundMessage& m, UserInbox& inbox, int64_t now);

//! Called on the p2pmsg worker for every entry StoreUserData stored.
using UserDataStoredFn = std::function<void(const UserInbox::Entry&)>;

//! Register the USER_DATA handler on `transport`: StoreUserData into `inbox`
//! under RECIPIENTS_USER_DATA, then `on_stored` (push notifiers) for each
//! stored entry.
void RegisterUserDataHandler(Transport& transport, UserInbox& inbox, UserDataStoredFn on_stored);

} // namespace p2pmsg

#endif // BITCOIN_P2PMSG_USER_DATA_H
