## Updated settings

- `-p2pmsgstoresize` is now split into one budget per message scope: inbox (1:1
  messages to the node's prekey), session (replies to keys minted with
  `mintp2pmsgreplykey`) and broadcast (subscribed topics). The shares are set by
  `USER_STORE_INBOX_PERCENT`, `USER_STORE_SESSION_PERCENT` and
  `USER_STORE_BROADCAST_PERCENT` in `src/p2pmsg/user_inbox.h`. Each scope prunes
  only its own oldest messages when it is full, so a flood of one kind can no
  longer evict another. Previously broadcast messages were pruned first and
  inbox and session messages then shared whatever was left. With the default
  `-p2pmsgstoresize=64` the inbox and session scopes each keep about 25.6 MiB
  and the broadcast scope about 12.8 MiB.

- A node that receives only one kind of message now keeps only that scope's
  share of `-p2pmsgstoresize`, not the whole store. An inbox-only node that
  should keep as many messages as before needs a proportionally larger
  `-p2pmsgstoresize`.

- A store written by an earlier version that holds more than a scope's new share
  is not pruned at startup. The excess is pruned when the next message is stored
  after upgrading; until then `listp2pmsgs` keeps returning it.

## Updated RPCs

- `getp2pmsginfo` gained a `store` object, present when the user-message store
  is enabled, with `entries`, `bytes` and `last_id`: the highest message id
  assigned so far. Ids never repeat, so `last_id` is a cursor; pass it as
  `listp2pmsgs`' `since_id` to receive only messages stored from now on.

- `clearp2pmsgs` is unchanged, but its help now spells out how to use it safely:
  `0` (the default) drops every stored message, including ones that arrived
  after the client's last `listp2pmsgs`. To drop only what was read, pass the
  highest id `listp2pmsgs` returned, and skip the call when it returned nothing.
  Passing `last_id` drops everything stored by then, read or not.
