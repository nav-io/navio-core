P2P and network changes
-----------------------

- Each `p2pmsg` kind is now accepted only when it decrypts under the recipient
  key class listed below. A message that decrypts under any other class is
  dropped before its handler runs and logged under the `net` debug category.
  Relay is unchanged: every kind is still relayed whether or not the node can
  decrypt it. SDKs and light makers must encrypt each kind to the key class
  shown here, or the receiving node discards it.

  | Kind           | Value | Accepted under                                                            |
  | -------------- | ----- | ------------------------------------------------------------------------- |
  | `PING`         | 0     | inbox key                                                                 |
  | `PONG`         | 1     | none: no local handler, relayed only                                      |
  | `AGG_ANN`      | 2     | broadcast key                                                             |
  | `CANDIDATE_TX` | 3     | internal session key carried by the pull request                          |
  | `RFQ_REQ`      | 4     | broadcast key                                                             |
  | `RFQ_QUOTE`    | 5     | internal session key carried by the RFQ request                           |
  | `ORDER_ANN`    | 6     | broadcast key                                                             |
  | `USER_DATA`    | 7     | inbox key, broadcast key, or a reply key minted with `mintp2pmsgreplykey` |

  "Inbox key" includes the previous inbox keys a node still holds for a grace
  period after rotating its prekey. `USER_DATA` is only handled while the
  message store is enabled (`-p2pmsgstoresize` above 0); otherwise it is dropped
  like any kind without a handler.

  A reply key minted with `mintp2pmsgreplykey` is accepted for `USER_DATA` only,
  and an internal session key is never accepted for `USER_DATA`.
