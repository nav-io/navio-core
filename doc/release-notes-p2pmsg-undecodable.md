## Updated RPCs

- `getp2pmsginfo`'s `store` object gained `undecodable`: the number of messages
  on disk that this node cannot read, for example ones written under a different
  obfuscation key or an incompatible store format. They are kept rather than
  deleted, but are not returned by `listp2pmsgs` and are not counted in
  `entries`, `bytes` or toward `-p2pmsgstoresize`. Previously they showed only
  in a log line at startup.

- `clearp2pmsgs` still removes undecodable messages in its range and counts them
  in its result, so `removed` can exceed the number of messages `listp2pmsgs`
  returned. Its help now says so.
