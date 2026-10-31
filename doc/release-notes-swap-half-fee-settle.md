## Wallet RPC

- `acceptquotewallet`, `broadcastorder` and `replyquote` no longer hang when the
  NAV inputs of the wallet's swap half exactly cover what it pays in NAV, fee
  included, leaving zero NAV change. The half's fee calculation alternated
  forever between the fee with and without a change output, spinning the RPC
  thread. Such a half now pays the with-change fee, overpaying by one change
  output's weight.
