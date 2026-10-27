## Updated RPCs

- `generatetoaddress` and `generatetoblsctaddress` now refuse a negative
  `maxtries` ("JSON integer out of range"), as `generatetodescriptor` already
  did. Before, a negative value wrapped around into a practically unlimited
  number of tries.
