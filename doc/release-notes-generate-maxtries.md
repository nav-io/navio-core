## Updated RPCs

- `generatetoaddress` and `generatetoblsctaddress` now refuse a negative
  `maxtries` ("JSON integer out of range"), as `generatetodescriptor` already
  did. Before, a negative value wrapped around into a practically unlimited
  number of tries. A `maxtries` above 2147483647, which used to be refused, is
  now accepted.
