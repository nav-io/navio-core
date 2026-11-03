### QoS (Quality of service)

This is a Linux bash script that will set up tc to limit the outgoing bandwidth
for connections to the Navio network. It limits outbound TCP traffic with a
source or destination port of `PORT` (set in the script to the Navio mainnet P2P
port), but not if the destination IP is within a LAN.

This means one can have an always-on naviod instance running, and another local
naviod instance which connects to this node and receives blocks from it.
