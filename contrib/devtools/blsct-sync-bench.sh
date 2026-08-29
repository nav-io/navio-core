#!/usr/bin/env bash
# Copyright (c) 2026 The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Full-chain-sync benchmark for a naviod binary: re-validates every block
# already on disk in <datadir> (-reindex-chainstate, no network involved),
# waits for the tip, and prints the wall-clock plus the cumulative [bench]
# breakdown that validation.cpp logs for BLSCT work (range proofs, aggregate
# signatures, PoS set-membership proofs) so different backends / builds can
# be compared like-for-like.
#
# Usage: blsct-sync-bench.sh <naviod> <navio-cli> <datadir> [extra naviod args...]
#   e.g. blsct-sync-bench.sh build/bin/naviod build/bin/navio-cli ~/navio-mainnet
#        blsct-sync-bench.sh build-omp/bin/naviod build-omp/bin/navio-cli ~/navio-mainnet -par=4
#
# The datadir must already hold the chain (blocks/blk*.dat). Any node using it
# must be stopped first. RPC is bound to a private port so the run never
# collides with a regular node.
export LC_ALL=C

set -euo pipefail

NAVIOD=${1:?naviod path}
CLI=${2:?navio-cli path}
DATADIR=${3:?datadir}
shift 3
RPCPORT=${RPCPORT:-48499}
AUTH=(-datadir="$DATADIR" -rpcport="$RPCPORT" -rpcuser=bench -rpcpassword=bench)

# Target height = what the block index already knows (the previous sync's tip).
"$NAVIOD" "${AUTH[@]}" -listen=0 -connect=0 -dnsseed=0 -server=1 -printtoconsole=0 -daemon=0 -debug=bench "$@" &
NODE_PID=$!
trap 'kill "$NODE_PID" 2>/dev/null || true' EXIT
until "$CLI" "${AUTH[@]}" getblockcount >/dev/null 2>&1; do sleep 1; done
TARGET=$("$CLI" "${AUTH[@]}" getblockchaininfo | python3 -c 'import json,sys; print(json.load(sys.stdin)["headers"])')
"$CLI" "${AUTH[@]}" stop >/dev/null
wait "$NODE_PID" || true
echo "target height: $TARGET"

START=$(date +%s.%N)
"$NAVIOD" "${AUTH[@]}" -listen=0 -connect=0 -dnsseed=0 -server=1 -printtoconsole=0 -daemon=0 -debug=bench -reindex-chainstate "$@" &
NODE_PID=$!
trap 'kill "$NODE_PID" 2>/dev/null || true' EXIT
until "$CLI" "${AUTH[@]}" getblockcount >/dev/null 2>&1; do sleep 1; done
while :; do
    H=$("$CLI" "${AUTH[@]}" getblockcount 2>/dev/null || echo 0)
    if [ "$H" -ge "$TARGET" ]; then break; fi
    sleep 2
done
END=$(date +%s.%N)
"$CLI" "${AUTH[@]}" stop >/dev/null
wait "$NODE_PID" || true

python3 - "$DATADIR/debug.log" "$START" "$END" "$TARGET" <<'PY'
import re, sys, collections
log, start, end, target = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]), int(sys.argv[4])
wall = end - start
print(f"reindex-chainstate to height {target}: {wall:.1f}s wall ({wall * 1000 / max(target, 1):.2f} ms/block)")
# Cumulative [bench] counters are printed per block as "- <name>: X ms [TOTAL s (Y ms/blk)]".
# Keep the last TOTAL per name; range-proof batches are keyed by batch size, so sum those.
last = {}
setmem_ms = 0.0
setmem_n = 0
lines = open(log, errors="replace").read().splitlines()
# debug.log accumulates across runs: only look at the last node start.
starts = [i for i, l in enumerate(lines) if "Navio Core version" in l]
for line in lines[starts[-1] if starts else 0:]:
    m = re.search(r"\[bench\]\s+-+\s+(.*?): [\d.]+ms \[([\d.]+)s \([\d.]+ms/blk\)\]", line)
    if m:
        last[m.group(1).strip()] = float(m.group(2))
        continue
    m = re.search(r"pos setmem: sample=\d+ padded=\d+ setmem=([\d.]+)ms", line)
    if m:
        setmem_ms += float(m.group(1)); setmem_n += 1
rows = collections.OrderedDict()
for name in ("Connect block", "Connect total", "Verify block proofs/scripts", "BLSCT aggregate signatures",
             "BLSCT reward/stake tx collect", "Write undo data"):
    if name in last: rows[name] = last[name]
# One shared cumulative counter is printed under a per-batch-size label; take its latest value.
rp = [v for k, v in last.items() if k.startswith("BLSCT block rangeproof batch")]
rows["BLSCT block rangeproof batch (all sizes)"] = max(rp) if rp else 0.0
rows["PoS setmem (async worker CPU, summed)"] = setmem_ms / 1000.0
for k, tot in rows.items():
    print(f"  {k:45s} {tot:9.1f}s  {tot * 1000 / max(target, 1):7.2f} ms/blk")
if setmem_n: print(f"  (pos setmem samples: {setmem_n}, avg {setmem_ms / setmem_n:.2f} ms)")
PY
