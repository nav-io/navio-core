# Seeds

`generate-seeds.py` turns the node list in `nodes_main.txt` into the fixed seeds
compiled into the client ([src/chainparamsseeds.h](/src/chainparamsseeds.h)).

The mainnet seeds compiled into the release are the Navio nodes listed by hand
in `nodes_main.txt`. Testnet has no fixed seeds. After editing the list, run the
following command from the `/contrib/seeds` directory (on a POSIX system, so the
header keeps LF line endings):

```
python3 generate-seeds.py . > ../../src/chainparamsseeds.h
```
