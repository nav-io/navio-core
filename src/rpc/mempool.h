// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_MEMPOOL_H
#define BITCOIN_RPC_MEMPOOL_H

class CTxMemPool;
class UniValue;

/** Mempool information to JSON */
UniValue MempoolInfoToJSON(const CTxMemPool& pool);

/** Mempool to JSON */
UniValue MempoolToJSON(const CTxMemPool& pool, bool verbose = false, bool include_mempool_sequence = false);

/** Stempool information to JSON */
UniValue StempoolInfoToJSON(const CTxMemPool& pool);

/** Stempool to JSON */
UniValue StempoolToJSON(const CTxMemPool& pool, bool verbose = false, bool include_stempool_sequence = false);

#endif // BITCOIN_RPC_MEMPOOL_H
