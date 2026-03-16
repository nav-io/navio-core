// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLSCT_WALLET_RPC_H
#define BITCOIN_BLSCT_WALLET_RPC_H

#include <blsct/wallet/txfactory.h>
#include <script/script.h>
#include <span.h>

namespace wallet {
class CWallet;
typedef std::multimap<int64_t, CWalletOutput*> OutputItems;
} // namespace wallet

namespace blsct {
UniValue SendTransaction(wallet::CWallet& wallet, const blsct::CreateTransactionData& transactionData, const bool& verbose);
CScript BuildHTLCScript(
    const std::vector<unsigned char>& hash_bytes,
    const std::vector<unsigned char>& spendingKeyA,
    const std::vector<unsigned char>& spendingKeyB,
    int64_t locktime);
}

class CRPCCommand;
class RPCHelpMan;
Span<const CRPCCommand> GetBLSCTWalletRPCCommands();
RPCHelpMan getblsctoutput();

#endif // BITCOIN_BLSCT_WALLET_RPC_H