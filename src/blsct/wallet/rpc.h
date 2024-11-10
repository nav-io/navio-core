// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLSCT_WALLET_RPC_H
#define BITCOIN_BLSCT_WALLET_RPC_H

#include <blsct/wallet/txfactory.h>
#include <span.h>

namespace wallet {
class CWallet;
}

namespace blsct {
UniValue SendTransaction(wallet::CWallet& wallet, const blsct::CreateTransactionData& transactionData, const bool& verbose);
}

class CRPCCommand;

Span<const CRPCCommand> GetBLSCTWalletRPCCommands();

#endif // BITCOIN_BLSCT_WALLET_RPC_H