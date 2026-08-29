// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_WALLET_RPC_H
#define NAVIO_BLSCT_WALLET_RPC_H

#include <blsct/wallet/txfactory.h>
#include <script/script.h>
#include <span.h>

namespace wallet {
class CWallet;
typedef std::multimap<int64_t, CWalletOutput*> OutputItems;
} // namespace wallet

namespace blsct {
//! Sum of the wallet's confirmed staked commitments that carry a
//! stake-delegation payload.
CAmount GetDelegatedStakedBalance(const wallet::CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
UniValue SendTransaction(wallet::CWallet& wallet, const blsct::CreateTransactionData& transactionData, const bool& verbose, wallet::mapValue_t mapValue = {});
CScript BuildHTLCScript(
    const std::vector<unsigned char>& hash_bytes,
    const std::vector<unsigned char>& spendingKeyA,
    const std::vector<unsigned char>& spendingKeyB,
    int64_t locktime,
    opcodetype timelock_opcode = OP_CHECKLOCKTIMEVERIFY);
}

class CRPCCommand;
class RPCHelpMan;
Span<const CRPCCommand> GetBLSCTWalletRPCCommands();
RPCHelpMan sendtoblsctaddress();
RPCHelpMan getblsctoutput();
RPCHelpMan getbalanceforaddress();

#endif // NAVIO_BLSCT_WALLET_RPC_H
