// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVIO_BLSCT_WALLET_RPC_H
#define NAVIO_BLSCT_WALLET_RPC_H

#include <blsct/public_key.h>
#include <blsct/wallet/txfactory.h>
#include <script/script.h>
#include <span.h>
#include <uint256.h>

#include <memory>
#include <optional>
#include <vector>

namespace wallet {
class CWallet;
typedef std::multimap<int64_t, CWalletOutput*> OutputItems;
} // namespace wallet

namespace blsct {
//! Sum of the wallet's confirmed staked commitments that carry a
//! stake-delegation payload.
CAmount GetDelegatedStakedBalance(const wallet::CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet);
UniValue SendTransaction(wallet::CWallet& wallet, const blsct::CreateTransactionData& transactionData, const bool& verbose, wallet::mapValue_t mapValue = {});
//! Build a fee-0 cover candidate from one of the wallet's coins and send it as
//! a CANDIDATE_TX encrypted 1:1 to `reply_key`. Returns the candidate txid, or
//! std::nullopt with `error` set.
std::optional<CTransactionRef> BuildAndSendCandidate(wallet::CWallet& wallet, const blsct::PublicKey& reply_key, bool stem, std::string& error);
//! Answer up to SERVE_MAX_PER_TICK queued candidate pull requests using the
//! first of `wallets` able to fund one. Used by the built-in serving task
//! (-servecandidates) scheduled from StartWallets.
void ServeCandidateRequests(const std::vector<std::shared_ptr<wallet::CWallet>>& wallets);
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
