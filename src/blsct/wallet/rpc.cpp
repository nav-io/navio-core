// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/balance_proof.h>
#include <blsct/wallet/helpers.h>
#include <blsct/wallet/rpc.h>
#include <blsct/wallet/unsigned_transaction.h>
#include <blsct/common.h>
#include <blsct/public_key.h>
#include <blsct/public_keys.h>
#include <blsct/tokens/predicate_parser.h>
#include <coins.h>
#include <core_io.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/transaction_identifier.h>
#include <validation.h>
#include <wallet/receive.h>
#include <wallet/rpc/util.h>
#include <limits>

namespace blsct {

CScript BuildHTLCScript(
    const std::vector<unsigned char>& hash_bytes,
    const std::vector<unsigned char>& spendingKeyA,
    const std::vector<unsigned char>& spendingKeyB,
    int64_t locktime)
{
    CScript script;
    script << OP_IF
           << OP_SIZE << 32 << OP_EQUALVERIFY
           << OP_SHA256 << hash_bytes << OP_EQUALVERIFY
           << spendingKeyA
           << OP_ELSE
           << locktime
           << OP_CHECKLOCKTIMEVERIFY << OP_DROP
           << spendingKeyB
           << OP_ENDIF
           << OP_BLSCHECKSIG;
    return script;
}

static void ParseBLSCTRecipients(const UniValue& address_amounts, const UniValue& subtract_fee_outputs, const std::string& sMemo, std::vector<wallet::CBLSCTRecipient>& recipients)
{
    std::set<CTxDestination> destinations;
    int i = 0;
    for (const std::string& address : address_amounts.getKeys()) {
        CTxDestination dest = DecodeDestination(address);
        if (!IsValidDestination(dest) || dest.index() != 8) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid BLSCT address: ") + address);
        }

        if (destinations.count(dest)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + address);
        }
        destinations.insert(dest);

        CAmount amount = AmountFromValue(address_amounts[i++]);

        bool subtract_fee = false;
        for (unsigned int idx = 0; idx < subtract_fee_outputs.size(); idx++) {
            const UniValue& addr = subtract_fee_outputs[idx];
            if (addr.get_str() == address) {
                subtract_fee = true;
            }
        }

        wallet::CBLSCTRecipient recipient = {amount, sMemo, dest, subtract_fee, false};
        recipients.push_back(recipient);
    }
}

template <typename Scalar>
static std::string FormatRecoveredGamma(const Scalar& gamma)
{
    return gamma.IsZero() ? "" : HexStr(gamma.GetVch());
}

UniValue SendTransaction(wallet::CWallet& wallet, const blsct::CreateTransactionData& transactionData, const bool& verbose)
{
    // This should always try to sign, if we don't have private keys, don't try to do anything here.
    if (wallet.IsWalletFlagSet(wallet::WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Private keys are disabled for this wallet");
    }
    // Send
    auto res = blsct::TxFactory::CreateTransaction(&wallet, wallet.GetBLSCTKeyMan(), transactionData);

    if (!res) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Not enough funds available");
    }

    const CTransactionRef& tx = MakeTransactionRef(res.value());

    wallet::mapValue_t map_value;
    wallet.CommitTransaction(tx, std::move(map_value), /*orderForm=*/{});
    const std::string outputHash = tx->vout[0].GetHash().GetHex();
    if (verbose) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("outputHash", outputHash);
        return entry;
    }
    return outputHash;
}
} // namespace blsct

UniValue CreateTokenOrNft(const RPCHelpMan& self, const JSONRPCRequest& request, const blsct::TokenType& type)
{
    std::shared_ptr<wallet::CWallet> const pwallet = wallet::GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    auto blsct_km = pwallet->GetOrCreateBLSCTKeyMan();

    std::map<std::string, UniValue> metadata;
    if (!request.params[0].isNull() && !request.params[0].get_obj().empty())
        request.params[0].get_obj().getObjMap(metadata);

    std::map<std::string, std::string> mapMetadata;

    for (auto& it : metadata) {
        if (it.second.isNull() || !it.second.isStr() || it.second.get_str().empty())
            continue;
        mapMetadata[it.first] = it.second.get_str();
    }

    CAmount max_supply = type == blsct::TokenType::TOKEN ? AmountFromValue(request.params[1]) : request.params[1].get_uint64();

    blsct::TokenInfo tokenInfo;
    tokenInfo.nTotalSupply = max_supply;
    tokenInfo.mapMetadata = mapMetadata;
    tokenInfo.type = type;

    auto tokenId = (HashWriter{} << tokenInfo.mapMetadata << tokenInfo.nTotalSupply).GetHash();

    std::map<uint256, blsct::TokenEntry> tokens;
    tokens[tokenId];
    pwallet->chain().findTokens(tokens);

    if (tokens.count(tokenId))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Token already exists");

    auto token = tokens[tokenId];

    tokenInfo.publicKey = blsct_km->GetTokenKey(tokenId).GetPublicKey();

    blsct::CreateTransactionData
        transactionData(tokenInfo);

    EnsureWalletIsUnlocked(*pwallet);
    auto hash = blsct::SendTransaction(*pwallet, transactionData, false);

    UniValue ret{UniValue::VOBJ};
    ret.pushKV("outputHash", hash);
    ret.pushKV("tokenId", tokenInfo.publicKey.GetHash().ToString());

    return ret;
}

RPCHelpMan createnft()
{
    return RPCHelpMan{
        "createnft",
        "Submits a transaction creating a NFT\n",
        {{
             "metadata",
             RPCArg::Type::OBJ_USER_KEYS,
             RPCArg::Optional::NO,
             "The NFT metadata",
             {
                 {"key", RPCArg::Type::STR, RPCArg::Optional::NO, "value"},
             },
         },
         {"max_supply", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The NFT max supply."}},
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                                              {RPCResult::Type::STR_HEX, "outputHash", "The output hash of the broadcasted transaction"},
                                              {RPCResult::Type::STR_HEX, "tokenId", "The token id"},
                                          }},
        RPCExamples{HelpExampleRpc("createnft", "{'name':'My NFT Collection'} 1000")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            return CreateTokenOrNft(self, request, blsct::NFT);
        },
    };
}

RPCHelpMan createtoken()
{
    return RPCHelpMan{
        "createtoken",
        "Submits a transaction creating a token.\n",
        {{
             "metadata",
             RPCArg::Type::OBJ_USER_KEYS,
             RPCArg::Optional::NO,
             "The token metadata",
             {
                 {"key", RPCArg::Type::STR, RPCArg::Optional::NO, "value"},
             },
         },
         {"max_supply", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The token max supply."}},
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                                              {RPCResult::Type::STR_HEX, "outputHash", "The output hash of the broadcasted transaction"},
                                              {RPCResult::Type::STR_HEX, "tokenId", "The token id"},
                                          }},
        RPCExamples{HelpExampleRpc("createtoken", "{\"name\":\"Token\"} 1000")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            return CreateTokenOrNft(self, request, blsct::TOKEN);
        },
    };
}

RPCHelpMan minttoken()
{
    return RPCHelpMan{
        "minttoken",
        "Mints a certain amount of tokens to an address.\n",
        {{
             "token_id",
             RPCArg::Type::STR_HEX,
             RPCArg::Optional::NO,
             "The token id.",
         },
         {
             "address",
             RPCArg::Type::STR,
             RPCArg::Optional::NO,
             "The address where the tokens will be minted.",
         },
         {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The token amount to be minted."}},
        RPCResult{
            RPCResult::Type::STR_HEX, "outputHash", "The output hash of the broadcasted transaction"},
        RPCExamples{HelpExampleRpc("minttoken", "d46a375d31843d6a303dc7a8c0e0cccaa2d89f442052226fd5337b4d77afcc80 " + BLSCT_EXAMPLE_ADDRESS[0] + " 1000")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> const pwallet = wallet::GetWalletForJSONRPCRequest(request);

            if (!pwallet) return UniValue::VNULL;

            // Make sure the results are valid at least up to the most recent block
            // the user could have gotten from another RPC command prior to now
            pwallet->BlockUntilSyncedToCurrentChain();

            LOCK(pwallet->cs_wallet);

            auto blsct_km = pwallet->GetOrCreateBLSCTKeyMan();

            uint256 token_id(ParseHashV(request.params[0], "token_id"));
            const std::string address = request.params[1].get_str();
            CAmount mint_amount = AmountFromValue(request.params[2]);

            std::map<uint256, blsct::TokenEntry> tokens;
            tokens[token_id];
            pwallet->chain().findTokens(tokens);

            if (!tokens.count(token_id))
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown token");

            auto token = tokens[token_id];

            auto tokenId = (HashWriter{} << token.info.mapMetadata << token.info.nTotalSupply).GetHash();
            auto publicKey = blsct_km->GetTokenKey(tokenId).GetPublicKey();

            if (publicKey != token.info.publicKey)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "You don't own the token");

            blsct::CreateTransactionData
                transactionData(token.info, mint_amount, address);

            EnsureWalletIsUnlocked(*pwallet);

            auto hash = blsct::SendTransaction(*pwallet, transactionData, false);

            return hash;
        },
    };
}

static RPCHelpMan mintnft()
{
    return RPCHelpMan{
        "mintnft",
        "Mints a NFT to an address.\n",
        {{
             "token_id",
             RPCArg::Type::STR_HEX,
             RPCArg::Optional::NO,
             "The token id.",
         },
         {
             "nft_id",
             RPCArg::Type::AMOUNT,
             RPCArg::Optional::NO,
             "The nft id.",
         },
         {
             "address",
             RPCArg::Type::STR,
             RPCArg::Optional::NO,
             "The address where the tokens will be minted.",
         },
         {
             "metadata",
             RPCArg::Type::OBJ_USER_KEYS,
             RPCArg::Optional::NO,
             "The token metadata",
             {
                 {"key", RPCArg::Type::STR, RPCArg::Optional::NO, "value"},
             },
         }},
        RPCResult{
            RPCResult::Type::STR_HEX, "outputHash", "The output hash of the broadcasted transaction"},
        RPCExamples{HelpExampleRpc("mintnft", "d46a375d31843d6a303dc7a8c0e0cccaa2d89f442052226fd5337b4d77afcc80 1 " + BLSCT_EXAMPLE_ADDRESS[0] + " {\"desc\":\"Your first NFT\"}")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> const pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Make sure the results are valid at least up to the most recent block
            // the user could have gotten from another RPC command prior to now
            pwallet->BlockUntilSyncedToCurrentChain();

            LOCK(pwallet->cs_wallet);

            auto blsct_km = pwallet->GetOrCreateBLSCTKeyMan();

            uint256 token_id(ParseHashV(request.params[0], "token_id"));
            uint64_t nft_id = request.params[1].get_uint64();
            const std::string address = request.params[2].get_str();
            std::map<std::string, UniValue> metadata;
            if (!request.params[3].isNull() && !request.params[3].get_obj().empty())
                request.params[3].get_obj().getObjMap(metadata);

            std::map<std::string, std::string> mapMetadata;

            for (auto& it : metadata) {
                if (it.second.isNull() || !it.second.isStr() || it.second.get_str().empty())
                    continue;
                mapMetadata[it.first] = it.second.get_str();
            }

            std::map<uint256, blsct::TokenEntry> tokens;
            tokens[token_id];
            pwallet->chain().findTokens(tokens);

            if (!tokens.count(token_id))
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown token");

            auto token = tokens[token_id];

            auto tokenId = (HashWriter{} << token.info.mapMetadata << token.info.nTotalSupply).GetHash();
            auto publicKey = blsct_km->GetTokenKey(tokenId).GetPublicKey();

            if (publicKey != token.info.publicKey)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "You don't own the token");

            if (token.mapMintedNft.count(nft_id))
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "The NFT is already minted");

            blsct::CreateTransactionData
                transactionData(token.info, nft_id, address, mapMetadata);

            EnsureWalletIsUnlocked(*pwallet);

            auto hash = blsct::SendTransaction(*pwallet, transactionData, false);

            return hash;
        },
    };
}

RPCHelpMan getblsctbalance()
{
    return RPCHelpMan{
        "getblsctbalance",
        "\nReturns the total available BLSCT balance.\n"
        "Only outputs the wallet can sign for are counted by default; pass\n"
        "include_watchonly=true to also include outputs imported as watch-only\n"
        "scripts (e.g. via importblsctscript), whose amount the wallet can\n"
        "decrypt but cannot spend.\n",
        {
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{0}, "Only include transactions confirmed at least this many times."},
            {"include_watchonly", RPCArg::Type::BOOL, RPCArg::DefaultHint{"true for watch-only wallets, otherwise false"}, "Also include balance in watch-only addresses / scripts (see 'importblsctscript')"},
            {"avoid_reuse", RPCArg::Type::BOOL, RPCArg::Default{true}, "(only available if avoid_reuse wallet flag is set) Do not include balance in dirty outputs; addresses are considered dirty if they have previously been used in a transaction."},
        },
        RPCResult{
            RPCResult::Type::STR_AMOUNT, "amount", "The total amount in " + CURRENCY_UNIT + " received for this wallet."},
        RPCExamples{
            "\nThe total amount in the wallet with 0 or more confirmations\n" + HelpExampleCli("getblsctbalance", "") +
            "\nThe total amount in the wallet with at least 6 confirmations\n" + HelpExampleCli("getblsctbalance", "\"*\" 6") +
            "\nAs a JSON-RPC call\n" + HelpExampleRpc("getblsctbalance", "\"*\", 6")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const std::shared_ptr<const wallet::CWallet> pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Make sure the results are valid at least up to the most recent block
            // the user could have gotten from another RPC command prior to now
            pwallet->BlockUntilSyncedToCurrentChain();

            LOCK(pwallet->cs_wallet);

            int min_depth = 0;
            if (!request.params[0].isNull()) {
                min_depth = request.params[0].getInt<int>();
            }

            bool include_watchonly = ParseIncludeWatchonly(request.params[1], *pwallet);

            // GetBlsctBalance only sees outputs stored in mapOutputs, which is
            // populated only when WALLET_FLAG_BLSCT_OUTPUT_STORAGE is set. For
            // legacy (e.g. bdb) BLSCT wallets the BLSCT outputs live in
            // mapWallet, so we have to walk them directly to avoid the RPC
            // reporting a confusing 0.
            CAmount mine_trusted = 0;
            CAmount watchonly_trusted = 0;

            if (pwallet->IsWalletFlagSet(wallet::WALLET_FLAG_BLSCT_OUTPUT_STORAGE)) {
                const auto bal = wallet::GetBlsctBalance(*pwallet, min_depth);
                mine_trusted = bal.m_mine_trusted;
                watchonly_trusted = bal.m_watchonly_trusted;
            } else {
                std::set<uint256> trusted_parents;
                for (const auto& entry : pwallet->mapWallet) {
                    const wallet::CWalletTx& wtx = entry.second;
                    if (!wallet::CachedTxIsTrusted(*pwallet, wtx, trusted_parents)) continue;
                    if (pwallet->IsTxImmatureCoinBase(wtx)) continue;
                    const int depth = pwallet->GetTxDepthInMainChain(wtx);
                    if (depth < min_depth) continue;
                    for (unsigned int i = 0; i < wtx.tx->vout.size(); ++i) {
                        const CTxOut& txout = wtx.tx->vout[i];
                        if (!txout.HasBLSCTRangeProof()) continue;
                        if (!txout.tokenId.IsNull()) continue;
                        if (pwallet->IsSpent(COutPoint(txout.GetHash()))) continue;
                        const wallet::isminetype mine = pwallet->IsMine(txout);
                        const bool is_signable = (mine & (wallet::ISMINE_SPENDABLE_BLSCT | wallet::ISMINE_STAKED_COMMITMENT_BLSCT)) != 0;
                        const bool is_watchonly = (mine & wallet::ISMINE_WATCH_ONLY) != 0;
                        if (!is_signable && !is_watchonly) continue;
                        const CAmount amount = wtx.GetBLSCTRecoveryData(i).amount;
                        if (is_signable) {
                            mine_trusted += amount;
                        } else if (is_watchonly) {
                            watchonly_trusted += amount;
                        }
                    }
                }
            }

            return ValueFromAmount(mine_trusted + (include_watchonly ? watchonly_trusted : 0));
        },
    };
}

RPCHelpMan gettokenbalance()
{
    return RPCHelpMan{
        "gettokenbalance",
        "\nReturns the total available balance of a token.\n"
        "The available balance is what the wallet considers currently spendable, and is\n"
        "thus affected by options which limit spendability such as -spendzeroconfchange.\n",
        {
            {"token_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The token id"},
            {"dummy", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Remains for backward compatibility. Must be excluded or set to \"*\"."},
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{0}, "Only include transactions confirmed at least this many times."},
            {"include_watchonly", RPCArg::Type::BOOL, RPCArg::DefaultHint{"true for watch-only wallets, otherwise false"}, "Also include balance in watch-only addresses (see 'importaddress')"},
            {"avoid_reuse", RPCArg::Type::BOOL, RPCArg::Default{true}, "(only available if avoid_reuse wallet flag is set) Do not include balance in dirty outputs; addresses are considered dirty if they have previously been used in a transaction."},
        },
        RPCResult{
            RPCResult::Type::STR_AMOUNT, "amount", "The total amount received for this wallet."},
        RPCExamples{
            "\nThe total amount in the wallet with 0 or more confirmations\n" + HelpExampleCli("gettokenbalance", "0e8ba9acaef5a91e5933393baf0b1187fae81f158cd9455437378b1796fc893d") +
            "\nThe total amount in the wallet with at least 6 confirmations\n" + HelpExampleCli("gettokenbalance", "0e8ba9acaef5a91e5933393baf0b1187fae81f158cd9455437378b1796fc893d \"*\" 6") +
            "\nAs a JSON-RPC call\n" + HelpExampleRpc("gettokenbalance", "\"0e8ba9acaef5a91e5933393baf0b1187fae81f158cd9455437378b1796fc893d\", \"*\", 6")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const std::shared_ptr<const wallet::CWallet> pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Make sure the results are valid at least up to the most recent block
            // the user could have gotten from another RPC command prior to now
            pwallet->BlockUntilSyncedToCurrentChain();

            LOCK(pwallet->cs_wallet);

            uint256 token_id(ParseHashV(request.params[0], "token_id"));

            std::map<uint256, blsct::TokenEntry> tokens;
            tokens[token_id];
            pwallet->chain().findTokens(tokens);

            if (!tokens.count(token_id))
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown token");

            auto token = tokens[token_id];

            if (token.info.type != blsct::TokenType::TOKEN)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Wrong token type");

            const auto dummy_value{self.MaybeArg<std::string>(1)};
            if (dummy_value && *dummy_value != "*") {
                throw JSONRPCError(RPC_METHOD_DEPRECATED, "dummy first argument must be excluded or set to \"*\".");
            }

            int min_depth = 0;
            if (!request.params[2].isNull()) {
                min_depth = request.params[2].getInt<int>();
            }

            bool include_watchonly = ParseIncludeWatchonly(request.params[3], *pwallet);

            const auto bal = pwallet->IsWalletFlagSet(wallet::WALLET_FLAG_BLSCT_OUTPUT_STORAGE)
                ? GetBlsctBalance(*pwallet, min_depth, token_id)
                : GetBalance(*pwallet, min_depth, false, token_id);

            return ValueFromAmount(bal.m_mine_trusted + (include_watchonly ? bal.m_watchonly_trusted : 0));
        },
    };
}

RPCHelpMan getnftbalance()
{
    return RPCHelpMan{
        "getnftbalance",
        "\nReturns the NFTs owned from a collection.\n"
        "The available balance is what the wallet considers currently spendable, and is\n"
        "thus affected by options which limit spendability such as -spendzeroconfchange.\n",
        {
            {"token_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The token id from the collection"},
            {"dummy", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Remains for backward compatibility. Must be excluded or set to \"*\"."},
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{0}, "Only include transactions confirmed at least this many times."},
            {"include_watchonly", RPCArg::Type::BOOL, RPCArg::DefaultHint{"true for watch-only wallets, otherwise false"}, "Also include balance in watch-only addresses (see 'importaddress')"},
            {"avoid_reuse", RPCArg::Type::BOOL, RPCArg::Default{true}, "(only available if avoid_reuse wallet flag is set) Do not include balance in dirty outputs; addresses are considered dirty if they have previously been used in a transaction."},
        },
        RPCResult{RPCResult::Type::ANY, "mintedNft", true, "the nfts already minted"},
        RPCExamples{
            "\nThe total amount in the wallet with 0 or more confirmations\n" + HelpExampleCli("getnftbalance", "0e8ba9acaef5a91e5933393baf0b1187fae81f158cd9455437378b1796fc893d") +
            "\nThe total amount in the wallet with at least 6 confirmations\n" + HelpExampleCli("getnftbalance", "0e8ba9acaef5a91e5933393baf0b1187fae81f158cd9455437378b1796fc893d \"*\" 6") +
            "\nAs a JSON-RPC call\n" + HelpExampleRpc("getnftbalance", "\"0e8ba9acaef5a91e5933393baf0b1187fae81f158cd9455437378b1796fc893d\", \"*\", 6")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const std::shared_ptr<const wallet::CWallet> pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Make sure the results are valid at least up to the most recent block
            // the user could have gotten from another RPC command prior to now
            pwallet->BlockUntilSyncedToCurrentChain();

            LOCK(pwallet->cs_wallet);

            uint256 token_id(ParseHashV(request.params[0], "token_id"));

            std::map<uint256, blsct::TokenEntry> tokens;
            tokens[token_id];
            pwallet->chain().findTokens(tokens);

            if (!tokens.count(token_id))
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown token");

            auto token = tokens[token_id];

            if (token.info.type != blsct::TokenType::NFT)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Wrong token type");

            const auto dummy_value{self.MaybeArg<std::string>(1)};
            if (dummy_value && *dummy_value != "*") {
                throw JSONRPCError(RPC_METHOD_DEPRECATED, "dummy first argument must be excluded or set to \"*\".");
            }

            int min_depth = 0;
            if (!request.params[2].isNull()) {
                min_depth = request.params[2].getInt<int>();
            }

            bool include_watchonly = ParseIncludeWatchonly(request.params[3], *pwallet);

            UniValue ret(UniValue::VARR);

            for (auto& it : token.mapMintedNft) {
                const auto bal = pwallet->IsWalletFlagSet(wallet::WALLET_FLAG_BLSCT_OUTPUT_STORAGE)
                    ? GetBlsctBalance(*pwallet, min_depth, TokenId(token_id, it.first))
                    : GetBalance(*pwallet, min_depth, false, TokenId(token_id, it.first));

                if ((bal.m_mine_trusted + (include_watchonly ? bal.m_watchonly_trusted : 0)) > 0) {
                    UniValue retObj(UniValue::VOBJ);

                    UniValue metadata(UniValue::VARR);
                    for (auto& md_it : it.second) {
                        UniValue metadataObj(UniValue::VOBJ);
                        metadataObj.pushKV("key", md_it.first);
                        metadataObj.pushKV("value", md_it.second);
                        metadata.push_back(metadataObj);
                    }
                    retObj.pushKV("index", strprintf("%llu", it.first));
                    retObj.pushKV("metadata", metadata);
                    ret.push_back(retObj);
                }
            }

            return ret;
        },
    };
}

RPCHelpMan sendtoblsctaddress()
{
    return RPCHelpMan{
        "sendtoblsctaddress",
        "\nSend an amount to a given blsct address." +
            wallet::HELP_REQUIRING_PASSPHRASE,
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The BLSCT address to send to."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in " + CURRENCY_UNIT + " to send. eg 0.1"},
            {"memo", RPCArg::Type::STR, RPCArg::Default{""}, "A memo used to store in the transaction.\n"
                                                             "The recipient will see its value."},
            {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, return extra information about the transaction."},
        },
        {
            RPCResult{"if verbose is not set or set to false",
                      RPCResult::Type::STR_HEX, "outputHash", "The output hash."},
            RPCResult{
                "if verbose is set to true",
                RPCResult::Type::OBJ,
                "",
                "",
                {{RPCResult::Type::STR_HEX, "outputHash", "The output hash."}},
            },
        },
        RPCExamples{
            "\nSend 0.1 " + CURRENCY_UNIT + "\n" + HelpExampleCli("sendtoblsctaddress", "\"" + BLSCT_EXAMPLE_ADDRESS[0] + "\" 0.1") +
            "\nSend 0.1 " + CURRENCY_UNIT + " including \"donation\" as memo in the transaction using positional arguments\n" + HelpExampleCli("sendtoblsctaddress", "\"" + BLSCT_EXAMPLE_ADDRESS[0] + "\" 0.1 \"donation\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> const pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Make sure the results are valid at least up to the most recent block
            // the user could have gotten from another RPC command prior to now
            pwallet->BlockUntilSyncedToCurrentChain();

            LOCK(pwallet->cs_wallet);

            // Wallet comments
            std::string sMemo;
            if (!request.params[2].isNull() && !request.params[2].get_str().empty())
                sMemo = request.params[2].get_str();

            CTxDestination destination = DecodeDestination(request.params[0].get_str());
            if (!IsValidDestination(destination) || destination.index() != 8) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
            }

            const std::string address = request.params[0].get_str();

            const bool verbose{request.params[3].isNull() ? false : request.params[10].get_bool()};

            blsct::CreateTransactionData transactionData(address, AmountFromValue(request.params[1]), sMemo, TokenId(), blsct::CreateTransactionType::NORMAL, 0);

            EnsureWalletIsUnlocked(*pwallet);

            return blsct::SendTransaction(*pwallet, transactionData, verbose);
        },
    };
}

RPCHelpMan sendtokentoblsctaddress()
{
    return RPCHelpMan{
        "sendtokentoblsctaddress",
        "\nSend an amount to tokens to a given blsct address." +
            wallet::HELP_REQUIRING_PASSPHRASE,
        {
            {"token_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The token id."},
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The BLSCT address to send to."},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in " + CURRENCY_UNIT + " to send. eg 0.1"},
            {"memo", RPCArg::Type::STR, RPCArg::Default{""}, "A memo used to store in the transaction.\n"
                                                             "The recipient will see its value."},
            {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, return extra information about the transaction."},
        },
        {
            RPCResult{"if verbose is not set or set to false",
                      RPCResult::Type::STR_HEX, "outputHash", "The output hash."},
            RPCResult{
                "if verbose is set to true",
                RPCResult::Type::OBJ,
                "",
                "",
                {{RPCResult::Type::STR_HEX, "outputHash", "The output hash."}},
            },
        },
        RPCExamples{
            "\nSend 0.1 tokens\n" + HelpExampleCli("sendtokentoblsctaddress", "a685e520f85d111a6c55bd2b8226f6b916a3bcdd3b549c75e0abddc55df70951 \"" + BLSCT_EXAMPLE_ADDRESS[0] + "\" 0.1") +
            "\nSend 0.1 tokens including \"donation\" as memo in the transaction using positional arguments\n" + HelpExampleCli("sendtotokensblsctaddress", "a685e520f85d111a6c55bd2b8226f6b916a3bcdd3b549c75e0abddc55df70951 \"" + BLSCT_EXAMPLE_ADDRESS[0] + "\" 0.1 \"donation\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> const pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Make sure the results are valid at least up to the most recent block
            // the user could have gotten from another RPC command prior to now
            pwallet->BlockUntilSyncedToCurrentChain();

            LOCK(pwallet->cs_wallet);

            uint256 token_id(ParseHashV(request.params[0], "token_id"));

            std::map<uint256, blsct::TokenEntry> tokens;
            tokens[token_id];
            pwallet->chain().findTokens(tokens);

            if (!tokens.count(token_id))
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown token");

            auto token = tokens[token_id];

            if (token.info.type != blsct::TokenType::TOKEN)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Wrong token type");

            // Wallet comments
            std::string sMemo;
            if (!request.params[3].isNull() && !request.params[3].get_str().empty())
                sMemo = request.params[3].get_str();

            CTxDestination destination = DecodeDestination(request.params[1].get_str());
            if (!IsValidDestination(destination) || destination.index() != 8) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
            }

            const std::string address = request.params[1].get_str();

            const bool verbose{request.params[4].isNull() ? false : request.params[11].get_bool()};

            blsct::SubAddress subAddress(std::get<blsct::DoublePublicKey>(destination));
            blsct::CreateTransactionData transactionData(address, AmountFromValue(request.params[2]), sMemo, TokenId(token_id), blsct::CreateTransactionType::NORMAL, 0);

            EnsureWalletIsUnlocked(*pwallet);

            return blsct::SendTransaction(*pwallet, transactionData, verbose);
        },
    };
}


RPCHelpMan sendnfttoblsctaddress()
{
    return RPCHelpMan{
        "sendnfttoblsctaddress",
        "\nSend an NFT to a given blsct address." +
            wallet::HELP_REQUIRING_PASSPHRASE,
        {
            {"token_id", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The token id."},
            {"nft_id", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The nft id."},
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The BLSCT address to send to."},
            {"memo", RPCArg::Type::STR, RPCArg::Default{""}, "A memo used to store in the transaction.\n"
                                                             "The recipient will see its value."},
            {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, return extra information about the transaction."},
        },
        {
            RPCResult{"if verbose is not set or set to false",
                      RPCResult::Type::STR_HEX, "outputHash", "The output hash."},
            RPCResult{
                "if verbose is set to true",
                RPCResult::Type::OBJ,
                "",
                "",
                {{RPCResult::Type::STR_HEX, "outputHash", "The output hash."}},
            },
        },
        RPCExamples{
            "\nSend NFT\n" + HelpExampleCli("sendnfttoblsctaddress", "a685e520f85d111a6c55bd2b8226f6b916a3bcdd3b549c75e0abddc55df70951 0 \"" + BLSCT_EXAMPLE_ADDRESS[0] + "\"") +
            "\nSend NFT including \"donation\" as memo in the transaction using positional arguments\n" + HelpExampleCli("sendnfttoblsctaddress", "a685e520f85d111a6c55bd2b8226f6b916a3bcdd3b549c75e0abddc55df70951 0 \"" + BLSCT_EXAMPLE_ADDRESS[0] + "\" \"donation\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> const pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Make sure the results are valid at least up to the most recent block
            // the user could have gotten from another RPC command prior to now
            pwallet->BlockUntilSyncedToCurrentChain();

            LOCK(pwallet->cs_wallet);

            uint256 token_id(ParseHashV(request.params[0], "token_id"));
            uint64_t nft_id(request.params[1].get_uint64());

            std::map<uint256, blsct::TokenEntry> tokens;
            tokens[token_id];
            pwallet->chain().findTokens(tokens);

            if (!tokens.count(token_id))
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown token");

            auto token = tokens[token_id];

            if (token.info.type != blsct::TokenType::NFT)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Wrong token type");

            // Wallet comments
            std::string sMemo;
            if (!request.params[3].isNull() && !request.params[3].get_str().empty())
                sMemo = request.params[3].get_str();

            CTxDestination destination = DecodeDestination(request.params[2].get_str());
            if (!IsValidDestination(destination) || destination.index() != 8) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
            }

            const std::string address = request.params[2].get_str();

            const bool verbose{request.params[4].isNull() ? false : request.params[4].get_bool()};

            blsct::SubAddress subAddress(std::get<blsct::DoublePublicKey>(destination));
            blsct::CreateTransactionData transactionData(address, 1, sMemo, TokenId(token_id, nft_id), blsct::CreateTransactionType::NORMAL, 0);

            EnsureWalletIsUnlocked(*pwallet);

            return blsct::SendTransaction(*pwallet, transactionData, verbose);
        },
    };
}


RPCHelpMan stakelock()
{
    return RPCHelpMan{
        "stakelock",
        "\nLock an amount in order to stake it." +
            wallet::HELP_REQUIRING_PASSPHRASE,
        {
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in " + CURRENCY_UNIT + " to stake. eg 0.1"},
            {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, return extra information about the transaction."},
        },
        {
            RPCResult{"if verbose is not set or set to false",
                      RPCResult::Type::STR_HEX, "outputHash", "The output hash."},
            RPCResult{
                "if verbose is set to true",
                RPCResult::Type::OBJ,
                "",
                "",
                {{RPCResult::Type::STR_HEX, "outputHash", "The output hash."}},
            },
        },
        RPCExamples{
            "\nLock 0.1 " + CURRENCY_UNIT + "\n" + HelpExampleCli("stakelock", "0.1")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> const pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Make sure the results are valid at least up to the most recent block
            // the user could have gotten from another RPC command prior to now
            pwallet->BlockUntilSyncedToCurrentChain();

            LOCK(pwallet->cs_wallet);

            UniValue address_amounts(UniValue::VOBJ);
            auto op_dest = pwallet->GetNewDestination(OutputType::BLSCT_STAKE, "Locked Stake");
            if (!op_dest) {
                throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(op_dest).original);
            }

            const std::string address = EncodeDestination(*op_dest);
            address_amounts.pushKV(address, request.params[0]);

            std::vector<wallet::CBLSCTRecipient> recipients;
            blsct::ParseBLSCTRecipients(address_amounts, false, "", recipients);
            const bool verbose{request.params[10].isNull() ? false : request.params[10].get_bool()};

            blsct::CreateTransactionData transactionData(recipients[0].destination, recipients[0].nAmount, recipients[0].sMemo, TokenId(), blsct::CreateTransactionType::STAKED_COMMITMENT, Params().GetConsensus().nPePoSMinStakeAmount);

            EnsureWalletIsUnlocked(*pwallet);

            return blsct::SendTransaction(*pwallet, transactionData, verbose);
        },
    };
}


RPCHelpMan stakeunlock()
{
    return RPCHelpMan{
        "stakeunlock",
        "\nUnlocks an staked amount." +
            wallet::HELP_REQUIRING_PASSPHRASE,
        {
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in " + CURRENCY_UNIT + " to unstake. eg 0.1"},
            {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, return extra information about the transaction."},
        },
        {
            RPCResult{"if verbose is not set or set to false",
                      RPCResult::Type::STR_HEX, "outputHash", "The output hash."},
            RPCResult{
                "if verbose is set to true",
                RPCResult::Type::OBJ,
                "",
                "",
                {{RPCResult::Type::STR_HEX, "outputHash", "The output hash."}},
            },
        },
        RPCExamples{
            "\nLock 0.1 " + CURRENCY_UNIT + "\n" + HelpExampleCli("stakelock", "0.1")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> const pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Make sure the results are valid at least up to the most recent block
            // the user could have gotten from another RPC command prior to now
            pwallet->BlockUntilSyncedToCurrentChain();

            LOCK(pwallet->cs_wallet);

            UniValue address_amounts(UniValue::VOBJ);
            auto op_dest = pwallet->GetNewDestination(OutputType::BLSCT_STAKE, "");
            if (!op_dest) {
                throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(op_dest).original);
            }

            const std::string address = EncodeDestination(*op_dest);
            address_amounts.pushKV(address, request.params[0]);

            std::vector<wallet::CBLSCTRecipient> recipients;
            blsct::ParseBLSCTRecipients(address_amounts, false, "", recipients);
            const bool verbose{request.params[10].isNull() ? false : request.params[10].get_bool()};


            blsct::CreateTransactionData transactionData(recipients[0].destination, recipients[0].nAmount, recipients[0].sMemo, TokenId(), blsct::CreateTransactionType::STAKED_COMMITMENT_UNSTAKE, Params().GetConsensus().nPePoSMinStakeAmount);

            EnsureWalletIsUnlocked(*pwallet);

            return blsct::SendTransaction(*pwallet, transactionData, verbose);
        },
    };
}

RPCHelpMan listblsctunspent()
{
    return RPCHelpMan{
        "listblsctunspent",
        "\nReturns array of unspent transaction outputs\n"
        "with between minconf and maxconf (inclusive) confirmations.\n"
        "Optionally filter to only include txouts paid to specified addresses.\n",
        {
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{1}, "The minimum confirmations to filter"},
            {"maxconf", RPCArg::Type::NUM, RPCArg::Default{9999999}, "The maximum confirmations to filter"},
            {
                "addresses",
                RPCArg::Type::ARR,
                RPCArg::Default{UniValue::VARR},
                "The navio addresses to filter",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "navio address"},
                },
            },
            {"query_options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "", {{"minimumAmount", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(0)}, "Minimum value of each UTXO in " + CURRENCY_UNIT + ""}, {"maximumAmount", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"unlimited"}, "Maximum value of each UTXO in " + CURRENCY_UNIT + ""}, {"maximumCount", RPCArg::Type::NUM, RPCArg::DefaultHint{"unlimited"}, "Maximum number of UTXOs"}, {"minimumSumAmount", RPCArg::Type::AMOUNT, RPCArg::DefaultHint{"unlimited"}, "Minimum sum value of all UTXOs in " + CURRENCY_UNIT + ""}, {"include_immature_coinbase", RPCArg::Type::BOOL, RPCArg::Default{false}, "Include immature coinbase UTXOs"}}, RPCArgOptions{.oneline_description = "query_options"}},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "", {
                                              {RPCResult::Type::OBJ, "", "", {
                                                                                 {RPCResult::Type::STR_HEX, "outid", "the output id"},
                                                                                 {RPCResult::Type::STR, "address", /*optional=*/true, "the navio address"},
                                                                                 {RPCResult::Type::STR, "label", /*optional=*/true, "The associated label, or \"\" for the default label"},
                                                                                 {RPCResult::Type::STR_AMOUNT, "amount", "the transaction output amount in " + CURRENCY_UNIT},
                                                                                 {RPCResult::Type::NUM, "confirmations", "The number of confirmations"},
                                                                                 {RPCResult::Type::BOOL, "spendable", "Whether the output may be selected for spending right now (depends on coin control / wallet state)"},
                                                                                 {RPCResult::Type::BOOL, "signable", "Whether the wallet can derive a non-zero spending key for this output. Outputs imported via importblsctscript (e.g. HTLCs) are reported as signable=false because the wallet only holds view material for them."},
                                                                                 {RPCResult::Type::BOOL, "watchonly", "Whether this output matches an imported watch-only scriptPubKey (e.g. an HTLC added via importblsctscript)"},
                                                                                 {RPCResult::Type::STR_HEX, "scriptPubKey", "The scriptPubKey of the output"},
                                                                             }},
                                          }},

        RPCExamples{HelpExampleCli("listblsctunspent", "") + HelpExampleCli("listblsctunspent", "6 9999999 \"[\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\"]\"") + HelpExampleRpc("listblsctunspent", "6, 9999999 \"[\\\"" + EXAMPLE_ADDRESS[0] + "\\\",\\\"" + EXAMPLE_ADDRESS[1] + "\\\"]\"") + HelpExampleCli("listblsctunspent", "6 9999999 '[]' '{ \"minimumAmount\": 0.005 }'") + HelpExampleRpc("listblsctunspent", "6, 9999999, [] , { \"minimumAmount\": 0.005 } ")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> const pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            int nMinDepth = 1;
            if (!request.params[0].isNull()) {
                nMinDepth = request.params[0].getInt<int>();
            }

            int nMaxDepth = 9999999;
            if (!request.params[1].isNull()) {
                nMaxDepth = request.params[1].getInt<int>();
            }

            std::set<CTxDestination> destinations;
            if (!request.params[2].isNull()) {
                UniValue inputs = request.params[2].get_array();
                for (unsigned int idx = 0; idx < inputs.size(); idx++) {
                    const UniValue& input = inputs[idx];
                    CTxDestination dest = DecodeDestination(input.get_str());
                    if (!IsValidDestination(dest)) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Bitcoin address: ") + input.get_str());
                    }
                    if (!destinations.insert(dest).second) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + input.get_str());
                    }
                }
            }

            wallet::CoinFilterParams filter_coins;
            filter_coins.min_amount = 0;
            // Surface watch-only outputs (e.g. HTLC scripts imported via
            // importblsctscript) so callers can see them and filter via the
            // per-entry `signable` / `watchonly` flags. Without this, the
            // default `only_spendable=true` would silently drop them.
            filter_coins.only_spendable = false;

            if (!request.params[3].isNull()) {
                const UniValue& options = request.params[3].get_obj();

                RPCTypeCheckObj(options,
                                {{"minimumAmount", UniValueType()},
                                 {"maximumAmount", UniValueType()},
                                 {"minimumSumAmount", UniValueType()},
                                 {"maximumCount", UniValueType(UniValue::VNUM)},
                                 {"include_immature_coinbase", UniValueType(UniValue::VBOOL)}},
                                true, true);

                if (options.exists("minimumAmount"))
                    filter_coins.min_amount = AmountFromValue(options["minimumAmount"]);

                if (options.exists("maximumAmount"))
                    filter_coins.max_amount = AmountFromValue(options["maximumAmount"]);

                if (options.exists("minimumSumAmount"))
                    filter_coins.min_sum_amount = AmountFromValue(options["minimumSumAmount"]);

                if (options.exists("maximumCount"))
                    filter_coins.max_count = options["maximumCount"].getInt<int64_t>();

                if (options.exists("include_immature_coinbase")) {
                    filter_coins.include_immature_coinbase = options["include_immature_coinbase"].get_bool();
                }
            }

            // Make sure the results are valid at least up to the most recent block
            // the user could have gotten from another RPC command prior to now
            pwallet->BlockUntilSyncedToCurrentChain();

            UniValue results(UniValue::VARR);
            std::vector<wallet::COutput> vecOutputs;
            {
                wallet::CCoinControl cctl;
                cctl.m_avoid_address_reuse = false;
                cctl.m_min_depth = nMinDepth;
                cctl.m_max_depth = nMaxDepth;
                LOCK(pwallet->cs_wallet);
                vecOutputs = (pwallet->IsWalletFlagSet(wallet::WALLET_FLAG_BLSCT_OUTPUT_STORAGE) ? AvailableBlsctCoins(*pwallet, &cctl, filter_coins) : AvailableCoins(*pwallet, nullptr, std::nullopt, filter_coins)).All();
            }

            LOCK(pwallet->cs_wallet);

            auto blsct_km = pwallet->GetOrCreateBLSCTKeyMan();

            for (const wallet::COutput& out : vecOutputs) {
                CTxDestination address = blsct_km->GetDestination(out.txout);
                bool fValidAddress = address.index() > 0;

                if (destinations.size() && (!fValidAddress || !destinations.count(address)))
                    continue;

                UniValue entry(UniValue::VOBJ);
                entry.pushKV("outid", out.outpoint.hash.GetHex());

                CTxDestination script_address;

                if (ExtractDestination(out.txout.scriptPubKey, script_address)) {
                    entry.pushKV("scriptAddress", EncodeDestination(script_address));
                }

                entry.pushKV("scriptPubKey", HexStr(out.txout.scriptPubKey));

                if (fValidAddress) {
                    entry.pushKV("address", EncodeDestination(address));

                    const auto* address_book_entry = pwallet->FindAddressBookEntry(address);
                    if (address_book_entry) {
                        entry.pushKV("label", address_book_entry->GetLabel());
                    }
                }

                entry.pushKV("amount", ValueFromAmount(out.txout.nValue));
                entry.pushKV("confirmations", out.depth);
                // `signable` answers the question downstream wallets actually
                // care about: "can this wallet produce a signature for this
                // output?". It is true iff IsMineMode classified the output
                // as one we own via a subaddress (or staked commitment) and
                // can therefore derive a non-zero spending key.
                const wallet::isminetype mine = pwallet->IsMine(out.txout);
                const bool signable = (mine & (wallet::ISMINE_SPENDABLE_BLSCT | wallet::ISMINE_STAKED_COMMITMENT_BLSCT)) != 0;
                entry.pushKV("spendable", out.spendable);
                entry.pushKV("signable", signable);
                entry.pushKV("watchonly", (mine & wallet::ISMINE_WATCH_ONLY) != 0);
                results.push_back(entry);
            }

            return results;
        },
    };
};

RPCHelpMan listblscttransactions()
{
    return RPCHelpMan{
        "listblscttransactions",
        "\nIf a label name is provided, this will return only incoming transactions paying to addresses with the specified label.\n"
        "\nReturns up to 'count' most recent transactions skipping the first 'from' transactions.\n",
        {
            {"label|dummy", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "If set, should be a valid label name to return only incoming transactions\n"
                                                                          "with the specified label, or \"*\" to disable filtering and return all transactions."},
            {"count", RPCArg::Type::NUM, RPCArg::Default{10}, "The number of transactions to return"},
            {"skip", RPCArg::Type::NUM, RPCArg::Default{0}, "The number of transactions to skip"},
            {"include_watchonly", RPCArg::Type::BOOL, RPCArg::DefaultHint{"true for watch-only wallets, otherwise false"}, "Include transactions to watch-only addresses (see 'importaddress')"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "", {
                                              {RPCResult::Type::OBJ, "", "", Cat<std::vector<RPCResult>>({
                                                                                                             {RPCResult::Type::BOOL, "involvesWatchonly", /*optional=*/true, "Only returns true if imported addresses were involved in transaction."},
                                                                                                             {RPCResult::Type::STR, "address", /*optional=*/true, "The bitcoin address of the transaction (not returned if the output does not have an address, e.g. OP_RETURN null data)."},
                                                                                                             {RPCResult::Type::STR, "category", "The transaction category.\n"
                                                                                                                                                "\"send\"                  Transactions sent.\n"
                                                                                                                                                "\"receive\"               Non-coinbase transactions received.\n"
                                                                                                                                                "\"generate\"              Coinbase transactions received with more than 100 confirmations.\n"
                                                                                                                                                "\"immature\"              Coinbase transactions received with 100 or fewer confirmations.\n"
                                                                                                                                                "\"orphan\"                Orphaned coinbase transactions received."},
                                                                                                             {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and is positive\n"
                                                                                                                                                                                        "for all other categories"},
                                                                                                             {RPCResult::Type::STR, "label", /*optional=*/true, "A comment for the address/transaction, if any"},
                                                                                                             {RPCResult::Type::NUM, "vout", /*optional=*/true, "the vout value"},
                                                                                                             {RPCResult::Type::STR_AMOUNT, "fee", /*optional=*/true, "The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the\n"
                                                                                                                                                                                                                   "'send' category of transactions."},
                                                                                                         },
                                                                                                         {
                                                                                                             {RPCResult::Type::BOOL, "abandoned", "'true' if the transaction has been abandoned (inputs are respendable)."},
                                                                                                         })},
                                          }},
        RPCExamples{"\nList the most recent 10 transactions in the systems\n" + HelpExampleCli("listblscttransactions", "") + "\nList transactions 100 to 120\n" + HelpExampleCli("listblscttransactions", "\"*\" 20 100") + "\nAs a JSON-RPC call\n" + HelpExampleRpc("listblscttransactions", "\"*\", 20, 100")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const std::shared_ptr<const wallet::CWallet> pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Make sure the results are valid at least up to the most recent block
            // the user could have gotten from another RPC command prior to now
            pwallet->BlockUntilSyncedToCurrentChain();

            std::optional<std::string> filter_label;
            if (!request.params[0].isNull() && request.params[0].get_str() != "*") {
                filter_label.emplace(wallet::LabelFromValue(request.params[0]));
                if (filter_label.value().empty()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Label argument must be a valid label name or \"*\".");
                }
            }
            int nCount = 10;
            if (!request.params[1].isNull())
                nCount = request.params[1].getInt<int>();
            int nFrom = 0;
            if (!request.params[2].isNull())
                nFrom = request.params[2].getInt<int>();

            // wallet::isminefilter filter = wallet::ISMINE_SPENDABLE | wallet::ISMINE_SPENDABLE_BLSCT;

            // if (ParseIncludeWatchonly(request.params[3], *pwallet)) {
            //     filter |= wallet::ISMINE_WATCH_ONLY;
            // }

            if (nCount < 0)
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
            if (nFrom < 0)
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

            std::vector<UniValue> ret;
            /*            entry.pushKV("category", "send");
            entry.pushKV("amount", ValueFromAmount(-s.amount));
            const auto* address_book_entry = wallet.FindAddressBookEntry(s.destination);
            if (address_book_entry) {
                entry.pushKV("label", address_book_entry->GetLabel());
            }
            if (s.vout != -1)
                entry.pushKV("vout", s.vout);
            entry.pushKV("fee", ValueFromAmount(-nFee));
            if (fLong)
                WalletTxToJSON(wallet, wtx, entry);
            if (wtx.tx->IsBLSCT() && wtx.isAbandoned())
                continue;
            entry.pushKV("abandoned", wtx.isAbandoned());
            ret.push_back(entry);*/
            {
                LOCK(pwallet->cs_wallet);

                // wallet::OutputItems sortedMap;
                // for (const auto& it : pwallet->mapOutputs) {
                //     sortedMap.emplace(it.second.GetTxTime(), &it.second);
                // }

                // // iterate backwards until we have nCount items to return:
                // for (wallet::OutputItems::const_reverse_iterator it = sortedMap.rbegin(); it != sortedMap.rend(); ++it) {
                //     wallet::CWalletOutput const pwout = (*it).second;
                //     ListBlsctTransactions(*pwallet, *pwout, 1, 100000000, true, ret, filter, filter_label);
                //     if ((int)ret.size() >= (nCount + nFrom)) break;
                // }
            }

            // ret is newest to oldest

            if (nFrom > (int)ret.size())
                nFrom = ret.size();
            if ((nFrom + nCount) > (int)ret.size())
                nCount = ret.size() - nFrom;

            auto txs_rev_it{std::make_move_iterator(ret.rend())};
            UniValue result{UniValue::VARR};
            result.push_backV(txs_rev_it - nFrom - nCount, txs_rev_it - nFrom); // Return oldest to newest
            return result;
        },
    };
};


static RPCHelpMan setblsctseed()
{
    return RPCHelpMan{
        "setblsctseed",
        "\nSet or generate a new BLSCT wallet seed. Non-BLSCT wallets will not be upgraded to being a BLSCT wallet. Wallets that are already\n"
        "BLSCT will have a new BLSCT seed set so that new keys added to the keypool will be derived from this new seed.\n"
        "\nNote that you will need to MAKE A NEW BACKUP of your wallet after setting the BLSCT wallet seed." +
            wallet::HELP_REQUIRING_PASSPHRASE,
        {
            {"seed", RPCArg::Type::STR, RPCArg::DefaultHint{"random seed"}, "The WIF private key to use as the new HD seed.\n"},
        },
        RPCResult{RPCResult::Type::NONE, "", ""},
        RPCExamples{
            HelpExampleCli("setblsctseed", "") + HelpExampleCli("setblsctseed", "") + HelpExampleCli("setblsctseed", "\"wifkey\"") + HelpExampleRpc("setblsctseed", "\"wifkey\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> const pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            auto blsct_km = pwallet->GetOrCreateBLSCTKeyMan();

            if (pwallet->IsWalletFlagSet(wallet::WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Cannot set a BLSCT seed to a wallet with private keys disabled");
            }

            LOCK2(pwallet->cs_wallet, blsct_km->cs_KeyStore);

            // Do not do anything to non-HD wallets
            if (!pwallet->IsWalletFlagSet(wallet::WALLET_FLAG_BLSCT)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Cannot set a BLSCT seed on a non-BLSCT wallet.");
            }

            EnsureWalletIsUnlocked(*pwallet);

            blsct::PrivateKey master_priv_key;
            if (request.params[0].isNull()) {
                master_priv_key = blsct_km->GenerateNewSeed();
            } else {
                CKey key = DecodeSecret(request.params[0].get_str());
                if (!key.IsValid()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
                }

                // Use the raw 32-byte key data, not the DER-encoded CPrivKey
                const auto& keydata = key.IsValid() ? std::vector<unsigned char>(UCharCast(key.begin()), UCharCast(key.end())) : std::vector<unsigned char>();
                if (keydata.size() != 32) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Failed to extract 32-byte key from WIF");
                }
                MclScalar scalar;
                scalar.SetVch(keydata);
                // Reject if the raw bytes encode a value >= the field order: SetVch
                // uses setBigEndianMod which silently reduces, so we verify round-trip.
                if (scalar.GetVch() != std::vector<uint8_t>(keydata.begin(), keydata.end())) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Key value is out of range (>= group order)");
                }
                master_priv_key = blsct::PrivateKey(scalar);

                if (blsct_km->HaveKey(master_priv_key.GetPublicKey().GetID())) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Already have this key (either as an BLSCT seed or as a loose private key)");
                }
            }

            blsct_km->SetHDSeed(master_priv_key);

            if (!blsct_km->NewSubAddressPool() || !blsct_km->NewSubAddressPool(-1) || !blsct_km->NewSubAddressPool(-2)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Unable to generate initial blsct address pool");
            }

            return UniValue::VNULL;
        },
    };
}

RPCHelpMan createblsctbalanceproof()
{
    return RPCHelpMan{
        "createblsctbalanceproof",
        "Creates a zero-knowledge proof that the wallet has at least the specified balance\n",
        {
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The minimum balance to prove"},
            {"additional_commitment", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "The additional commitment to use for the proof signature"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                                              {RPCResult::Type::STR_HEX, "proof", "The serialized balance proof"},
                                          }},
        RPCExamples{HelpExampleCli("createblsctbalanceproof", "1.0 \"order id: 100\"") + HelpExampleRpc("createblsctbalanceproof", "1.0 \"order id: 100\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::vector<COutPoint> outpoints;
            CAmount target_amount = AmountFromValue(request.params[0]);

            uint256 hash = MessageHash("BLSCT_BALANCE_PROOF_" + (!request.params[1].isNull() ? request.params[1].get_str() : ""));
            blsct::Message additional_commitment(hash.begin(), hash.end());

            std::shared_ptr<wallet::CWallet> const pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            if (!pwallet->IsWalletFlagSet(wallet::WALLET_FLAG_BLSCT)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "BLSCT must be enabled for this wallet");
            }

            LOCK(pwallet->cs_wallet);

            if (target_amount <= 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount must be positive");
            }

            // Get available BLSCT coins
            wallet::CoinFilterParams filter_coins;
            filter_coins.only_blsct = true;
            filter_coins.skip_locked = false;
            filter_coins.include_immature_coinbase = false;
            wallet::CoinsResult available_coins = pwallet->IsWalletFlagSet(wallet::WALLET_FLAG_BLSCT_OUTPUT_STORAGE)
                ? AvailableBlsctCoins(*pwallet, nullptr, filter_coins)
                : AvailableCoins(*pwallet, nullptr, std::nullopt, filter_coins);

            if (available_coins.GetTotalAmount() < target_amount) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");
            }

            // Collect outpoints and create balance proof
            for (const auto& [type, outputs] : available_coins.coins) {
                for (const auto& output : outputs) {
                    outpoints.push_back(output.outpoint);
                }
            }

            blsct::BalanceProof proof(outpoints, target_amount, *pwallet, additional_commitment);

            // Serialize the proof
            DataStream ss{};
            ss << proof;

            UniValue result(UniValue::VOBJ);
            result.pushKV("proof", HexStr(ss));

            return result;
        },
    };
}

RPCHelpMan createblsctrawtransaction()
{
    return RPCHelpMan{
        "createblsctrawtransaction",
        "\nCreate a unsigned transaction spending the given inputs and creating new outputs.\n"
        "Returns hex-encoded raw unsigned transaction.\n"
        "Note that the transaction's inputs are not signed, and\n"
        "it is not stored in the wallet or transmitted to the network.\n",
        {
            {
                "inputs",
                RPCArg::Type::ARR,
                RPCArg::Optional::NO,
                "A json array of json objects",
                {
                    {
                        "",
                        RPCArg::Type::OBJ,
                        RPCArg::Optional::OMITTED,
                        "",
                        {
                            {"outid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The output id"},
                            {"sequence", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "The script sequence number"},
                            {"value", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "The input value in navoshis"},
                            {"gamma", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The gamma value for the input (hex string)"},
                            {"spending_key", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The private key for signing this input (hex string)"},
                            {"is_staked_commitment", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Whether this input is a staked commitment"},
                            {"scriptSig", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The scriptSig in hex format to use for this input"},
                        },
                    },
                },
            },
            {
                "outputs",
                RPCArg::Type::ARR,
                RPCArg::Optional::NO,
                "A json array with outputs (key-value pairs)",
                {
                    {
                        "",
                        RPCArg::Type::OBJ,
                        RPCArg::Optional::OMITTED,
                        "",
                        {
                            {"type", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Output type. Use \"atomic_swap\" for a hash/time locked output, otherwise omit for a standard payment"},
                            {"address", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "The BLSCT address to send to"},
                            {"address_a", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "First BLSCT address for an atomic_swap output (hashlock branch)"},
                            {"address_b", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Second BLSCT address for an atomic_swap output (timelock branch)"},
                            {"amount", RPCArg::Type::NUM, RPCArg::Optional::NO, "The amount in navoshis"},
                            {"memo", RPCArg::Type::STR, RPCArg::Default{""}, "A memo used to store in the transaction.\n"
                                                                             "The recipient will see its value."},
                            {"token_id", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "The token id for token transactions"},
                            {"script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The script in hex format to use for this output"},
                            {"nonce", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The nonce for this output (hex string)"},
                            {"hash", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "32-byte hash (hex) for atomic_swap outputs"},
                            {"locktime", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Locktime (block height or timestamp) for atomic_swap refund branch"},
                            {"blinding_key", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "Optional 32-byte blinding key to deterministically derive atomic_swap spending keys"},
                        },
                    },
                },
            },
            {"type", RPCArg::Type::STR, RPCArg::Default{""}, "Transaction type: \"normal\", \"create_token\", \"mint_token\", or \"mint_nft\""},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "transaction", "hex string of the transaction"},
        RPCExamples{
            HelpExampleCli("createblsctrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"value\\\":1000000,\\\"gamma\\\":\\\"1234567890abcdef\\\",\\\"spending_key\\\":\\\"abcdef1234567890\\\"}]\" \"[{\\\"address\\\":\\\"address\\\",\\\"amount\\\":1000000,\\\"memo\\\":\\\"memo\\\",\\\"token_id\\\":\\\"tokenid\\\"}]\"") +
            HelpExampleCli("createblsctrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\"}]\" \"[{\\\"address\\\":\\\"address\\\",\\\"amount\\\":1000000}]\"") +
            HelpExampleCli("createblsctrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\"}]\" \"[{\\\"address\\\":\\\"address\\\",\\\"amount\\\":1000000,\\\"script\\\":\\\"51\\\"}]\"") +
            HelpExampleCli("createblsctrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\"}]\" \"[{\\\"type\\\":\\\"atomic_swap\\\",\\\"address_a\\\":\\\"blsctAddr1\\\",\\\"address_b\\\":\\\"blsctAddr2\\\",\\\"amount\\\":1000000,\\\"hash\\\":\\\"00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff\\\",\\\"locktime\\\":750000}]\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> const pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Make sure the results are valid at least up to the most recent block
            // the user could have gotten from another RPC command prior to now
            pwallet->BlockUntilSyncedToCurrentChain();

            LOCK(pwallet->cs_wallet);

            auto blsct_km = pwallet->GetOrCreateBLSCTKeyMan();

            // Parse inputs
            const UniValue& inputs = request.params[0].get_array();
            std::vector<blsct::UnsignedInput> unsigned_inputs;
            for (unsigned int idx = 0; idx < inputs.size(); idx++) {
                const UniValue& input = inputs[idx];
                const UniValue& o = input.get_obj();

                const Txid txid = Txid::FromUint256(ParseHashO(o, "outid"));
                blsct::UnsignedInput unsigned_input;
                unsigned_input.in.prevout = COutPoint(txid);
                CTxOut wallet_prevout;
                std::optional<range_proof::RecoveredData<Mcl>> wallet_recovery_data;

                if (const wallet::CWalletOutput* wallet_output = pwallet->GetWalletOutput(unsigned_input.in.prevout)) {
                    wallet_prevout = *wallet_output->out;
                    wallet_recovery_data = wallet_output->blsctRecoveryData;
                } else if (const wallet::CWalletTx* wallet_tx = pwallet->GetWalletTxFromOutpoint(unsigned_input.in.prevout)) {
                    auto txout_iter = std::find_if(wallet_tx->tx->vout.begin(), wallet_tx->tx->vout.end(),
                        [&](const CTxOut& out) { return out.GetHash() == txid; });
                    if (txout_iter != wallet_tx->tx->vout.end()) {
                        wallet_prevout = *txout_iter;
                        wallet_recovery_data = wallet_tx->GetBLSCTRecoveryData(unsigned_input.in.prevout);
                    }
                }

                if (o.exists("sequence")) {
                    uint32_t seq = o["sequence"].getInt<uint32_t>();
                    if (seq != CTxIn::SEQUENCE_FINAL && (seq & (1U << 31))) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                            "Sequence value has bit 31 set (reserved for future relative timelocks). "
                            "Valid absolute locktime range: 0 to 0x7FFFFFFF, or 0xFFFFFFFF for no lock.");
                    }
                    unsigned_input.in.nSequence = seq;
                }

                // Parse optional value field
                if (o.exists("value")) {
                    CAmount value = o["value"].getInt<CAmount>();
                    if (value < 0)
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Input value must be positive");
                    unsigned_input.value = Scalar(value);
                }

                // Parse optional gamma field
                if (o.exists("gamma")) {
                    std::string gamma_hex = o["gamma"].get_str();
                    if (!gamma_hex.empty()) {
                        try {
                            std::vector<unsigned char> gamma_bytes = ParseHex(gamma_hex);
                            if (gamma_bytes.size() != 32) {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Gamma must be 32 bytes (64 hex characters)");
                            }
                            unsigned_input.gamma = Scalar(gamma_bytes);
                        } catch (const std::exception& e) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid gamma hex string: %s", e.what()));
                        }
                    }
                }

                // Parse optional private key field
                if (o.exists("spending_key")) {
                    std::string sk_hex = o["spending_key"].get_str();
                    if (!sk_hex.empty()) {
                        try {
                            std::vector<unsigned char> sk_bytes = ParseHex(sk_hex);
                            if (sk_bytes.size() != 32) {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Private key must be 32 bytes (64 hex characters)");
                            }
                            unsigned_input.sk = blsct::PrivateKey(Scalar(sk_bytes));
                        } catch (const std::exception& e) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid private key hex string: %s", e.what()));
                        }
                    }
                }

                // Parse optional is_staked_commitment field
                if (o.exists("is_staked_commitment")) {
                    unsigned_input.is_staked_commitment = o["is_staked_commitment"].get_bool();
                }

                // Parse optional scriptSig field
                if (o.exists("scriptSig")) {
                    std::string scriptSig_hex = o["scriptSig"].get_str();
                    auto scriptSig = ParseHex(scriptSig_hex);
                    unsigned_input.in.scriptSig = CScript(scriptSig.begin(), scriptSig.end());
                }

                // If value or gamma are not provided, try to get them from the wallet
                if (!o.exists("value") || !o.exists("gamma")) {
                    if (!wallet_recovery_data) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Output %s not found in wallet", txid.GetHex()));
                    }

                    if (wallet_recovery_data->amount == 0 && wallet_recovery_data->gamma == Scalar(0) && wallet_recovery_data->id == 0 && wallet_recovery_data->message == "") {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("BLSCT recovery data not available for output %s", txid.GetHex()));
                    }

                    if (!o.exists("value")) {
                        unsigned_input.value = Scalar(wallet_recovery_data->amount);
                    }

                    if (!o.exists("gamma")) {
                        unsigned_input.gamma = wallet_recovery_data->gamma;
                    }
                }

                // If private key is not provided, try to get it from the wallet
                if (!o.exists("spending_key")) {
                    if (wallet_prevout.IsNull()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Output %s not found in wallet", txid.GetHex()));
                    }

                    blsct::PrivateKey spending_key;
                    if (!blsct_km->GetSpendingKeyForOutputWithCache(wallet_prevout, spending_key) || !spending_key.IsValid()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Spending key not available for output %s", txid.GetHex()));
                    }

                    unsigned_input.sk = spending_key;
                }

                // Validate: spending key must produce a public key matching the UTXO's spendingKey
                if (unsigned_input.sk.IsValid() && !wallet_prevout.IsNull() && !wallet_prevout.blsctData.spendingKey.IsZero()) {
                    auto signing_pubkey = unsigned_input.sk.GetPublicKey();
                    auto expected_pubkey = blsct::PublicKey(wallet_prevout.blsctData.spendingKey);
                    if (signing_pubkey != expected_pubkey) {
                        throw JSONRPCError(RPC_WALLET_ERROR, strprintf(
                            "Input %d (%s): spending key does not match the UTXO spendingKey. "
                            "This transaction would fail signature verification on broadcast.",
                            idx, txid.GetHex()));
                        }
                }

                unsigned_inputs.push_back(unsigned_input);
            }

            // Parse type
            blsct::CreateTransactionType type = blsct::NORMAL;
            if (!request.params[2].isNull()) {
                std::string type_str = request.params[2].get_str();
                if (type_str == "create_token") {
                    type = blsct::TX_CREATE_TOKEN;
                } else if (type_str == "mint_token") {
                    type = blsct::TX_MINT_TOKEN;
                } else if (type_str == "mint_nft") {
                    type = blsct::TX_MINT_TOKEN;
                } else if (type_str != "normal") {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid transaction type");
                }
            }

            // Parse outputs
            const UniValue& outputs = request.params[1].get_array();
            std::vector<blsct::UnsignedOutput> unsigned_outputs;

            auto derive_spending_key = [&](const blsct::DoublePublicKey& dest_keys, const Scalar& blinding_key) -> blsct::PublicKey {
                MclG1Point vk;
                MclG1Point sk;

                if (!dest_keys.GetViewKey(vk)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Could not extract view key from BLSCT address");
                }

                if (!dest_keys.GetSpendKey(sk)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Could not extract spend key from BLSCT address");
                }

                auto rV = vk * blinding_key;

                return blsct::PublicKey(sk + blsct::PrivateKey(Scalar(rV.GetHashWithSalt(0))).GetPoint());
            };

            for (unsigned int idx = 0; idx < outputs.size(); idx++) {
                const UniValue& output = outputs[idx];
                const UniValue& o = output.get_obj();

                if (!o.exists("amount")) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Each output must include an amount");
                }

                CAmount nAmount = o["amount"].getInt<CAmount>();
                if (nAmount < 0)
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount, must be positive");

                std::string memo = o.exists("memo") ? o["memo"].get_str() : "";
                TokenId token_id;
                if (o.exists("token_id") && !o["token_id"].get_str().empty()) {
                    token_id = TokenId(ParseHashV(o["token_id"], "token_id"));
                }

                blsct::UnsignedOutput unsigned_output;
                auto blindingKey = Scalar::Rand();

                if (o.exists("blinding_key")) {
                    auto blinding_key_bytes = ParseHex(o["blinding_key"].get_str());
                    if (blinding_key_bytes.size() != 32) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Blinding key must be 32 bytes (64 hex characters)");
                    }
                    blindingKey = Scalar(blinding_key_bytes);
                }

                if (blindingKey.IsZero()) {
                    blindingKey = Scalar::Rand();
                }

                std::string output_type = o.exists("type") ? o["type"].get_str() : "";

                if (!output_type.empty() && output_type != "atomic_swap") {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Unsupported output type: " + output_type);
                }

                if (output_type == "atomic_swap") {
                    auto parse_address = [&](const std::string& address, const std::string& field_name) -> blsct::DoublePublicKey {
                        CTxDestination destination = DecodeDestination(address);
                        if (!IsValidDestination(destination) || destination.index() != 8) {
                            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid BLSCT address for ") + field_name + ": " + address);
                        }
                        return std::get<blsct::DoublePublicKey>(destination);
                    };

                    if (!o.exists("address_a") || !o.exists("address_b")) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Atomic swap output requires address_a and address_b");
                    }

                    blsct::DoublePublicKey address_a = parse_address(o["address_a"].get_str(), "address_a");
                    blsct::DoublePublicKey address_b = parse_address(o["address_b"].get_str(), "address_b");

                    if (!o.exists("hash")) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Atomic swap output requires a 32-byte hash");
                    }

                    std::vector<unsigned char> hash_bytes = ParseHex(o["hash"].get_str());
                    if (hash_bytes.size() != 32) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Atomic swap hash must be 32 bytes (64 hex characters)");
                    }

                    if (!o.exists("locktime")) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Atomic swap output requires locktime");
                    }

                    int64_t locktime = o["locktime"].getInt<int64_t>();
                    if (locktime < 0 || locktime > std::numeric_limits<uint32_t>::max()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Locktime must be between 0 and 4294967295");
                    }

                    if (o.exists("script") && !o["script"].get_str().empty()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Custom script is not allowed when type is atomic_swap");
                    }

                    auto spendingKeyA = derive_spending_key(address_a, blindingKey);
                    auto spendingKeyB = derive_spending_key(address_b, blindingKey);

                    auto spendingKeyABytes = spendingKeyA.GetVch();
                    auto spendingKeyBBytes = spendingKeyB.GetVch();

                    if (spendingKeyABytes.size() != blsct::PublicKey::SIZE || spendingKeyBBytes.size() != blsct::PublicKey::SIZE) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Failed to derive valid spending keys for atomic_swap output");
                    }

                    CScript script = blsct::BuildHTLCScript(hash_bytes, spendingKeyABytes, spendingKeyBBytes, locktime);

                    unsigned_output = CreateOutput(std::make_pair(address_a, script), nAmount, memo, token_id, blindingKey, type, 0);

                    // Nullify the spending key
                    unsigned_output.out.blsctData.spendingKey = MclG1Point();
                } else {
                    blsct::SubAddress subAddress;
                    if (o.exists("address")) {
                        std::string address = o["address"].get_str();
                        CTxDestination destination = DecodeDestination(address);
                        if (!IsValidDestination(destination) || destination.index() != 8) {
                            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid BLSCT address: ") + address);
                        }
                        subAddress = std::get<blsct::DoublePublicKey>(destination);
                    } else {
                        subAddress = blsct::DoublePublicKey(MclG1Point::GetBasePoint(), MclG1Point::GetBasePoint());
                    }

                    // Check if script is provided
                    if (o.exists("script") && !o["script"].get_str().empty()) {
                        std::string script_hex = o["script"].get_str();
                        try {
                            std::vector<unsigned char> script_bytes = ParseHex(script_hex);
                            CScript script(script_bytes.begin(), script_bytes.end());
                            unsigned_output = CreateOutput(std::make_pair(subAddress.GetKeys(), script), nAmount, memo, token_id, blindingKey, type, 0);
                        } catch (const std::exception& e) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid script hex string: %s", e.what()));
                        }
                    } else {
                        unsigned_output = CreateOutput(subAddress.GetKeys(), nAmount, memo, token_id, blindingKey, type);
                    }
                }

                unsigned_outputs.push_back(unsigned_output);
            }

            // Create unsigned transaction
            blsct::UnsignedTransaction unsigned_tx;

            // Add inputs and outputs
            for (const auto& input : unsigned_inputs) {
                unsigned_tx.AddInput(input);
            }
            for (const auto& output : unsigned_outputs) {
                unsigned_tx.AddOutput(output);
            }

            // Serialize the transaction
            return HexStr(unsigned_tx.Serialize());
        },
    };
}

RPCHelpMan fundblsctrawtransaction()
{
    return RPCHelpMan{
        "fundblsctrawtransaction",
        "\nAdd inputs to a BLSCT transaction until it has enough value to cover outputs and fee.\n"
        "If lock_unspents is true, selected inputs are locked. Use unlockblsctoutpoint to unlock them.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex string of the raw transaction"},
            {"changeaddress", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "The BLSCT address to receive the change"},
            {"lock_unspents", RPCArg::Type::BOOL, RPCArg::Default{false}, "Lock selected unspent outputs"},
            {"fee", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "The absolute fee in navoshis. Defaults to 1000000"},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "transaction", "hex string of the funded transaction"},
        RPCExamples{
            HelpExampleCli("fundblsctrawtransaction", "\"hexstring\"") +
            HelpExampleCli("fundblsctrawtransaction", "\"hexstring\" \"changeaddress\"") +
            HelpExampleCli("fundblsctrawtransaction", "\"hexstring\" \"changeaddress\" true") +
            HelpExampleCli("fundblsctrawtransaction", "\"hexstring\" null false 250000")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> const pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Make sure the results are valid at least up to the most recent block
            pwallet->BlockUntilSyncedToCurrentChain();

            LOCK(pwallet->cs_wallet);

            auto blsct_km = pwallet->GetOrCreateBLSCTKeyMan();

            // Parse the unsigned transaction
            std::vector<unsigned char> txData = ParseHex(request.params[0].get_str());
            auto unsigned_tx_opt = blsct::UnsignedTransaction::Deserialize(txData);
            if (!unsigned_tx_opt) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Transaction deserialization failed");
            }
            auto& unsigned_tx = unsigned_tx_opt.value();

            const bool lock_unspents = !request.params[2].isNull() && request.params[2].get_bool();
            CAmount fee = COIN / 100;
            if (!request.params[3].isNull()) {
                fee = request.params[3].getInt<CAmount>();
            }
            if (fee < 0 || !MoneyRange(fee)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Fee must be a non-negative amount in navoshis");
            }

            unsigned_tx.SetFee(fee);

            // Calculate total output amount
            CAmount output_value = 0;
            for (const auto& out : unsigned_tx.GetOutputs()) {
                output_value += out.value.GetUint64();
                if (!MoneyRange(output_value)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Output value is too large");
                }
            }
            LogPrint(BCLog::WALLETDB, "fundblsctrawtransaction: total output value=%lld\n", output_value);

            // Calculate total input amount from existing inputs
            CAmount existing_input_value = 0;
            std::set<COutPoint> existing_inputs;

            // Find unspent outputs to use as inputs
            wallet::CoinFilterParams filter_coins;
            filter_coins.only_blsct = true;
            filter_coins.skip_locked = true;
            filter_coins.include_immature_coinbase = false;
            wallet::CoinsResult available_outputs = pwallet->IsWalletFlagSet(wallet::WALLET_FLAG_BLSCT_OUTPUT_STORAGE)
                ? AvailableBlsctCoins(*pwallet, nullptr, filter_coins)
                : AvailableCoins(*pwallet, nullptr, std::nullopt, filter_coins);

            for (const auto& input : unsigned_tx.GetInputs()) {
                existing_input_value += input.value.GetUint64();
                existing_inputs.insert(input.in.prevout);
            }
            LogPrint(BCLog::WALLETDB, "fundblsctrawtransaction: existing input value=%lld, existing inputs count=%zu\n", existing_input_value, existing_inputs.size());

            auto lock_outpoint_if_wallet = [&](const COutPoint& outpoint) EXCLUSIVE_LOCKS_REQUIRED(pwallet->cs_wallet) {
                if (pwallet->GetWalletTxFromOutpoint(outpoint)) {
                    pwallet->LockCoin(outpoint);
                }
            };

            // Calculate how much more we need
            CAmount required_value = output_value + fee;
            CAmount additional_required = required_value - existing_input_value;
            LogPrint(BCLog::WALLETDB, "fundblsctrawtransaction: required value=%lld, additional required=%lld\n", required_value, additional_required);

            // Get change address (needed for both cases)
            CTxDestination change_dest;
            if (!request.params[1].isNull()) {
                change_dest = DecodeDestination(request.params[1].get_str());
                if (!IsValidDestination(change_dest) || change_dest.index() != 8) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid BLSCT change address");
                }
            } else {
                // Get new change address from wallet
                change_dest = std::get<blsct::DoublePublicKey>(blsct_km->GetNewDestination(blsct::CHANGE_ACCOUNT).value());
            }

            // Check if we need a change output even without additional inputs
            if (additional_required <= 0) {
                if (lock_unspents) {
                    for (const auto& outpoint : existing_inputs) {
                        lock_outpoint_if_wallet(outpoint);
                    }
                }

                // Add change output if needed
                CAmount total_input_value = existing_input_value;

                if (total_input_value > required_value) {
                    CAmount change_value = total_input_value - required_value;
                    blsct::SubAddress change_subaddr(std::get<blsct::DoublePublicKey>(change_dest));
                    blsct::UnsignedOutput change_output = CreateOutput(change_subaddr.GetKeys(), change_value, "", TokenId(), Scalar::Rand());
                    unsigned_tx.AddOutput(change_output);
                }

                return HexStr(unsigned_tx.Serialize());
            }

            CAmount additional_input_value = 0;
            std::vector<COutPoint> added_inputs;
            size_t total_available = 0;
            for (const auto& [type, outputs] : available_outputs.coins) {
                total_available += outputs.size();
            }
            LogPrint(BCLog::WALLETDB, "fundblsctrawtransaction: found %zu candidate outputs, need %lld additional\n", total_available, additional_required);

            for (const auto& [type, outputs] : available_outputs.coins) {
                for (const auto& output : outputs) {
                    if (existing_inputs.count(output.outpoint) > 0) {
                        continue;
                    }

                    LogPrint(BCLog::WALLETDB, "fundblsctrawtransaction: evaluating output %s nValue=%lld hasRangeProof=%d hasKeys=%d spendingKeyZero=%d\n",
                        output.outpoint.ToString(), output.txout.nValue,
                        output.txout.HasBLSCTRangeProof(), output.txout.HasBLSCTKeys(),
                        output.txout.blsctData.spendingKey.IsZero());

                    std::optional<range_proof::RecoveredData<Mcl>> recovery_data;
                    if (const wallet::CWalletOutput* wallet_output = pwallet->GetWalletOutput(output.outpoint)) {
                        recovery_data = wallet_output->blsctRecoveryData;
                        LogPrint(BCLog::WALLETDB, "fundblsctrawtransaction: recovery source=mapOutputs amount=%lld\n", recovery_data->amount);
                    } else if (const wallet::CWalletTx* wallet_tx = pwallet->GetWalletTxFromOutpoint(output.outpoint)) {
                        recovery_data = wallet_tx->GetBLSCTRecoveryData(output.outpoint);
                        LogPrint(BCLog::WALLETDB, "fundblsctrawtransaction: recovery source=mapWallet amount=%lld\n", recovery_data->amount);
                    } else {
                        auto recovery_result = blsct_km->RecoverOutputs({output.txout});
                        if (recovery_result.is_completed && !recovery_result.amounts.empty()) {
                            recovery_data = recovery_result.amounts[0];
                            LogPrint(BCLog::WALLETDB, "fundblsctrawtransaction: recovery source=RecoverOutputs amount=%lld\n", recovery_data->amount);
                        } else {
                            LogPrint(BCLog::WALLETDB, "fundblsctrawtransaction: recovery source=none (not in mapOutputs, mapWallet, or RecoverOutputs)\n");
                        }
                    }

                    CAmount input_amount = 0;
                    Scalar input_gamma;
                    bool has_recovery = recovery_data.has_value() &&
                        !(recovery_data->amount == 0 && recovery_data->gamma == Scalar(0) && recovery_data->id == 0 && recovery_data->message == "");

                    if (has_recovery) {
                        input_amount = recovery_data->amount;
                        input_gamma = recovery_data->gamma;
                    } else if (!output.txout.HasBLSCTRangeProof() && output.txout.nValue > 0) {
                        input_amount = output.txout.nValue;
                        input_gamma = Scalar(0);
                        LogPrint(BCLog::WALLETDB, "fundblsctrawtransaction: using transparent nValue=%lld for output %s\n", input_amount, output.outpoint.ToString());
                    } else {
                        LogPrint(BCLog::WALLETDB, "fundblsctrawtransaction: SKIP output %s reason=no_recovery_data\n", output.outpoint.ToString());
                        continue;
                    }

                    blsct::UnsignedInput input;
                    input.in.prevout = output.outpoint;
                    input.value = Scalar(input_amount);
                    input.gamma = input_gamma;

                    blsct::PrivateKey spending_key;
                    if (!blsct_km->GetSpendingKeyForOutputWithCache(output.txout, spending_key) || !spending_key.IsValid()) {
                        LogPrint(BCLog::WALLETDB, "fundblsctrawtransaction: SKIP output %s reason=spending_key_derivation_failed\n", output.outpoint.ToString());
                        continue;
                    }

                    input.sk = spending_key;

                    if (!output.txout.blsctData.spendingKey.IsZero()) {
                        auto signing_pubkey = spending_key.GetPublicKey();
                        auto expected_pubkey = blsct::PublicKey(output.txout.blsctData.spendingKey);
                        if (signing_pubkey != expected_pubkey) {
                            LogPrint(BCLog::WALLETDB, "fundblsctrawtransaction: SKIP output %s reason=spending_key_mismatch derived=%s expected=%s\n",
                                output.outpoint.ToString(),
                                signing_pubkey.ToString().substr(0, 16),
                                expected_pubkey.ToString().substr(0, 16));
                            continue;
                        }
                    }

                    LogPrint(BCLog::WALLETDB, "fundblsctrawtransaction: ACCEPTED output %s amount=%lld\n", output.outpoint.ToString(), input_amount);
                    unsigned_tx.AddInput(input);
                    additional_input_value += input_amount;
                    added_inputs.push_back(output.outpoint);

                    if (additional_input_value >= additional_required) break;
                }

                if (additional_input_value >= additional_required) break;
            }
            LogPrint(BCLog::WALLETDB, "fundblsctrawtransaction: collected=%lld required=%lld\n", additional_input_value, additional_required);

            if (additional_input_value < additional_required) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strprintf(
                    "Insufficient funds: found %zu candidate outputs but collected %s, need %s. "
                    "Check debug.log for per-output rejection reasons.",
                    total_available, FormatMoney(additional_input_value), FormatMoney(additional_required)));
            }

            if (lock_unspents) {
                std::set<COutPoint> inputs_to_lock = existing_inputs;
                inputs_to_lock.insert(added_inputs.begin(), added_inputs.end());

                for (const auto& outpoint : inputs_to_lock) {
                    lock_outpoint_if_wallet(outpoint);
                }
            }

            // Add change output if needed
            CAmount total_input_value = existing_input_value + additional_input_value;

            if (total_input_value > required_value) {
                CAmount change_value = total_input_value - required_value;
                blsct::SubAddress change_subaddr(std::get<blsct::DoublePublicKey>(change_dest));
                blsct::UnsignedOutput change_output = CreateOutput(change_subaddr.GetKeys(), change_value, "", TokenId(), Scalar::Rand());
                unsigned_tx.AddOutput(change_output);
            }

            return HexStr(unsigned_tx.Serialize());
        },
    };
}

RPCHelpMan unlockblsctoutpoint()
{
    return RPCHelpMan{
        "unlockblsctoutpoint",
        "\nUnlock a BLSCT outpoint that was previously locked for funding.\n",
        {
            {"outpoint_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The output outpoint hash"},
        },
        RPCResult{
            RPCResult::Type::BOOL, "", "Whether the outpoint was successfully unlocked"},
        RPCExamples{
            HelpExampleCli("unlockblsctoutpoint", "\"outpoint_hash\"") +
            HelpExampleRpc("unlockblsctoutpoint", "\"outpoint_hash\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> const pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Make sure the results are valid at least up to the most recent block
            pwallet->BlockUntilSyncedToCurrentChain();

            LOCK(pwallet->cs_wallet);

            const uint256 hash = ParseHashV(request.params[0], "outpoint_hash");
            const COutPoint outpoint(hash);

            if (!pwallet->GetWalletTxFromOutpoint(outpoint)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, unknown outpoint");
            }

            if (pwallet->IsSpent(outpoint)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected unspent output");
            }

            if (!pwallet->IsLockedCoin(outpoint)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected locked output");
            }

            if (!pwallet->UnlockCoin(outpoint)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Unlocking coin failed");
            }

            return true;
        },
    };
}

RPCHelpMan signblsctrawtransaction()
{
    return RPCHelpMan{
        "signblsctrawtransaction",
        "\nSigns a BLSCT raw transaction by adding BLSCT signatures.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction hex string"},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "hex", "The signed transaction hex"},
        RPCExamples{
            HelpExampleRpc("signblsctrawtransaction", "\"hexstring\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> const pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            pwallet->BlockUntilSyncedToCurrentChain();

            LOCK(pwallet->cs_wallet);

            std::vector<unsigned char> tx_data = ParseHex(request.params[0].get_str());
            auto unsigned_tx_opt = blsct::UnsignedTransaction::Deserialize(tx_data);
            if (!unsigned_tx_opt) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Transaction deserialization failed");
            }
            auto& unsigned_tx = unsigned_tx_opt.value();

            pwallet->GetOrCreateBLSCTKeyMan();

            // Sign the transaction
            const auto& tx_opt = unsigned_tx.Sign();
            if (!tx_opt) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign transaction");
            }
            auto tx = tx_opt.value();

            return EncodeHexTx(tx);
        },
    };
}

RPCHelpMan decodeblsctrawtransaction()
{
    return RPCHelpMan{
        "decodeblsctrawtransaction",
        "\nDecode a BLSCT raw transaction and return a JSON object describing the transaction structure.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction hex string"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                                              {RPCResult::Type::ARR, "inputs", "Array of transaction inputs", {
                                                                                                                  {RPCResult::Type::OBJ, "", "", {
                                                                                                                                                {RPCResult::Type::STR_HEX, "outid", "The previous output hash"},
                                                                                                                                                     {RPCResult::Type::NUM, "value", "The input value in navoshis"},
                                                                                                                                                     {RPCResult::Type::STR_HEX, "gamma", "The gamma value (hex string)"},
                                                                                                                                                     {RPCResult::Type::BOOL, "is_staked_commitment", "Whether this input is a staked commitment"},
                                                                                                                                                 }},
                                                                                                              }},
                                                                                                              {RPCResult::Type::ARR, "outputs", "Array of transaction outputs", {
                                                                                                                    {RPCResult::Type::OBJ, "", "", {
                                                                                                                                                       {RPCResult::Type::STR, "scriptAddress", "The decoded destination address for the output script, if any"},
                                                                                                                                                       {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT},
                                                                                                                                                       {RPCResult::Type::NUM, "amount_navoshi", "The amount in navoshis"},
                                                                                                                                                       {RPCResult::Type::STR_HEX, "blinding_key", "The blinding key (hex string)"},
                                                                                                                                                       {RPCResult::Type::STR_HEX, "outputHash", "The output hash identifier (hex string)"},
                                                                                                                                                       {RPCResult::Type::STR_HEX, "gamma", "The gamma value (hex string)"},
                                                                                                                                                       {RPCResult::Type::STR_HEX, "scriptPubKey", "The scriptPubKey of the output"},
                                                                                                                                                       {RPCResult::Type::STR_HEX, "spending_key", /*optional=*/true, "The output spending key (if available)"},
                                                                                                                                                   }},
                                                                                                                }},
                                              {RPCResult::Type::NUM, "fee", "The transaction fee in navoshis"},
                                          }},
        RPCExamples{HelpExampleCli("decodeblsctrawtransaction", "\"hexstring\"") + HelpExampleRpc("decodeblsctrawtransaction", "\"hexstring\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::vector<unsigned char> tx_data = ParseHex(request.params[0].get_str());
            auto unsigned_tx_opt = blsct::UnsignedTransaction::Deserialize(tx_data);
            if (!unsigned_tx_opt) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Transaction deserialization failed");
            }
            auto& unsigned_tx = unsigned_tx_opt.value();

            UniValue result(UniValue::VOBJ);

            // Decode inputs
            UniValue inputs(UniValue::VARR);
            for (const auto& input : unsigned_tx.GetInputs()) {
                UniValue input_obj(UniValue::VOBJ);
                input_obj.pushKV("outid", input.in.prevout.hash.GetHex());
                input_obj.pushKV("value", (int64_t)input.value.GetUint64());
                input_obj.pushKV("gamma", HexStr(input.gamma.GetVch()));
                input_obj.pushKV("is_staked_commitment", input.is_staked_commitment);
                inputs.push_back(input_obj);
            }
            result.pushKV("inputs", inputs);

            // Decode outputs
            UniValue outputs(UniValue::VARR);
            for (const auto& output : unsigned_tx.GetOutputs()) {
                UniValue output_obj(UniValue::VOBJ);

                // Decode the address from the CTxOut
                CTxDestination destination;
                if (ExtractDestination(output.out.scriptPubKey, destination)) {
                    output_obj.pushKV("scriptAddress", EncodeDestination(destination));
                } else {
                    output_obj.pushKV("scriptAddress", "");
                }
                output_obj.pushKV("outputHash", output.out.GetHash().ToString());
                output_obj.pushKV("scriptPubKey", HexStr(output.out.scriptPubKey));

                const CAmount amount_navoshi = output.value.GetUint64();
                output_obj.pushKV("amount", ValueFromAmount(amount_navoshi));
                output_obj.pushKV("amount_navoshi", amount_navoshi);

                output_obj.pushKV("blinding_key", HexStr(output.blindingKey.GetVch()));
                output_obj.pushKV("gamma", HexStr(output.gamma.GetVch()));

                std::shared_ptr<wallet::CWallet> const wallet = wallet::GetWalletForJSONRPCRequest(request);
                if (wallet) {
                    LOCK(wallet->cs_wallet);

                    auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();

                    blsct::PrivateKey spending_key;
                    bool found = blsct_km->GetSpendingKeyForOutputWithCache(output.out, spending_key) && spending_key.IsValid();

                    if (!found) {
                        // For HTLC and other complex scripts, try all BLS public keys in the script
                        std::vector<blsct::PublicKey> script_keys;
                        if (blsct_km->ExtractAllSpendingKeysFromScript(output.out.scriptPubKey, script_keys)) {
                            for (const auto& candidate_key : script_keys) {
                                auto hashId = blsct_km->GetHashId(output.out.blsctData.blindingKey, candidate_key);
                                if (!hashId.IsNull() && blsct_km->GetSpendingKeyForOutputWithCache(output.out, hashId, spending_key) && spending_key.IsValid()) {
                                    found = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (found) {
                        output_obj.pushKV("spending_key", HexStr(spending_key.GetScalar().GetVch()));
                    }
                }

                outputs.push_back(output_obj);
            }
            result.pushKV("outputs", outputs);

            // Add fee
            result.pushKV("fee", (int64_t)unsigned_tx.GetFee());

            return result;
        },
    };
}

static RPCHelpMan getblsctrecoverydata()
{
    return RPCHelpMan{
        "getblsctrecoverydata",
        "\nGet BLSCT recovery data for transaction output(s)\n",
        {
            {"txid_or_hex", RPCArg::Type::STR, RPCArg::Optional::NO, "The transaction id, raw transaction hex, or output outpoint hash"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "The output index. If omitted, shows data for all outputs. Ignored when an outpoint hash is provided."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                                              {RPCResult::Type::ARR, "outputs", "Array of outputs with recovery data", {
                                                                                                                           {RPCResult::Type::OBJ, "", "", {
                                                                                                                                                              {RPCResult::Type::NUM, "vout", "Output index"},
                                                                                                                                                              {RPCResult::Type::STR_HEX, "out_hash", "The output hash (hex string)"},
                                                                                                                                                              {RPCResult::Type::STR_HEX, "script", "The script hex"},
                                                                                                                                                              {RPCResult::Type::STR_AMOUNT, "amount", "The recovered amount in " + CURRENCY_UNIT},
                                                                                                                                                              {RPCResult::Type::NUM, "amount_navoshi", "The recovered amount in navoshis"},
                                                                                                                                                              {RPCResult::Type::STR_HEX, "gamma", "The gamma value (hex string)"},
                                                                                                                                                              {RPCResult::Type::STR, "message", "The memo/message associated with this output"},
                                                                                                                                                          }},
                                                                                                                       }},
                                          }},
        RPCExamples{HelpExampleCli("getblsctrecoverydata", "\"mytxid\"") + HelpExampleCli("getblsctrecoverydata", "\"mytxid\" 1") + HelpExampleRpc("getblsctrecoverydata", "\"mytxid\", 1")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> const wallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!wallet) return NullUniValue;

            LOCK(wallet->cs_wallet);

            CMutableTransaction mtx;
            uint256 hash;
            bool is_hex_input = false;
            bool is_outpoint_input = false;
            COutPoint outpoint;
            const wallet::CWalletTx* wallet_tx_ptr = nullptr;
            const wallet::CWalletOutput* wallet_output_ptr = nullptr;

            // Parse input as either txid, outpoint hash, or raw hex
            std::string input = request.params[0].get_str();

            if (input.length() == 64 && IsHex(input)) {
                hash = uint256S(input);
                wallet_tx_ptr = wallet->GetWalletTx(hash);

                if (!wallet_tx_ptr) {
                    // Fallback: treat input as an outpoint hash
                    outpoint = COutPoint(hash);
                    wallet_output_ptr = wallet->GetWalletOutput(outpoint);
                    if (!wallet_output_ptr) {
                        wallet_tx_ptr = wallet->GetWalletTxFromOutpoint(outpoint);
                    }
                    if (!wallet_tx_ptr && !wallet_output_ptr) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction or outpoint not found in wallet");
                    }
                    is_outpoint_input = true;
                }

                if (wallet_tx_ptr) {
                    mtx = CMutableTransaction(*wallet_tx_ptr->tx);
                }
            } else {
                if (!DecodeHexTx(mtx, input)) {
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Transaction decode failed");
                }
                hash = mtx.GetHash();
                is_hex_input = true;
            }

            int specific_vout = -1;
            if (!request.params[1].isNull()) {
                specific_vout = request.params[1].getInt<int>();
                if (specific_vout < 0 || (!wallet_output_ptr && specific_vout >= (int)mtx.vout.size())) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "vout index out of range");
                }
            }

            if (is_outpoint_input && wallet_tx_ptr) {
                const auto it = std::find_if(mtx.vout.begin(), mtx.vout.end(), [&](const CTxOut& out) { return out.GetHash() == outpoint.hash; });
                if (it == mtx.vout.end()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Outpoint not found in transaction");
                }

                int outpoint_vout = static_cast<int>(std::distance(mtx.vout.begin(), it));
                if (specific_vout == -1) {
                    specific_vout = outpoint_vout;
                } else if (specific_vout != outpoint_vout) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Provided vout does not match outpoint");
                }
            }

            UniValue result(UniValue::VOBJ);
            UniValue outputs(UniValue::VARR);

            if (is_hex_input) {
                // For hex input, use BLSCT key manager to recover outputs
                auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();

                for (size_t i = 0; i < mtx.vout.size(); i++) {
                    if (specific_vout != -1 && specific_vout != (int)i) {
                        continue;
                    }

                    const CTxOut& out = mtx.vout[i];
                    UniValue output(UniValue::VOBJ);
                    output.pushKV("vout", (int)i);
                    output.pushKV("script", HexStr(out.scriptPubKey));
                    output.pushKV("out_hash", out.GetHash().GetHex());

                    // Use RecoverOutputs for hex input
                    auto recovery_result = blsct_km->RecoverOutputs({out});
                    if (recovery_result.is_completed && !recovery_result.amounts.empty()) {
                        const auto& recovery_data = recovery_result.amounts[0];
                        output.pushKV("amount", ValueFromAmount(recovery_data.amount));
                        output.pushKV("amount_navoshi", recovery_data.amount);
                        output.pushKV("gamma", blsct::FormatRecoveredGamma(recovery_data.gamma));
                        output.pushKV("message", recovery_data.message);
                    } else {
                        output.pushKV("amount", ValueFromAmount(0));
                        output.pushKV("amount_navoshi", 0);
                        output.pushKV("gamma", "");
                        output.pushKV("message", "");
                    }
                    outputs.push_back(output);
                }
            } else if (wallet_output_ptr) {
                UniValue output(UniValue::VOBJ);
                output.pushKV("vout", 0);
                output.pushKV("script", HexStr(wallet_output_ptr->out->scriptPubKey));
                output.pushKV("out_hash", wallet_output_ptr->GetOutputHash().GetHex());

                const auto& recovery_data = wallet_output_ptr->blsctRecoveryData;
                output.pushKV("amount", ValueFromAmount(recovery_data.amount));
                output.pushKV("amount_navoshi", recovery_data.amount);
                output.pushKV("gamma", blsct::FormatRecoveredGamma(recovery_data.gamma));
                output.pushKV("message", recovery_data.message);

                outputs.push_back(output);
            } else {
                // For txid input, use wallet transaction
                if (!wallet_tx_ptr) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction not found in wallet");
                }

                for (size_t i = 0; i < mtx.vout.size(); i++) {
                    if (specific_vout != -1 && specific_vout != (int)i) {
                        continue;
                    }

                    UniValue output(UniValue::VOBJ);
                    output.pushKV("vout", (int)i);
                    output.pushKV("script", HexStr(mtx.vout[i].scriptPubKey));
                    output.pushKV("out_hash", mtx.vout[i].GetHash().GetHex());

                    // Get recovery data from wallet transaction
                    auto recovery_data = wallet_tx_ptr->GetBLSCTRecoveryData(i);
                    output.pushKV("amount", ValueFromAmount(recovery_data.amount));
                    output.pushKV("amount_navoshi", recovery_data.amount);
                    output.pushKV("gamma", blsct::FormatRecoveredGamma(recovery_data.gamma));
                    output.pushKV("message", recovery_data.message);

                    outputs.push_back(output);
                }
            }

            result.pushKV("outputs", outputs);
            return result;
        },
    };
}

static RPCHelpMan getblsctrecoverydatawithnonce()
{
    return RPCHelpMan{
        "getblsctrecoverydatawithnonce",
        "\nGet BLSCT recovery data for outputs in a transaction using a specified shared public nonce.\n"
        "Accepts a transaction hex string or an output outpoint hash.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction hex string or output outpoint hash"},
            {"nonce", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The shared public nonce to use for recovery (48-byte hex public key)"},
            {"vout", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "If specified, only return data for this output index. Ignored when an outpoint hash is provided."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                                              {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                                              {RPCResult::Type::ARR, "outputs", "Array of transaction outputs", {
                                                                                                                    {RPCResult::Type::OBJ, "", "", {
                                                                                                                                                       {RPCResult::Type::NUM, "vout", "The output index"},
                                                                                                                                                       {RPCResult::Type::STR_HEX, "out_hash", "The output hash (hex string)"},
                                                                                                                                                       {RPCResult::Type::STR_HEX, "script", "The script hex"},
                                                                                                                                                       {RPCResult::Type::STR_AMOUNT, "amount", "The recovered amount in " + CURRENCY_UNIT},
                                                                                                                                                       {RPCResult::Type::NUM, "amount_navoshi", "The recovered amount in navoshis"},
                                                                                                                                                       {RPCResult::Type::STR_HEX, "gamma", "The gamma value (hex string)"},
                                                                                                                                                       {RPCResult::Type::STR, "message", "The memo/message associated with this output"},
                                                                                                                                                   }},
                                                                                                                }},
                                          }},
        RPCExamples{HelpExampleCli("getblsctrecoverydatawithnonce", "\"hexstring\" \"nonce\"") + HelpExampleCli("getblsctrecoverydatawithnonce", "\"hexstring\" \"nonce\" 1") + HelpExampleRpc("getblsctrecoverydatawithnonce", "\"hexstring\", \"nonce\", 1")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> const wallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!wallet) return NullUniValue;

            LOCK(wallet->cs_wallet);

            CMutableTransaction mtx;
            uint256 hash;
            bool is_outpoint_input = false;
            COutPoint outpoint;
            const wallet::CWalletOutput* wallet_output_ptr = nullptr;

            // Parse hex transaction or outpoint hash
            std::string input = request.params[0].get_str();
            if (input.length() == 64 && IsHex(input)) {
                hash = uint256S(input);

                // Try to fetch via txid
                if (const wallet::CWalletTx* wallet_tx_ptr = wallet->GetWalletTx(hash)) {
                    mtx = CMutableTransaction(*wallet_tx_ptr->tx);
                } else {
                    // Fallback: treat input as an outpoint hash
                    outpoint = COutPoint(hash);
                    wallet_output_ptr = wallet->GetWalletOutput(outpoint);
                    if (wallet_output_ptr) {
                        is_outpoint_input = true;
                    } else if (const wallet::CWalletTx* wallet_tx_ptr = wallet->GetWalletTxFromOutpoint(outpoint)) {
                        mtx = CMutableTransaction(*wallet_tx_ptr->tx);
                        is_outpoint_input = true;
                    }
                }
            }

            if (mtx.vout.empty() && !wallet_output_ptr) {
                // If not loaded from wallet, try to decode raw hex
                if (!DecodeHexTx(mtx, input)) {
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Transaction decode failed");
                }
                hash = mtx.GetHash();
            }

            // Parse shared public nonce
            std::string nonce_hex = request.params[1].get_str();
            std::vector<unsigned char> nonce_bytes = ParseHex(nonce_hex);
            if (nonce_bytes.size() != blsct::PublicKey::SIZE) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Nonce must be 48 bytes (96 hex characters)");
            }
            blsct::PublicKey nonce_pubkey(nonce_bytes);
            if (!nonce_pubkey.IsValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid nonce public key");
            }
            MclG1Point nonce = nonce_pubkey.GetG1Point();

            int specific_vout = -1;
            if (!request.params[2].isNull()) {
                specific_vout = request.params[2].getInt<int>();
                if (specific_vout < 0 || (!wallet_output_ptr && specific_vout >= (int)mtx.vout.size())) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "vout index out of range");
                }
            }

            if (is_outpoint_input && !wallet_output_ptr) {
                const auto it = std::find_if(mtx.vout.begin(), mtx.vout.end(), [&](const CTxOut& out) { return out.GetHash() == outpoint.hash; });
                if (it == mtx.vout.end()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Outpoint not found in transaction");
                }

                int outpoint_vout = static_cast<int>(std::distance(mtx.vout.begin(), it));
                if (specific_vout == -1) {
                    specific_vout = outpoint_vout;
                } else if (specific_vout != outpoint_vout) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Provided vout does not match outpoint");
                }
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", hash.GetHex());
            UniValue outputs(UniValue::VARR);

            // Use BLSCT key manager to recover outputs with specified nonce
            auto blsct_km = wallet->GetOrCreateBLSCTKeyMan();

            auto append_output = [&](const CTxOut& out, int vout_index, const uint256* out_hash_override = nullptr, const range_proof::RecoveredData<Mcl>* recovery_override = nullptr) {
                UniValue output(UniValue::VOBJ);
                output.pushKV("vout", vout_index);
                output.pushKV("out_hash", (out_hash_override ? *out_hash_override : out.GetHash()).GetHex());
                output.pushKV("script", HexStr(out.scriptPubKey));

                if (recovery_override) {
                    output.pushKV("amount", ValueFromAmount(recovery_override->amount));
                    output.pushKV("amount_navoshi", recovery_override->amount);
                    output.pushKV("gamma", blsct::FormatRecoveredGamma(recovery_override->gamma));
                    output.pushKV("message", recovery_override->message);
                } else {
                    // Use the specified nonce for recovery
                    auto recovery_result = blsct_km->RecoverOutputsWithNonce({out}, nonce);
                    if (recovery_result.is_completed && !recovery_result.amounts.empty()) {
                        auto recovery_data = recovery_result.amounts[0];
                        output.pushKV("amount", ValueFromAmount(recovery_data.amount));
                        output.pushKV("amount_navoshi", recovery_data.amount);
                        output.pushKV("gamma", blsct::FormatRecoveredGamma(recovery_data.gamma));
                        output.pushKV("message", recovery_data.message);
                    } else {
                        // Recovery failed with specified nonce
                        output.pushKV("amount", ValueFromAmount(0));
                        output.pushKV("amount_navoshi", 0);
                        output.pushKV("gamma", "");
                        output.pushKV("message", "");
                    }
                }
                outputs.push_back(output);
            };

            if (wallet_output_ptr) {
                const uint256 output_hash = wallet_output_ptr->GetOutputHash();
                if (wallet_output_ptr->fBLSCTOutput && !wallet_output_ptr->out->HasBLSCTRangeProof()) {
                    append_output(*wallet_output_ptr->out, 0, &output_hash, &wallet_output_ptr->blsctRecoveryData);
                } else {
                    append_output(*wallet_output_ptr->out, 0, &output_hash);
                }
            } else {
                for (size_t i = 0; i < mtx.vout.size(); i++) {
                    if (specific_vout != -1 && specific_vout != (int)i) {
                        continue;
                    }

                    append_output(mtx.vout[i], static_cast<int>(i));
                }
            }

            result.pushKV("outputs", outputs);
            return result;
        },
    };
}

RPCHelpMan deriveblsctnonce()
{
    return RPCHelpMan{
        "deriveblsctnonce",
        "\nDerive the shared public nonce for a BLSCT output from a destination address and blinding key.\n"
        "This can be used together with getblsctrecoverydatawithnonce for outputs whose amount was blinded\n"
        "against the destination's public view key, including HTLC outputs constructed from address_a.\n",
        {
            {"blinding_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 32-byte blinding key (hex) used when creating the output"},
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The BLSCT destination address used to derive the shared public nonce"},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "nonce", "The shared public nonce as a 48-byte public key (hex)"},
        RPCExamples{
            HelpExampleCli("deriveblsctnonce", "\"0102030405060708091011121314151617181920212223242526272829303132\" \"rnv1...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> const pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            auto blinding_key_bytes = ParseHex(request.params[0].get_str());
            if (blinding_key_bytes.size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Blinding key must be 32 bytes (64 hex characters)");
            }
            Scalar blindingKey(blinding_key_bytes);

            std::string address_str = request.params[1].get_str();
            CTxDestination dest = DecodeDestination(address_str);
            if (!IsValidDestination(dest) || dest.index() != 8) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid BLSCT address");
            }
            auto dpk = std::get<blsct::DoublePublicKey>(dest);

            MclG1Point vk_point;
            if (!dpk.GetViewKey(vk_point)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Could not extract view key from address");
            }

            return HexStr(blsct::PublicKey(vk_point * blindingKey).GetVch());
        },
    };
}

static RPCHelpMan signblsmessage()
{
    return RPCHelpMan{
        "signblsmessage",
        "\nSign a message using a BLS private key.\n",
        {
            {"private_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The BLS private key in hex format"},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to sign"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                                              {RPCResult::Type::STR_HEX, "signature", "The signature in hex format"},
                                              {RPCResult::Type::STR_HEX, "public_key", "The public key corresponding to the private key"},
                                          }},
        RPCExamples{HelpExampleCli("signblsmessage", "\"private_key_hex\" \"Hello, world!\"") + HelpExampleRpc("signblsmessage", "\"private_key_hex\", \"Hello, world!\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::string private_key_hex = request.params[0].get_str();
            std::string message = request.params[1].get_str();

            // Parse private key from hex
            std::vector<unsigned char> private_key_bytes;
            try {
                private_key_bytes = ParseHex(private_key_hex);
                if (private_key_bytes.size() != 32) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Private key must be 32 bytes (64 hex characters)");
                }
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid private key hex string: %s", e.what()));
            }

            // Create private key object
            blsct::PrivateKey private_key = MclScalar(private_key_bytes);
            if (!private_key.IsValid()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid private key");
            }

            // Hash the message with prefix
            uint256 message_hash = MessageHash("BLSCT_MESSAGE_SIGN_" + message);
            blsct::Message blsct_message(message_hash.begin(), message_hash.end());

            // Sign the message
            blsct::Signature signature = private_key.Sign(blsct_message);

            // Get the public key
            blsct::PublicKey public_key = private_key.GetPublicKey();

            UniValue result(UniValue::VOBJ);
            result.pushKV("signature", HexStr(signature.GetVch()));
            result.pushKV("public_key", HexStr(public_key.GetVch()));

            return result;
        },
    };
}

static RPCHelpMan verifyblsmessage()
{
    return RPCHelpMan{
        "verifyblsmessage",
        "\nVerify a BLS message signature.\n",
        {
            {"public_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The BLS public key in hex format"},
            {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message that was signed"},
            {"signature", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The signature in hex format"},
        },
        RPCResult{
            RPCResult::Type::BOOL, "valid", "Whether the signature is valid"},
        RPCExamples{HelpExampleCli("verifyblsmessage", "\"public_key_hex\" \"Hello, world!\" \"signature_hex\"") + HelpExampleRpc("verifyblsmessage", "\"public_key_hex\", \"Hello, world!\", \"signature_hex\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::string public_key_hex = request.params[0].get_str();
            std::string message = request.params[1].get_str();
            std::string signature_hex = request.params[2].get_str();

            // Parse public key from hex
            std::vector<unsigned char> public_key_bytes;
            try {
                public_key_bytes = ParseHex(public_key_hex);
                if (public_key_bytes.size() != 48) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Public key must be 48 bytes (96 hex characters)");
                }
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid public key hex string: %s", e.what()));
            }

            // Parse signature from hex
            std::vector<unsigned char> signature_bytes;
            try {
                signature_bytes = ParseHex(signature_hex);
                if (signature_bytes.size() != 96) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Signature must be 96 bytes (192 hex characters)");
                }
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid signature hex string: %s", e.what()));
            }

            // Create public key and signature objects
            blsct::PublicKey public_key(public_key_bytes);
            blsct::Signature signature(signature_bytes);

            // Hash the message with prefix
            uint256 message_hash = MessageHash("BLSCT_MESSAGE_SIGN_" + message);
            blsct::Message blsct_message(message_hash.begin(), message_hash.end());

            // Verify the signature
            bool valid = public_key.Verify(blsct_message, signature);

            return valid;
        },
    };
}


RPCHelpMan deriveblsctspendingkey()
{
    return RPCHelpMan{
        "deriveblsctspendingkey",
        "\nDerive the private spending key for an HTLC/atomic-swap output.\n"
        "Given the blinding key used when creating the output and a BLSCT address owned by this wallet,\n"
        "returns the private spending key needed to spend via the corresponding script branch.\n"
        "\nNOTE: this RPC only works correctly with the wallet's top-level (default) BLSCT address.\n"
        "Sub-addresses use a different spend-key point (D = sk + H(vk,i,j)·G) and will not derive\n"
        "the correct spending key with this call.\n",
        {
            {"blinding_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 32-byte blinding key (hex) used when creating the HTLC output"},
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The BLSCT address to derive the spending key for (must be owned by this wallet)"},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "spending_key", "The 32-byte private spending key (hex)"},
        RPCExamples{
            HelpExampleCli("deriveblsctspendingkey", "\"0102030405060708091011121314151617181920212223242526272829303132\" \"rnv1...\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> const pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            LOCK(pwallet->cs_wallet);
            auto blsct_km = pwallet->GetOrCreateBLSCTKeyMan();

            auto blinding_key_bytes = ParseHex(request.params[0].get_str());
            if (blinding_key_bytes.size() != 32) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Blinding key must be 32 bytes (64 hex characters)");
            }
            Scalar blindingKey(blinding_key_bytes);

            std::string address_str = request.params[1].get_str();
            CTxDestination dest = DecodeDestination(address_str);
            if (!IsValidDestination(dest) || dest.index() != 8) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid BLSCT address");
            }
            auto dpk = std::get<blsct::DoublePublicKey>(dest);

            MclG1Point sk_point;
            if (!dpk.GetSpendKey(sk_point)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Could not extract spend key from address");
            }
            CKeyID hashId = blsct::PublicKey(sk_point).GetID();

            // blsctData.blindingKey in a real output is D * blindingKey_scalar
            // (where D = sub-address spend key point), NOT blindingKey * G.
            // CalculatePrivateSpendingKey computes t = blindingKey_point * viewKey,
            // so we must set it to sk_point * blindingKey to match CreateOutput's
            // GenerateKeys which stores sk * blindingKey.
            CTxOut fakeOut;
            fakeOut.blsctData.blindingKey = sk_point * blindingKey;

            blsct::PrivateKey spendingKey;
            if (!blsct_km->GetSpendingKeyForOutputWithCache(fakeOut, hashId, spendingKey) || !spendingKey.IsValid()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to derive spending key — address may not belong to this wallet");
            }

            return HexStr(spendingKey.GetScalar().GetVch());
        },
    };
}

RPCHelpMan getblsctoutput()
{
    return RPCHelpMan{
        "getblsctoutput",
        "Look up a BLSCT output by its output hash.\n",
        {
            {"output_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The output hash to look up."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR_HEX, "outputHash", "The output hash"},
                {RPCResult::Type::NUM, "amount", "The recovered amount in navoshis"},
                {RPCResult::Type::STR, "memo", "The recovered memo"},
                {RPCResult::Type::STR_HEX, "tokenId", "The token id (if applicable)"},
                {RPCResult::Type::NUM, "confirmations", "The number of confirmations"},
                {RPCResult::Type::BOOL, "spendable", "Whether the output is spendable (not spent)"},
            }},
        RPCExamples{HelpExampleRpc("getblsctoutput", "\"a685e520f85d111a6c55bd2b8226f6b916a3bcdd3b549c75e0abddc55df70951\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> const pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            pwallet->BlockUntilSyncedToCurrentChain();

            LOCK(pwallet->cs_wallet);

            uint256 output_hash(ParseHashV(request.params[0], "output_hash"));

            // Try mapOutpointHashToWalletTx first (transaction storage mode)
            auto it = pwallet->mapOutpointHashToWalletTx.find(output_hash);
            if (it != pwallet->mapOutpointHashToWalletTx.end()) {
                const wallet::CWalletTx* wtx = it->second;
                for (size_t i = 0; i < wtx->tx->vout.size(); i++) {
                    if (wtx->tx->vout[i].GetHash() == output_hash) {
                        auto recoveryData = wtx->GetBLSCTRecoveryData(i);
                        const auto& tokenId = wtx->tx->vout[i].tokenId;

                        UniValue result(UniValue::VOBJ);
                        result.pushKV("outputHash", output_hash.GetHex());
                        result.pushKV("amount", recoveryData.amount);
                        result.pushKV("memo", recoveryData.message);
                        result.pushKV("tokenId", tokenId.IsNull() ? "" : tokenId.ToString());
                        result.pushKV("confirmations", pwallet->GetTxDepthInMainChain(*wtx));
                        result.pushKV("spendable", !pwallet->IsSpent(COutPoint(output_hash)));
                        return result;
                    }
                }
            }

            // Try mapOutputs (output storage mode)
            for (const auto& [outpoint, wout] : pwallet->mapOutputs) {
                if (wout.out && wout.GetOutputHash() == output_hash) {
                    const auto& tokenId = wout.out->tokenId;

                    UniValue result(UniValue::VOBJ);
                    result.pushKV("outputHash", output_hash.GetHex());
                    result.pushKV("amount", wout.blsctRecoveryData.amount);
                    result.pushKV("memo", wout.blsctRecoveryData.message);
                    result.pushKV("tokenId", tokenId.IsNull() ? "" : tokenId.ToString());
                    result.pushKV("confirmations", pwallet->GetOutputDepthInMainChain(wout));
                    result.pushKV("spendable", !wout.IsSpent());
                    return result;
                }
            }

            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Output not found");
        },
    };
}

Span<const CRPCCommand> GetBLSCTWalletRPCCommands()
{
    static const CRPCCommand commands[]{
        {"blsct", &createnft},
        {"blsct", &createtoken},
        {"blsct", &minttoken},
        {"blsct", &mintnft},
        {"blsct", &getblsctbalance},
        {"blsct", &getnftbalance},
        {"blsct", &gettokenbalance},
        {"blsct", &listblscttransactions},
        {"blsct", &listblsctunspent},
        {"blsct", &sendtoblsctaddress},
        {"blsct", &sendnfttoblsctaddress},
        {"blsct", &sendtokentoblsctaddress},
        {"blsct", &stakelock},
        {"blsct", &stakeunlock},
        {"blsct", &setblsctseed},
        {"blsct", &createblsctbalanceproof},
        {"blsct", &createblsctrawtransaction},
        {"blsct", &fundblsctrawtransaction},
        {"blsct", &unlockblsctoutpoint},
        {"blsct", &signblsctrawtransaction},
        {"blsct", &decodeblsctrawtransaction},
        {"blsct", &getblsctrecoverydata},
        {"blsct", &getblsctrecoverydatawithnonce},
        {"blsct", &deriveblsctnonce},
        {"blsct", &signblsmessage},
        {"blsct", &verifyblsmessage},
        {"blsct", &deriveblsctspendingkey},
        {"blsct", &getblsctoutput},
    };
    return commands;
}
