// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/balance_proof.h>
#include <blsct/wallet/rpc.h>
#include <blsct/wallet/unsigned_transaction.h>
#include <coins.h>
#include <core_io.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <validation.h>
#include <wallet/receive.h>
#include <wallet/rpc/util.h>

namespace blsct {
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
    if (verbose) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("txid", tx->GetHash().GetHex());
        return entry;
    }
    return tx->GetHash().GetHex();
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
    ret.pushKV("hash", hash);
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
                                              {RPCResult::Type::STR_HEX, "hash", "The broadcasted transaction hash"},
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
                                              {RPCResult::Type::STR_HEX, "hash", "The broadcasted transaction hash"},
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
            RPCResult::Type::STR_HEX, "hash", "The transaction hash"},
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
            RPCResult::Type::STR_HEX, "hash", "The transaction hash"},
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
        "\nReturns the total available balance.\n"
        "The available balance is what the wallet considers currently spendable, and is\n"
        "thus affected by options which limit spendability such as -spendzeroconfchange.\n",
        {
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{0}, "Only include transactions confirmed at least this many times."},
            {"include_watchonly", RPCArg::Type::BOOL, RPCArg::DefaultHint{"true for watch-only wallets, otherwise false"}, "Also include balance in watch-only addresses (see 'importaddress')"},
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

            const auto bal = GetBlsctBalance(*pwallet, min_depth);

            return ValueFromAmount(bal.m_mine_trusted + (include_watchonly ? bal.m_watchonly_trusted : 0));
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

            const auto bal = GetBalance(*pwallet, min_depth, false, token_id);

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

            UniValue ret(UniValue::VOBJ);

            for (auto& it : token.mapMintedNft) {
                const auto bal = GetBalance(*pwallet, min_depth, false, TokenId(token_id, it.first));

                if ((bal.m_mine_trusted + (include_watchonly ? bal.m_watchonly_trusted : 0)) > 0) {
                    UniValue metadata(UniValue::VOBJ);
                    for (auto& md_it : it.second) {
                        metadata.pushKV(md_it.first, md_it.second);
                    }
                    ret.pushKV(strprintf("%llu", it.first), metadata);
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
                      RPCResult::Type::STR_HEX, "txid", "The transaction id."},
            RPCResult{
                "if verbose is set to true",
                RPCResult::Type::OBJ,
                "",
                "",
                {{RPCResult::Type::STR_HEX, "txid", "The transaction id."}},
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
                      RPCResult::Type::STR_HEX, "txid", "The transaction id."},
            RPCResult{
                "if verbose is set to true",
                RPCResult::Type::OBJ,
                "",
                "",
                {{RPCResult::Type::STR_HEX, "txid", "The transaction id."}},
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
                      RPCResult::Type::STR_HEX, "txid", "The transaction id."},
            RPCResult{
                "if verbose is set to true",
                RPCResult::Type::OBJ,
                "",
                "",
                {{RPCResult::Type::STR_HEX, "txid", "The transaction id."}},
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
                      RPCResult::Type::STR_HEX, "txid", "The transaction id."},
            RPCResult{
                "if verbose is set to true",
                RPCResult::Type::OBJ,
                "",
                "",
                {{RPCResult::Type::STR_HEX, "txid", "The transaction id."}},
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
                      RPCResult::Type::STR_HEX, "txid", "The transaction id."},
            RPCResult{
                "if verbose is set to true",
                RPCResult::Type::OBJ,
                "",
                "",
                {{RPCResult::Type::STR_HEX, "txid", "The transaction id."}},
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
                                                                                 {RPCResult::Type::STR_HEX, "txid", "the transaction id"},
                                                                                 {RPCResult::Type::NUM, "vout", "the vout value"},
                                                                                 {RPCResult::Type::STR, "address", /*optional=*/true, "the navio address"},
                                                                                 {RPCResult::Type::STR, "label", /*optional=*/true, "The associated label, or \"\" for the default label"},
                                                                                 {RPCResult::Type::STR_AMOUNT, "amount", "the transaction output amount in " + CURRENCY_UNIT},
                                                                                 {RPCResult::Type::NUM, "confirmations", "The number of confirmations"},
                                                                                 {RPCResult::Type::BOOL, "spendable", "Whether we have the private keys to spend this output"},
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
                entry.pushKV("txid", out.outpoint.hash.GetHex());
                entry.pushKV("vout", (int)out.outpoint.n);

                if (fValidAddress) {
                    entry.pushKV("address", EncodeDestination(address));

                    const auto* address_book_entry = pwallet->FindAddressBookEntry(address);
                    if (address_book_entry) {
                        entry.pushKV("label", address_book_entry->GetLabel());
                    }

                    entry.pushKV("amount", ValueFromAmount(out.txout.nValue));
                    entry.pushKV("confirmations", out.depth);
                    entry.pushKV("spendable", out.spendable);
                    results.push_back(entry);
                }
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
            if (request.params[1].isNull()) {
                master_priv_key = blsct_km->GenerateNewSeed();
            } else {
                CKey key = DecodeSecret(request.params[1].get_str());
                if (!key.IsValid()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
                }

                if (blsct_km->HaveKey(key.GetPubKey().GetID())) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Already have this key (either as an BLSCT seed or as a loose private key)");
                }

                master_priv_key = key.GetPrivKey();
            }

            blsct_km->SetHDSeed(master_priv_key);

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
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                                              {RPCResult::Type::STR_HEX, "proof", "The serialized balance proof"},
                                          }},
        RPCExamples{HelpExampleCli("createblsctbalanceproof", "1.0") + HelpExampleRpc("createblsctbalanceproof", "1.0")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::vector<COutPoint> outpoints;
            CAmount target_amount = AmountFromValue(request.params[0]);

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
            wallet::CoinsResult available_coins = AvailableCoins(*pwallet, nullptr, std::nullopt, filter_coins);

            if (available_coins.GetTotalAmount() < target_amount) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");
            }

            // Collect outpoints and create balance proof
            for (const auto& [type, outputs] : available_coins.coins) {
                for (const auto& output : outputs) {
                    outpoints.push_back(output.outpoint);
                }
            }

            blsct::BalanceProof proof(outpoints, target_amount, *pwallet);

            // Serialize the proof
            DataStream ss{};
            ss << proof;

            UniValue result(UniValue::VOBJ);
            result.pushKV("proof", HexStr(ss));

            return result;
        },
    };
}

RPCHelpMan verifyblsctbalanceproof()
{
    return RPCHelpMan{
        "verifyblsctbalanceproof",
        "Verifies a zero-knowledge balance proof\n",
        {
            {"proof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The serialized balance proof"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                                              {RPCResult::Type::BOOL, "valid", "Whether the proof is valid"},
                                              {RPCResult::Type::NUM, "min_amount", "The minimum amount proven"},
                                          }},
        RPCExamples{HelpExampleCli("verifyblsctbalanceproof", "\"<hex>\"") + HelpExampleRpc("verifyblsctbalanceproof", "\"<hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            LOCK(cs_main);
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            Chainstate& active_chainstate = chainman.ActiveChainstate();

            CCoinsViewCache* coins_view;
            coins_view = &active_chainstate.CoinsTip();

            // Deserialize the proof
            std::vector<unsigned char> proof_data = ParseHex(request.params[0].get_str());
            DataStream ss{proof_data};
            blsct::BalanceProof proof;
            try {
                ss >> proof;
            } catch (const std::exception& e) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid proof format");
            }

            // Verify the proof
            bool valid = proof.Verify(coins_view);

            UniValue result(UniValue::VOBJ);
            result.pushKV("valid", valid);
            result.pushKV("min_amount", ValueFromAmount(proof.GetMinAmount()));

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
                            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id"},
                            {"vout", RPCArg::Type::NUM, RPCArg::Optional::NO, "The output number"},
                            {"value", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "The input value in satoshis"},
                            {"gamma", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The gamma value for the input (hex string)"},
                            {"private_key", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The private key for signing this input (hex string)"},
                            {"is_staked_commitment", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Whether this input is a staked commitment"},
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
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The BLSCT address to send to"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount in " + CURRENCY_UNIT},
                            {"memo", RPCArg::Type::STR, RPCArg::Default{""}, "A memo used to store in the transaction.\n"
                                                                             "The recipient will see its value."},
                            {"token_id", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "The token id for token transactions"},
                        },
                    },
                },
            },
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "transaction", "hex string of the transaction"},
        RPCExamples{
            HelpExampleCli("createblsctrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0,\\\"value\\\":1000000,\\\"gamma\\\":\\\"1234567890abcdef\\\",\\\"private_key\\\":\\\"abcdef1234567890\\\"}]\" \"[{\\\"address\\\":\\\"address\\\",\\\"amount\\\":0.01,\\\"memo\\\":\\\"memo\\\",\\\"token_id\\\":\\\"tokenid\\\"}]\"") +
            HelpExampleCli("createblsctrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"address\\\":\\\"address\\\",\\\"amount\\\":0.01}]\"")},
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

                const Txid txid = Txid::FromUint256(ParseHashO(o, "txid"));
                const int nOut = o.find_value("vout").getInt<int>();
                if (nOut < 0)
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout must be positive");

                blsct::UnsignedInput unsigned_input;
                unsigned_input.in.prevout = COutPoint(txid, nOut);

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
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid gamma hex string");
                        }
                    }
                }

                // Parse optional private key field
                if (o.exists("private_key")) {
                    std::string sk_hex = o["private_key"].get_str();
                    if (!sk_hex.empty()) {
                        try {
                            std::vector<unsigned char> sk_bytes = ParseHex(sk_hex);
                            if (sk_bytes.size() != 32) {
                                throw JSONRPCError(RPC_INVALID_PARAMETER, "Private key must be 32 bytes (64 hex characters)");
                            }
                            unsigned_input.sk = blsct::PrivateKey(Scalar(sk_bytes));
                        } catch (const std::exception& e) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid private key hex string");
                        }
                    }
                }

                // Parse optional is_staked_commitment field
                if (o.exists("is_staked_commitment")) {
                    unsigned_input.is_staked_commitment = o["is_staked_commitment"].get_bool();
                }

                // If value or gamma are not provided, try to get them from the wallet
                if (!o.exists("value") || !o.exists("gamma")) {
                    // Get the transaction from the wallet
                    auto wallet_tx = pwallet->GetWalletTx(txid);
                    if (!wallet_tx) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Transaction %s not found in wallet", txid.GetHex()));
                    }

                    // Get BLSCT recovery data for this output
                    auto recovery_data = wallet_tx->GetBLSCTRecoveryData(nOut);
                    if (recovery_data.amount == 0 && recovery_data.gamma == Scalar(0) && recovery_data.id == 0 && recovery_data.message == "") {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("BLSCT recovery data not available for output %s:%d", txid.GetHex(), nOut));
                    }

                    // Set value if not provided
                    if (!o.exists("value")) {
                        unsigned_input.value = Scalar(recovery_data.amount);
                    }

                    // Set gamma if not provided
                    if (!o.exists("gamma")) {
                        unsigned_input.gamma = recovery_data.gamma;
                    }
                }

                // If private key is not provided, try to get it from the wallet
                if (!o.exists("private_key")) {
                    // Get the output to determine the token ID
                    auto wallet_tx = pwallet->GetWalletTx(txid);
                    if (!wallet_tx) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Transaction %s not found in wallet", txid.GetHex()));
                    }

                    const CTxOut& txout = wallet_tx->tx->vout[nOut];

                    // Get the spending key for this output
                    auto spending_key = blsct_km->GetSpendingKeyForOutputWithCache(txout);
                    if (!spending_key.IsValid()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Spending key not available for output %s:%d", txid.GetHex(), nOut));
                    }

                    unsigned_input.sk = spending_key;
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
            for (unsigned int idx = 0; idx < outputs.size(); idx++) {
                const UniValue& output = outputs[idx];
                const UniValue& o = output.get_obj();

                if (!o.exists("address") || !o.exists("amount")) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Each output must have an address and amount");
                }

                std::string address = o["address"].get_str();
                CTxDestination destination = DecodeDestination(address);
                if (!IsValidDestination(destination) || destination.index() != 8) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid BLSCT address: ") + address);
                }

                CAmount nAmount = AmountFromValue(o["amount"]);
                if (nAmount < 0)
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount, must be positive");

                std::string memo = o.exists("memo") ? o["memo"].get_str() : "";
                TokenId token_id;
                if (o.exists("token_id") && !o["token_id"].get_str().empty()) {
                    token_id = TokenId(ParseHashV(o["token_id"], "token_id"));
                }

                blsct::SubAddress subAddress(std::get<blsct::DoublePublicKey>(destination));
                blsct::UnsignedOutput unsigned_output = CreateOutput(subAddress.GetKeys(), nAmount, memo, token_id, Scalar::Rand(), type);
                unsigned_outputs.push_back(unsigned_output);
            }

            // Create unsigned transaction
            blsct::UnsignedTransaction unsigned_tx;

            unsigned_tx = blsct::UnsignedTransaction();

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
        "\nAdd inputs to a BLSCT transaction until it has enough value to cover outputs and fee.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex string of the raw transaction"},
            {"changeaddress", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "The BLSCT address to receive the change"},
        },
        RPCResult{
            RPCResult::Type::STR_HEX, "transaction", "hex string of the funded transaction"},
        RPCExamples{
            HelpExampleCli("fundblsctrawtransaction", "\"hexstring\"") +
            HelpExampleCli("fundblsctrawtransaction", "\"hexstring\" \"changeaddress\"")},
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
            auto unsigned_tx = unsigned_tx_opt.value();

            // Calculate total output amount
            CAmount output_value = 0;
            for (const auto& out : unsigned_tx.GetOutputs()) {
                output_value += out.value.GetUint64();
            }

            // Add fixed fee
            CAmount required_value = output_value + COIN / 100; // 0.01 fixed fee
            unsigned_tx.SetFee(COIN / 100);

            // Get change address
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

            // Find unspent outputs to use as inputs
            wallet::CoinFilterParams filter_coins;
            filter_coins.only_blsct = true;
            filter_coins.skip_locked = false;
            filter_coins.include_immature_coinbase = false;
            wallet::CoinsResult available_outputs = AvailableCoins(*pwallet, nullptr, std::nullopt, filter_coins);

            CAmount input_value = 0;
            for (const auto& [type, outputs] : available_outputs.coins) {
                for (const auto& output : outputs) {
                    auto wallet_tx = pwallet->GetWalletTx(output.outpoint.hash);
                    if (!wallet_tx) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Transaction %s not found in wallet", output.outpoint.hash.GetHex()));
                    }

                    // Get BLSCT recovery data for this output
                    auto recovery_data = wallet_tx->GetBLSCTRecoveryData(output.outpoint.n);

                    if (recovery_data.amount == 0 && recovery_data.gamma == Scalar(0) && recovery_data.id == 0 && recovery_data.message == "") {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("BLSCT recovery data not available for output %s:%d", output.outpoint.hash.GetHex(), output.outpoint.n));
                    }

                    blsct::UnsignedInput input;
                    input.in.prevout = output.outpoint;
                    input.value = Scalar(recovery_data.amount);
                    input.gamma = recovery_data.gamma;

                    // Get the spending key for this output
                    auto spending_key = blsct_km->GetSpendingKeyForOutputWithCache(output.txout);
                    if (!spending_key.IsValid()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Spending key not available for output %s:%d", output.outpoint.hash.GetHex(), output.outpoint.n));
                    }

                    input.sk = spending_key;

                    unsigned_tx.AddInput(input);
                    input_value += recovery_data.amount;

                    if (input_value >= required_value) break;
                }

                if (input_value < required_value) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");
                }

                // Add change output if needed
                if (input_value > required_value) {
                    CAmount change_value = input_value - required_value;
                    blsct::SubAddress change_subaddr(std::get<blsct::DoublePublicKey>(change_dest));
                    blsct::UnsignedOutput change_output = CreateOutput(change_subaddr.GetKeys(), change_value, "", TokenId(), Scalar::Rand());
                    unsigned_tx.AddOutput(change_output);
                }

                return HexStr(unsigned_tx.Serialize());
            }
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
            HelpExampleCli("signblsctrawtransaction", "\"hexstring\"") +
            HelpExampleRpc("signblsctrawtransaction", "\"hexstring\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::shared_ptr<wallet::CWallet> const pwallet = wallet::GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            // Make sure the results are valid at least up to the most recent block
            // the user could have gotten from another RPC command prior to now
            pwallet->BlockUntilSyncedToCurrentChain();

            LOCK(pwallet->cs_wallet);

            std::vector<unsigned char> tx_data = ParseHex(request.params[0].get_str());
            auto unsigned_tx_opt = blsct::UnsignedTransaction::Deserialize(tx_data);
            if (!unsigned_tx_opt) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Transaction deserialization failed");
            }
            auto unsigned_tx = unsigned_tx_opt.value();

            // Sign the transaction
            auto tx_opt = unsigned_tx.Sign();
            if (!tx_opt) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign transaction");
            }
            auto tx = tx_opt.value();

            return EncodeHexTx(tx);
        },
    };
}

RPCHelpMan decodeblsctrawunsignedtransaction()
{
    return RPCHelpMan{
        "decodeblsctrawunsignedtransaction",
        "\nDecode a BLSCT raw transaction and return a JSON object describing the transaction structure.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction hex string"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                                              {RPCResult::Type::ARR, "inputs", "Array of transaction inputs", {
                                                                                                                  {RPCResult::Type::OBJ, "", "", {
                                                                                                                                                     {RPCResult::Type::STR_HEX, "txid", "The transaction id"},
                                                                                                                                                     {RPCResult::Type::NUM, "vout", "The output number"},
                                                                                                                                                     {RPCResult::Type::NUM, "value", "The input value"},
                                                                                                                                                     {RPCResult::Type::STR_HEX, "gamma", "The gamma value (hex string)"},
                                                                                                                                                     {RPCResult::Type::BOOL, "is_staked_commitment", "Whether this input is a staked commitment"},
                                                                                                                                                 }},
                                                                                                              }},
                                              {RPCResult::Type::ARR, "outputs", "Array of transaction outputs", {
                                                                                                                    {RPCResult::Type::OBJ, "", "", {
                                                                                                                                                       {RPCResult::Type::STR_AMOUNT, "amount", "The amount in " + CURRENCY_UNIT},
                                                                                                                                                       {RPCResult::Type::STR_HEX, "blinding_key", "The blinding key (hex string)"},
                                                                                                                                                       {RPCResult::Type::STR_HEX, "gamma", "The gamma value (hex string)"},
                                                                                                                                                   }},
                                                                                                                }},
                                              {RPCResult::Type::STR_AMOUNT, "fee", "The transaction fee in " + CURRENCY_UNIT},
                                          }},
        RPCExamples{HelpExampleCli("decodeblsctrawunsignedtransaction", "\"hexstring\"") + HelpExampleRpc("decodeblsctrawunsignedtransaction", "\"hexstring\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            std::vector<unsigned char> tx_data = ParseHex(request.params[0].get_str());
            auto unsigned_tx_opt = blsct::UnsignedTransaction::Deserialize(tx_data);
            if (!unsigned_tx_opt) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Transaction deserialization failed");
            }
            auto unsigned_tx = unsigned_tx_opt.value();

            UniValue result(UniValue::VOBJ);

            // Decode inputs
            UniValue inputs(UniValue::VARR);
            for (const auto& input : unsigned_tx.GetInputs()) {
                UniValue input_obj(UniValue::VOBJ);
                input_obj.pushKV("txid", input.in.prevout.hash.GetHex());
                input_obj.pushKV("vout", (int)input.in.prevout.n);
                input_obj.pushKV("value", ValueFromAmount(input.value.GetUint64()));
                input_obj.pushKV("gamma", HexStr(input.gamma.GetVch()));
                input_obj.pushKV("is_staked_commitment", input.is_staked_commitment);
                inputs.push_back(input_obj);
            }
            result.pushKV("inputs", inputs);

            // Decode outputs
            UniValue outputs(UniValue::VARR);
            for (const auto& output : unsigned_tx.GetOutputs()) {
                UniValue output_obj(UniValue::VOBJ);
                output_obj.pushKV("amount", ValueFromAmount(output.value.GetUint64()));
                output_obj.pushKV("blinding_key", HexStr(output.blindingKey.GetVch()));
                output_obj.pushKV("gamma", HexStr(output.gamma.GetVch()));
                outputs.push_back(output_obj);
            }
            result.pushKV("outputs", outputs);

            // Add fee
            result.pushKV("fee", ValueFromAmount(unsigned_tx.GetFee()));

            return result;
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
        {"blsct", &signblsctrawtransaction},
        {"blsct", &decodeblsctrawunsignedtransaction},
    };
    return commands;
}

void RegisterBLSCTUtilsRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"blsct", &verifyblsctbalanceproof},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}