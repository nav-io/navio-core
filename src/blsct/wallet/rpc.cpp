// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/wallet/rpc.h>
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

            const std::string address = request.params[1].get_str();

            const bool verbose{request.params[4].isNull() ? false : request.params[11].get_bool()};

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

            const std::string address = request.params[2].get_str();

            const bool verbose{request.params[4].isNull() ? false : request.params[4].get_bool()};

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
                vecOutputs = AvailableBlsctCoins(*pwallet, &cctl, filter_coins).All();
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
    };
    return commands;
}