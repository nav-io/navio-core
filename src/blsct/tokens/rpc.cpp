// Copyright (c) 2024 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <validation.h>

std::vector<RPCResult> tokenInfoResult = {
    RPCResult{RPCResult::Type::STR_HEX, "tokenId", "the token id"},
    RPCResult{RPCResult::Type::STR_HEX, "publicKey", "the token public key"},
    RPCResult{RPCResult::Type::STR, "type", "the token type"},
    RPCResult{RPCResult::Type::OBJ_DYN, "metadata", "the token metadata", {{RPCResult::Type::STR, "xxxx", "value"}}},
    RPCResult{RPCResult::Type::NUM, "maxSupply", "the token max supply"},
    RPCResult{RPCResult::Type::NUM, "currentSupply", true, "the token current supply"},
    RPCResult{RPCResult::Type::OBJ_DYN, "mintedNft", true, "the nfts already minted", {{RPCResult::Type::OBJ_DYN, "index", "metadata", {{RPCResult::Type::STR, "xxxx", "value"}}}}},

};

void TokenToUniValue(UniValue& obj, const blsct::TokenEntry& token)
{
    obj.pushKV("publicKey", token.info.publicKey.ToString());
    obj.pushKV("type", blsct::TokenTypeToString(token.info.type));
    UniValue metadata{UniValue::VOBJ};
    for (auto& it : token.info.mapMetadata) {
        metadata.pushKV(it.first, it.second);
    }
    obj.pushKV("metadata", metadata);
    obj.pushKV("maxSupply", token.info.nTotalSupply);
    if (token.info.type == blsct::TokenType::TOKEN)
        obj.pushKV("currentSupply", token.nSupply);
    else if (token.info.type == blsct::TokenType::NFT) {
        UniValue mintedNft{UniValue::VOBJ};
        for (auto& it : token.mapMintedNft) {
            UniValue nftMetadata{UniValue::VOBJ};
            for (auto& it2 : it.second) {
                nftMetadata.pushKV(it2.first, it2.second);
            }
            mintedNft.pushKV(strprintf("%llu", it.first), nftMetadata);
        }
        obj.pushKV("mintedNft", mintedNft);
    }
}

RPCHelpMan
gettoken()
{
    return RPCHelpMan{
        "gettoken",
        "Returns an object containing information about a token.\n",
        {
            {
                "token_id",
                RPCArg::Type::STR_HEX,
                RPCArg::Optional::NO,
                "The token id",
            },
        },
        RPCResult{RPCResult::Type::OBJ, "", "", tokenInfoResult},
        RPCExamples{HelpExampleCli("gettoken", "ba12afc43322f204fe6236b11a0f85b5d9edcb09f446176c73fe4abe99a17edd")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            LOCK(cs_main);
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            Chainstate& active_chainstate = chainman.ActiveChainstate();

            CCoinsViewCache* coins_view;
            coins_view = &active_chainstate.CoinsTip();

            uint256 tokenId(ParseHashV(request.params[0], "tokenId"));
            blsct::TokenEntry token;
            if (!coins_view->GetToken(tokenId, token))
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown token");

            UniValue obj{UniValue::VOBJ};
            obj.pushKV("tokenId", tokenId.ToString());
            TokenToUniValue(obj, token);
            return obj;
        },
    };
};

RPCHelpMan
listtokens()
{
    return RPCHelpMan{
        "listtokens",
        "Returns an array containing the tokens list.\n",
        {},
        RPCResult{RPCResult::Type::ARR, "", "", {
                                                    RPCResult{RPCResult::Type::OBJ, "", "", tokenInfoResult},
                                                }},
        RPCExamples{HelpExampleCli("listtokens", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            LOCK(cs_main);
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            Chainstate& active_chainstate = chainman.ActiveChainstate();

            CCoinsViewCache* coins_view;
            coins_view = &active_chainstate.CoinsTip();

            TokensMap tokens;
            coins_view->GetAllTokens(tokens);

            UniValue ret{UniValue::VARR};

            for (auto& it : tokens) {
                uint256 key = it.first;
                blsct::TokenEntry token = it.second.token;
                UniValue obj{UniValue::VOBJ};
                obj.pushKV("tokenId", key.ToString());
                TokenToUniValue(obj, token);
                ret.push_back(obj);
            }

            return ret;
        },
    };
};

void RegisterTokenRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"blsct", &listtokens},
        {"blsct", &gettoken},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
