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

std::vector<RPCResult> metadataResult = {
    {RPCResult::Type::OBJ, "metadata", "", {
                                               {RPCResult::Type::STR, "key", "the metadata key"},
                                               {RPCResult::Type::STR, "value", "the metadata value"},
                                           }}};

std::vector<RPCResult>
    tokenInfoResult = {
        RPCResult{RPCResult::Type::STR_HEX, "tokenId", "the token id"}, RPCResult{RPCResult::Type::STR_HEX, "publicKey", "the token public key"},
        RPCResult{RPCResult::Type::STR, "type", "the token type"},
        RPCResult{RPCResult::Type::ARR, "metadata", "the token metadata", metadataResult},
        RPCResult{RPCResult::Type::NUM, "maxSupply", "the token max supply"},
        RPCResult{RPCResult::Type::NUM, "currentSupply", true, "the token current supply"},
        RPCResult{RPCResult::Type::ARR, "mintedNft", true, "the nfts already minted", {{RPCResult::Type::OBJ, "", "", {{RPCResult::Type::STR, "index", "the nft index"}, {RPCResult::Type::ARR, "metadata", "the token metadata", metadataResult}}}}}

};

void TokenToUniValue(UniValue& obj, const blsct::TokenEntry& token)
{
    obj.pushKV("publicKey", token.info.publicKey.ToString());
    obj.pushKV("type", blsct::TokenTypeToString(token.info.type));
    UniValue metadata{UniValue::VARR};
    for (auto& it : token.info.mapMetadata) {
        UniValue metadataObj{UniValue::VOBJ};
        metadataObj.pushKV("key", it.first);
        metadataObj.pushKV("value", it.second);
        metadata.push_back(metadataObj);
    }
    obj.pushKV("metadata", metadata);
    obj.pushKV("maxSupply", token.info.nTotalSupply);
    if (token.info.type == blsct::TokenType::TOKEN)
        obj.pushKV("currentSupply", token.nSupply);
    else if (token.info.type == blsct::TokenType::NFT) {
        UniValue mintedNft{UniValue::VARR};
        for (auto& it : token.mapMintedNft) {
            UniValue nftMetadata{UniValue::VARR};
            UniValue nftObject{UniValue::VOBJ};
            for (auto& it2 : it.second) {
                UniValue nftMetadataObj{UniValue::VOBJ};
                nftMetadataObj.pushKV("key", it2.first);
                nftMetadataObj.pushKV("value", it2.second);
                nftMetadata.push_back(nftMetadataObj);
            }
            nftObject.pushKV("index", strprintf("%llu", it.first));
            nftObject.pushKV("metadata", nftMetadata);
            mintedNft.push_back(nftObject);
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
        RPCExamples{HelpExampleCli("gettoken", "ba12afc43322f204fe6236b11a0f85b5d9edcb09f446176c73fe4abe99a17edd") + HelpExampleRpc("gettoken", "ba12afc43322f204fe6236b11a0f85b5d9edcb09f446176c73fe4abe99a17edd")},
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
        RPCExamples{HelpExampleCli("listtokens", "") + HelpExampleRpc("listtokens", "")},
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