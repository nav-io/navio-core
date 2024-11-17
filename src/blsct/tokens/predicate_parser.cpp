// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/tokens/predicate_parser.h>

namespace blsct {
ParsedPredicate ParsePredicate(const VectorPredicate& vch)
{
    DataStream ss{vch};
    PredicateOperation op;
    ss >> Using<CustomUintFormatter<1>>(op);

    if (op == CREATE_TOKEN) {
        CreateTokenPredicate p;
        ss >> p;
        return p;
    } else if (op == MINT) {
        MintTokenPredicate p;
        ss >> p;
        return p;
    } else if (op == NFT_MINT) {
        MintNftPredicate p;
        ss >> p;
        return p;
    } else if (op == PAY_FEE) {
        PayFeePredicate p;
        ss >> p;
        return p;
    } else {
        throw std::ios_base::failure("unknown predicate operation");
    }
}

std::string PredicateToString(const VectorPredicate& vch)
{
    auto predicate = ParsePredicate(vch);

    std::string ret;

    if (predicate.IsCreateTokenPredicate())
        ret = "CREATE_TOKEN";
    else if (predicate.IsMintTokenPredicate())
        ret = "MINT_TOKEN";
    else if (predicate.IsMintNftPredicate())
        ret = "MINT_NFT";
    else if (predicate.IsPayFeePredicate())
        ret = "PAY_FEE";

    return ret;
}

bool ExecutePredicate(const ParsedPredicate& predicate, CCoinsViewCache& view, const bool& fDisconnect)
{
    if (predicate.IsCreateTokenPredicate()) {
        auto hash = predicate.GetPublicKey().GetHash();

        blsct::TokenEntry token;
        if (view.GetToken(hash, token) == !fDisconnect) return false;

        if (fDisconnect)
            view.EraseToken(hash);
        else
            view.AddToken(hash, std::move(predicate.GetTokenInfo()));

        return true;
    } else if (predicate.IsMintTokenPredicate()) {
        auto hash = predicate.GetPublicKey().GetHash();

        blsct::TokenEntry token;

        if (!view.GetToken(hash, token))
            return false;
        if (!token.Mint(predicate.GetAmount() * (1 - 2 * fDisconnect)))
            return false;

        view.AddToken(hash, std::move(token));

        return true;
    } else if (predicate.IsMintNftPredicate()) {
        auto hash = predicate.GetPublicKey().GetHash();

        blsct::TokenEntry token;

        if (!view.GetToken(hash, token))
            return false;

        if (predicate.GetNftId() >= token.info.nTotalSupply || predicate.GetNftId() < 0)
            return false;

        if (token.mapMintedNft.contains(predicate.GetNftId()) == !fDisconnect)
            return false;

        if (fDisconnect)
            token.mapMintedNft.erase(predicate.GetNftId());
        else
            token.mapMintedNft[predicate.GetNftId()] = predicate.GetNftMetaData();

        view.AddToken(hash, std::move(token));

        return true;
    } else if (predicate.IsPayFeePredicate()) {
        return true;
    }

    return false;
}

bool ExecutePredicate(const VectorPredicate& vch, CCoinsViewCache& view, const bool& fDisconnect)
{
    return ExecutePredicate(ParsePredicate(vch), view, fDisconnect);
}
} // namespace blsct