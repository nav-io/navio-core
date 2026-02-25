// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/tokens/predicate_exec.h>

namespace blsct {
bool ExecutePredicate(const ParsedPredicate& predicate, CCoinsViewCache& view, const bool& fDisconnect)
{
    if (predicate.IsCreateTokenPredicate()) {
        auto hash = predicate.GetPublicKey().GetHash();

        blsct::TokenEntry token;
        if (view.GetToken(hash, token) == !fDisconnect) return false;

        if (fDisconnect)
            view.EraseToken(hash);
        else {
            view.AddToken(hash, blsct::TokenInfo{predicate.GetTokenInfo()});
        }

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

        if ((CAmount)predicate.GetNftId() >= token.info.nTotalSupply || predicate.GetNftId() < 0)
            return false;

        if ((token.mapMintedNft.find(predicate.GetNftId()) != token.mapMintedNft.end()) == !fDisconnect)
            return false;

        if (fDisconnect)
            token.mapMintedNft.erase(predicate.GetNftId());
        else
            token.mapMintedNft[predicate.GetNftId()] = predicate.GetNftMetaData();

        view.AddToken(hash, std::move(token));

        return true;
    } else if (predicate.IsPayFeePredicate()) {
        return true;
    } else if (predicate.IsDataPredicate()) {
        return true;
    }

    return false;
}

bool ExecutePredicate(const VectorPredicate& vch, CCoinsViewCache& view, const bool& fDisconnect)
{
    try {
        return ExecutePredicate(ParsePredicate(vch), view, fDisconnect);
    } catch (const std::ios_base::failure&) {
        // If predicate parsing fails, treat it as a no-op predicate
        // This can happen with invalid or random predicate data
        return true;
    }
}
} // namespace blsct