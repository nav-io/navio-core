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
            // Validate the attacker-supplied TokenInfo before storing it.
            // Nothing else checks these fields, and CreateToken writes them
            // verbatim into the consensus token set.
            const blsct::TokenInfo info = predicate.GetTokenInfo();
            // Only TOKEN/NFT are known types; TokenEntry::Serialize persists
            // nSupply or mapMintedNft based on this. An unknown type would
            // serialize neither (silently dropping all supply state) and can
            // never be minted, so reject it outright.
            if (info.type != blsct::TOKEN && info.type != blsct::NFT)
                return false;
            // nTotalSupply must be non-negative: it is a signed CAmount used
            // as the upper bound in Mint()/the NFT-id check, and a negative
            // value only yields a permanently dead token. For fungible TOKEN
            // the supply is an amount, so additionally bound it by MoneyRange;
            // NFT supply is a count of ids (not an amount), so only the
            // non-negative constraint applies there.
            if (info.nTotalSupply < 0)
                return false;
            if (info.type == blsct::TOKEN && !MoneyRange(info.nTotalSupply))
                return false;
            view.AddToken(hash, blsct::TokenInfo{info});
        }

        return true;
    } else if (predicate.IsMintTokenPredicate()) {
        auto hash = predicate.GetPublicKey().GetHash();

        blsct::TokenEntry token;

        if (!view.GetToken(hash, token))
            return false;
        // The fungible-token mint path mutates nSupply, which TokenEntry only
        // serializes for TOKEN-type entries (NFT-type serializes mapMintedNft
        // instead). Minting against an NFT-type token would bump an nSupply
        // that is never persisted -- after a flush it reads back 0, letting
        // the owner re-mint up to nTotalSupply repeatedly (supply-cap break /
        // inflation). The token type is attacker-chosen at creation, so it
        // must be validated here.
        if (token.info.type != blsct::TOKEN)
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

        // Symmetric guard: the NFT mint path mutates mapMintedNft, which is
        // only serialized for NFT-type entries. Reject mints against a
        // non-NFT token.
        if (token.info.type != blsct::NFT)
            return false;

        if ((CAmount)predicate.GetNftId() >= token.info.nTotalSupply)
            return false;

        if ((token.mapMintedNft.contains(predicate.GetNftId())) == !fDisconnect)
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