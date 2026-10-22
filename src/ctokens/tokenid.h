// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CTOKENS_TOKENID_H
#define BITCOIN_CTOKENS_TOKENID_H

#include <streams.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <optional>
#include <string>
#include <string_view>

class TokenId
{
public:
    uint256 token;
    uint64_t subid;

    TokenId(const uint256& t = uint256(), const uint64_t& i = std::numeric_limits<uint64_t>::max()) : token(t), subid(i) {}

    void SetNull()
    {
        token = uint256();
        subid = std::numeric_limits<uint64_t>::max();
    }

    bool IsNFT() const
    {
        return token != uint256() && subid != std::numeric_limits<uint64_t>::max();
    };

    bool IsNull() const { return token == uint256() && subid == std::numeric_limits<uint64_t>::max(); }

    std::string ToString() const { return strprintf("%s%s", token.ToString(), subid == std::numeric_limits<uint64_t>::max() ? "" : strprintf("#%d", subid)); }

    /**
     * Parse the form ToString() prints: the 64-hex token hash, followed by
     * "#<decimal subid>" for an NFT. The empty string is NAV. The subid must be
     * spelled exactly as ToString() emits it (no sign, whitespace, hex or leading
     * zeros), so it has one form. The hash is case-insensitive, like ParseHashV's,
     * so upper- or mixed-case hex parses to the same id as ToString()'s lower case.
     *
     * Not every ToString() output parses back: TokenId{uint256(), n} prints as
     * "000...0#n" but is rejected, since NAV has no NFTs. Such an id is not
     * tradeable; only a malformed RFQ off the wire could carry one.
     */
    static std::optional<TokenId> FromString(std::string_view str)
    {
        if (str.empty()) return TokenId();
        const size_t sep = str.find('#');
        const std::string_view hex = str.substr(0, sep);
        if (hex.size() != uint256::size() * 2 || !IsHex(hex)) return std::nullopt;
        TokenId id(uint256S(std::string{hex}));
        if (sep == std::string_view::npos) return id;
        const std::string_view sub = str.substr(sep + 1);
        if (sub.size() > 1 && sub.front() == '0') return std::nullopt;
        const std::optional<uint64_t> subid = ToIntegral<uint64_t>(sub);
        if (!subid) return std::nullopt;
        id.subid = *subid;
        // A suffix must name an NFT: the fungible sentinel would make "<hex>#<max>"
        // a second spelling of "<hex>", and NAV has no NFTs.
        if (!id.IsNFT()) return std::nullopt;
        return id;
    }

    friend bool operator==(const TokenId& a, const TokenId& b) { return a.token == b.token && a.subid == b.subid; }

    friend bool operator<(const TokenId& a, const TokenId& b)
    {
        if (a.token == b.token) {
            return a.subid < b.subid;
        }
        return a.token < b.token;
    }

    friend bool operator!=(const TokenId& a, const TokenId& b) { return !(a == b); }

    SERIALIZE_METHODS(TokenId, obj) { READWRITE(obj.token, obj.subid); }
};

#endif // BITCOIN_CTOKENS_TOKENID_H
