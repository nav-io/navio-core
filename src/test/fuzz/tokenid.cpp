// Copyright (c) 2026 The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ctokens/tokenid.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cassert>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>

FUZZ_TARGET(tokenid)
{
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    // Whatever FromString() accepts, ToString() prints back in the one canonical
    // spelling (only the hash's case may differ), and that spelling parses to the
    // same id.
    const std::string str{fuzzed_data_provider.ConsumeRandomLengthString()};
    if (const std::optional<TokenId> parsed{TokenId::FromString(str)}) {
        const std::string printed{parsed->ToString()};
        if (!str.empty()) assert(printed == ToLower(str));
        const std::optional<TokenId> reparsed{TokenId::FromString(printed)};
        assert(reparsed && *reparsed == *parsed);
        assert(reparsed->ToString() == printed);
    }

    // FromString() inverts ToString() for every id except NAV with a subid,
    // which ToString() can print but FromString() rejects by design.
    const uint64_t fungible{std::numeric_limits<uint64_t>::max()};
    const uint256 token{fuzzed_data_provider.ConsumeBool() ? uint256{} : ConsumeUInt256(fuzzed_data_provider)};
    const uint64_t subid{fuzzed_data_provider.ConsumeBool() ? fungible : fuzzed_data_provider.ConsumeIntegral<uint64_t>()};
    const TokenId id{token, subid};
    const std::optional<TokenId> round{TokenId::FromString(id.ToString())};
    if (token == uint256{} && subid != fungible) {
        assert(!round);
    } else {
        assert(round && *round == id);
    }
}
