// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/private_key.h>
#include <blsct/tokens/info.h>
#include <blsct/tokens/predicate_exec.h>
#include <blsct/tokens/predicate_parser.h>
#include <coins.h>
#include <consensus/amount.h>
#include <test/util/setup_common.h>
#include <txdb.h>

#include <boost/test/unit_test.hpp>

#include <limits>

BOOST_FIXTURE_TEST_SUITE(predicate_exec_tests, BasicTestingSetup)

static blsct::CreateTokenPredicate MakeCreate(uint8_t type, CAmount total_supply, uint8_t key_seed = 7)
{
    blsct::PrivateKey owner_sk(key_seed);
    blsct::TokenInfo info;
    info.type = static_cast<blsct::TokenType>(type);
    info.publicKey = owner_sk.GetPublicKey();
    info.nTotalSupply = total_supply;
    return blsct::CreateTokenPredicate(info);
}

BOOST_AUTO_TEST_CASE(create_token_valid_ok)
{
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache view{&base};

    auto p = MakeCreate(blsct::TOKEN, /*total_supply=*/1000);
    blsct::ParsedPredicate parsed(p);
    BOOST_CHECK(blsct::ExecutePredicate(parsed, view));
}

BOOST_AUTO_TEST_CASE(create_nft_valid_ok)
{
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache view{&base};

    auto p = MakeCreate(blsct::NFT, /*total_supply=*/10);
    blsct::ParsedPredicate parsed(p);
    BOOST_CHECK(blsct::ExecutePredicate(parsed, view));
}

// Unknown token type is rejected: TokenEntry::Serialize would persist neither
// nSupply nor mapMintedNft, and such a token can never be minted.
BOOST_AUTO_TEST_CASE(create_token_unknown_type_rejected)
{
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache view{&base};

    auto p = MakeCreate(/*type=*/7, /*total_supply=*/1000);
    blsct::ParsedPredicate parsed(p);
    BOOST_CHECK(!blsct::ExecutePredicate(parsed, view));
}

// Negative supply is rejected (never satisfiable by Mint / the NFT-id check).
BOOST_AUTO_TEST_CASE(create_token_negative_supply_rejected)
{
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache view{&base};

    auto p = MakeCreate(blsct::TOKEN, /*total_supply=*/-1);
    blsct::ParsedPredicate parsed(p);
    BOOST_CHECK(!blsct::ExecutePredicate(parsed, view));
}

// Fungible token supply above MoneyRange is rejected.
BOOST_AUTO_TEST_CASE(create_token_supply_above_money_range_rejected)
{
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache view{&base};

    auto p = MakeCreate(blsct::TOKEN, /*total_supply=*/MAX_MONEY + 1);
    blsct::ParsedPredicate parsed(p);
    BOOST_CHECK(!blsct::ExecutePredicate(parsed, view));
}

BOOST_AUTO_TEST_SUITE_END()
