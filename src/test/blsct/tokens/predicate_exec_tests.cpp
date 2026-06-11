// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blsct/private_key.h>
#include <blsct/tokens/info.h>
#include <blsct/tokens/predicate_exec.h>
#include <blsct/tokens/predicate_parser.h>
#include <coins.h>
#include <test/util/setup_common.h>
#include <txdb.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(predicate_exec_tests, BasicTestingSetup)

static blsct::PublicKey RegisterToken(CCoinsViewCache& view, blsct::TokenType type, CAmount total_supply)
{
    blsct::PrivateKey owner_sk(7);
    blsct::PublicKey owner_pk = owner_sk.GetPublicKey();

    blsct::TokenInfo info;
    info.type = type;
    info.publicKey = owner_pk;
    info.nTotalSupply = total_supply;

    blsct::TokenEntry entry(info);
    view.AddToken(owner_pk.GetHash(), std::move(entry));
    return owner_pk;
}

// Minting a fungible token against a TOKEN-type entry works.
BOOST_AUTO_TEST_CASE(mint_token_on_token_type_ok)
{
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache view{&base};

    auto owner_pk = RegisterToken(view, blsct::TOKEN, /*total_supply=*/1000);

    blsct::MintTokenPredicate p(owner_pk, /*amount=*/100);
    blsct::ParsedPredicate parsed(p);
    BOOST_CHECK(blsct::ExecutePredicate(parsed, view));
}

// Regression: minting a fungible token against an NFT-type entry must be
// rejected. MintToken mutates nSupply, which TokenEntry serializes only for
// TOKEN-type entries; against an NFT-type token nSupply would not persist,
// so the supply cap resets to 0 on reload and the owner could re-mint
// unbounded amounts of the fungible asset H(pubkey) (inflation).
BOOST_AUTO_TEST_CASE(mint_token_on_nft_type_rejected)
{
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache view{&base};

    auto owner_pk = RegisterToken(view, blsct::NFT, /*total_supply=*/1000);

    blsct::MintTokenPredicate p(owner_pk, /*amount=*/100);
    blsct::ParsedPredicate parsed(p);
    BOOST_CHECK(!blsct::ExecutePredicate(parsed, view));
}

// Minting an NFT against an NFT-type entry works.
BOOST_AUTO_TEST_CASE(mint_nft_on_nft_type_ok)
{
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache view{&base};

    auto owner_pk = RegisterToken(view, blsct::NFT, /*total_supply=*/10);

    blsct::MintNftPredicate p(owner_pk, /*nftId=*/3, {});
    blsct::ParsedPredicate parsed(p);
    BOOST_CHECK(blsct::ExecutePredicate(parsed, view));
}

// Symmetric regression: minting an NFT against a TOKEN-type entry must be
// rejected (mapMintedNft is only serialized for NFT-type entries).
BOOST_AUTO_TEST_CASE(mint_nft_on_token_type_rejected)
{
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache view{&base};

    auto owner_pk = RegisterToken(view, blsct::TOKEN, /*total_supply=*/10);

    blsct::MintNftPredicate p(owner_pk, /*nftId=*/3, {});
    blsct::ParsedPredicate parsed(p);
    BOOST_CHECK(!blsct::ExecutePredicate(parsed, view));
}

BOOST_AUTO_TEST_SUITE_END()
