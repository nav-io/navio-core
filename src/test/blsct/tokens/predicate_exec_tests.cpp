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

#include <limits>

BOOST_FIXTURE_TEST_SUITE(predicate_exec_tests, BasicTestingSetup)

// Register an NFT token with a small fixed supply, returning its consensus
// token key (publicKey hash) and the owner public key.
static blsct::PublicKey RegisterNftToken(CCoinsViewCache& view, CAmount total_supply)
{
    blsct::PrivateKey owner_sk(7);
    blsct::PublicKey owner_pk = owner_sk.GetPublicKey();

    blsct::TokenInfo info;
    info.type = blsct::NFT;
    info.publicKey = owner_pk;
    info.nTotalSupply = total_supply;

    blsct::TokenEntry entry(info, std::map<uint64_t, std::map<std::string, std::string>>{});
    view.AddToken(owner_pk.GetHash(), std::move(entry));
    return owner_pk;
}

BOOST_AUTO_TEST_CASE(mint_nft_within_supply_ok)
{
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache view{&base};

    auto owner_pk = RegisterNftToken(view, /*total_supply=*/10);

    blsct::MintNftPredicate p(owner_pk, /*nftId=*/3, {});
    blsct::ParsedPredicate parsed(p);
    BOOST_CHECK(blsct::ExecutePredicate(parsed, view));
}

BOOST_AUTO_TEST_CASE(mint_nft_at_or_above_supply_rejected)
{
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache view{&base};

    auto owner_pk = RegisterNftToken(view, /*total_supply=*/10);

    // id == supply is out of [0, supply)
    blsct::MintNftPredicate at(owner_pk, /*nftId=*/10, {});
    blsct::ParsedPredicate parsed_at(at);
    BOOST_CHECK(!blsct::ExecutePredicate(parsed_at, view));
}

// Regression: a uint64 nftId with the high bit set must NOT be accepted. The
// old check cast nftId to signed CAmount, making any id >= 2^63 negative and
// thus "< nTotalSupply", bypassing the issuer's fixed-supply bound.
BOOST_AUTO_TEST_CASE(mint_nft_high_bit_id_rejected)
{
    CCoinsViewDB base{{.path = "test", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache view{&base};

    auto owner_pk = RegisterNftToken(view, /*total_supply=*/10);

    const uint64_t high_bit_id = (static_cast<uint64_t>(1) << 63) + 5; // negative if cast to int64
    blsct::MintNftPredicate evil(owner_pk, high_bit_id, {});
    blsct::ParsedPredicate parsed(evil);
    BOOST_CHECK(!blsct::ExecutePredicate(parsed, view));

    // And the largest possible uint64 likewise.
    blsct::MintNftPredicate evil_max(owner_pk, std::numeric_limits<uint64_t>::max(), {});
    blsct::ParsedPredicate parsed_max(evil_max);
    BOOST_CHECK(!blsct::ExecutePredicate(parsed_max, view));
}

BOOST_AUTO_TEST_SUITE_END()
