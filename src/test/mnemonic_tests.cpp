// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mnemonic/mnemonic.h>
#include <mnemonic/wordlist.h>
#include <blsct/eip_2333/bls12_381_keygen.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <set>
#include <string>

BOOST_FIXTURE_TEST_SUITE(mnemonic_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(wordlist_has_2048_entries)
{
    BOOST_CHECK_EQUAL(mnemonic::wordlist_en.size(), 2048U);
    int non_empty = 0;
    for (const auto* word : mnemonic::wordlist_en) {
        if (word != nullptr && word[0] != '\0') non_empty++;
    }
    BOOST_CHECK_EQUAL(non_empty, 2048);
}

BOOST_AUTO_TEST_CASE(wordlist_is_sorted)
{
    for (size_t i = 1; i < mnemonic::wordlist_en.size(); i++) {
        BOOST_CHECK_MESSAGE(
            std::string(mnemonic::wordlist_en[i - 1]) < std::string(mnemonic::wordlist_en[i]),
            "Word list not sorted at index " + std::to_string(i) + ": \"" +
            mnemonic::wordlist_en[i - 1] + "\" >= \"" + mnemonic::wordlist_en[i] + "\"");
    }
}

BOOST_AUTO_TEST_CASE(wordlist_has_no_duplicates)
{
    std::set<std::string> seen;
    for (const auto* word : mnemonic::wordlist_en) {
        BOOST_CHECK_MESSAGE(seen.insert(std::string(word)).second,
            "Duplicate word in list: " + std::string(word));
    }
}

BOOST_AUTO_TEST_CASE(entropy_to_mnemonic_vector_1)
{
    auto entropy = ParseHex("00000000000000000000000000000000");
    std::string expected = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    BOOST_CHECK_EQUAL(mnemonic::EntropyToMnemonic(entropy), expected);
}

BOOST_AUTO_TEST_CASE(entropy_to_mnemonic_vector_2)
{
    auto entropy = ParseHex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f");
    std::string expected = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    BOOST_CHECK_EQUAL(mnemonic::EntropyToMnemonic(entropy), expected);
}

BOOST_AUTO_TEST_CASE(entropy_to_mnemonic_vector_3)
{
    auto entropy = ParseHex("0000000000000000000000000000000000000000000000000000000000000000");
    std::string expected = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    BOOST_CHECK_EQUAL(mnemonic::EntropyToMnemonic(entropy), expected);
}

BOOST_AUTO_TEST_CASE(entropy_to_mnemonic_vector_4)
{
    auto entropy = ParseHex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f");
    std::string expected = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";
    BOOST_CHECK_EQUAL(mnemonic::EntropyToMnemonic(entropy), expected);
}

BOOST_AUTO_TEST_CASE(entropy_to_mnemonic_vector_5)
{
    auto entropy = ParseHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    std::string expected = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";
    BOOST_CHECK_EQUAL(mnemonic::EntropyToMnemonic(entropy), expected);
}

BOOST_AUTO_TEST_CASE(entropy_to_mnemonic_vector_6)
{
    auto entropy = ParseHex("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c");
    std::string expected = "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length";
    BOOST_CHECK_EQUAL(mnemonic::EntropyToMnemonic(entropy), expected);
}

BOOST_AUTO_TEST_CASE(entropy_to_mnemonic_vector_7)
{
    auto entropy = ParseHex("9e885d952ad362caeb4efe34a8e91bd2");
    std::string expected = "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic";
    BOOST_CHECK_EQUAL(mnemonic::EntropyToMnemonic(entropy), expected);
}

BOOST_AUTO_TEST_CASE(mnemonic_to_entropy_roundtrip_128)
{
    auto entropy = ParseHex("9e885d952ad362caeb4efe34a8e91bd2");
    std::string mnemonic = "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic";
    auto result = mnemonic::MnemonicToEntropy(mnemonic);
    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK_EQUAL(HexStr(result.value()), HexStr(entropy));
}

BOOST_AUTO_TEST_CASE(mnemonic_to_entropy_roundtrip_256)
{
    auto entropy = ParseHex("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c");
    std::string mnemonic = "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length";
    auto result = mnemonic::MnemonicToEntropy(mnemonic);
    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK_EQUAL(HexStr(result.value()), HexStr(entropy));
}

BOOST_AUTO_TEST_CASE(mnemonic_to_entropy_invalid_checksum)
{
    std::string bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    auto result = mnemonic::MnemonicToEntropy(bad);
    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(mnemonic_to_entropy_unknown_word)
{
    std::string bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon xyznotaword";
    auto result = mnemonic::MnemonicToEntropy(bad);
    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(mnemonic_to_entropy_wrong_word_count)
{
    std::string bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    auto result = mnemonic::MnemonicToEntropy(bad);
    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(validate_correct_mnemonic)
{
    BOOST_CHECK(mnemonic::Validate(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"));
    BOOST_CHECK(mnemonic::Validate(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"));
}

BOOST_AUTO_TEST_CASE(validate_wrong_word_count)
{
    BOOST_CHECK(!mnemonic::Validate(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"));
    BOOST_CHECK(!mnemonic::Validate(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about about"));
}

BOOST_AUTO_TEST_CASE(validate_unknown_word)
{
    BOOST_CHECK(!mnemonic::Validate(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon xyznotreal"));
}

BOOST_AUTO_TEST_CASE(validate_bad_checksum)
{
    BOOST_CHECK(!mnemonic::Validate(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon above"));
}

BOOST_AUTO_TEST_CASE(validate_empty_string)
{
    BOOST_CHECK(!mnemonic::Validate(""));
}

BOOST_AUTO_TEST_CASE(generate_produces_24_words)
{
    std::string m = mnemonic::Generate();
    std::istringstream iss(m);
    std::string word;
    int count = 0;
    while (iss >> word) count++;
    BOOST_CHECK_EQUAL(count, 24);
}

BOOST_AUTO_TEST_CASE(generate_all_words_in_list)
{
    std::string m = mnemonic::Generate();
    std::istringstream iss(m);
    std::string word;
    while (iss >> word) {
        auto it = std::lower_bound(mnemonic::wordlist_en.begin(), mnemonic::wordlist_en.end(), word,
            [](const char* a, const std::string& b) { return std::string(a) < b; });
        BOOST_CHECK_MESSAGE(it != mnemonic::wordlist_en.end() && std::string(*it) == word,
            "Word not in list: " + word);
    }
}

BOOST_AUTO_TEST_CASE(generate_validates)
{
    std::string m = mnemonic::Generate();
    BOOST_CHECK(mnemonic::Validate(m));
}

BOOST_AUTO_TEST_CASE(generate_is_non_deterministic)
{
    std::string m1 = mnemonic::Generate();
    std::string m2 = mnemonic::Generate();
    BOOST_CHECK(m1 != m2);
}

BOOST_AUTO_TEST_CASE(mnemonic_to_blsct_key_determinism)
{
    auto entropy = ParseHex("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c");
    std::string m = mnemonic::EntropyToMnemonic(entropy);

    auto key1 = BLS12_381_KeyGen::derive_master_SK(entropy);

    auto recovered_entropy = mnemonic::MnemonicToEntropy(m);
    BOOST_REQUIRE(recovered_entropy.has_value());
    auto key2 = BLS12_381_KeyGen::derive_master_SK(recovered_entropy.value());

    BOOST_CHECK(key1 == key2);
}

BOOST_AUTO_TEST_CASE(different_mnemonics_different_keys)
{
    auto entropy1 = ParseHex("0000000000000000000000000000000000000000000000000000000000000000");
    auto entropy2 = ParseHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    auto key1 = BLS12_381_KeyGen::derive_master_SK(entropy1);
    auto key2 = BLS12_381_KeyGen::derive_master_SK(entropy2);
    BOOST_CHECK(!(key1 == key2));
}

BOOST_AUTO_TEST_SUITE_END()
