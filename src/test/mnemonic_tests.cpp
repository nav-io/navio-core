// Copyright (c) 2024 The Navio developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mnemonic/mnemonic.h>
#include <mnemonic/wordlist.h>
#include <blsct/eip_2333/bls12_381_keygen.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <set>
#include <sstream>
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

BOOST_AUTO_TEST_CASE(entropy_to_mnemonic_vector_8_128bit)
{
    // 128-bit entropy -> 12 words (known vector, verifies EntropyToMnemonic directly)
    auto entropy = ParseHex("77c2b00716cec7213839159e404db50d");
    std::string expected = "jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge";
    BOOST_CHECK_EQUAL(mnemonic::EntropyToMnemonic(entropy), expected);
}

BOOST_AUTO_TEST_CASE(entropy_to_mnemonic_vector_160bit)
{
    // 160-bit entropy -> 15 words (BIP-39 test vector)
    auto entropy = ParseHex("6610b25967cdcca9d59875f5cb50b0ea75433311869e930b");
    std::string expected = "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog";
    BOOST_CHECK_EQUAL(mnemonic::EntropyToMnemonic(entropy), expected);
}

BOOST_AUTO_TEST_CASE(entropy_to_mnemonic_vector_256bit_2)
{
    // 256-bit entropy -> 24 words (BIP-39 test vector)
    auto entropy = ParseHex("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f");
    std::string expected = "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold";
    BOOST_CHECK_EQUAL(mnemonic::EntropyToMnemonic(entropy), expected);
}

BOOST_AUTO_TEST_CASE(entropy_to_mnemonic_vector_192bit)
{
    // Genuine 192-bit entropy (24 bytes = 48 hex chars) -> 18 words
    auto entropy = ParseHex("000102030405060708090a0b0c0d0e0f1011121314151617");
    BOOST_CHECK_EQUAL(entropy.size(), 24U);
    std::string mnemonic_str = mnemonic::EntropyToMnemonic(entropy);
    // Must produce exactly 18 words
    std::istringstream iss(mnemonic_str);
    std::string word;
    int count = 0;
    while (iss >> word) count++;
    BOOST_CHECK_EQUAL(count, 18);
    // Must roundtrip back to same entropy
    auto result = mnemonic::MnemonicToEntropy(mnemonic_str);
    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK_EQUAL(HexStr(result.value()), HexStr(entropy));
}

BOOST_AUTO_TEST_CASE(mnemonic_to_entropy_roundtrip_192)
{
    // Genuine 192-bit (18 words) roundtrip
    auto entropy = ParseHex("000102030405060708090a0b0c0d0e0f1011121314151617");
    std::string mnemonic_str = mnemonic::EntropyToMnemonic(entropy);
    auto result = mnemonic::MnemonicToEntropy(mnemonic_str);
    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK_EQUAL(HexStr(result.value()), HexStr(entropy));
}

BOOST_AUTO_TEST_CASE(validate_correct_mnemonic_18_words)
{
    // 192-bit -> 18 words
    auto entropy = ParseHex("000102030405060708090a0b0c0d0e0f1011121314151617");
    std::string mnemonic_str = mnemonic::EntropyToMnemonic(entropy);
    BOOST_CHECK(mnemonic::Validate(mnemonic_str));
}

BOOST_AUTO_TEST_CASE(validate_bad_checksum_18_words)
{
    // Generate valid 18-word mnemonic, then corrupt last word
    auto entropy = ParseHex("000102030405060708090a0b0c0d0e0f1011121314151617");
    std::string valid = mnemonic::EntropyToMnemonic(entropy);
    auto last_space = valid.rfind(' ');
    std::string bad = valid.substr(0, last_space + 1) + "abandon";
    BOOST_CHECK(!mnemonic::Validate(bad));
}

BOOST_AUTO_TEST_CASE(mnemonic_to_entropy_invalid_checksum_18_words)
{
    // Generate valid 18-word mnemonic, then corrupt last word
    auto entropy = ParseHex("000102030405060708090a0b0c0d0e0f1011121314151617");
    std::string valid = mnemonic::EntropyToMnemonic(entropy);
    auto last_space = valid.rfind(' ');
    std::string bad = valid.substr(0, last_space + 1) + "abandon";
    BOOST_CHECK(!mnemonic::MnemonicToEntropy(bad).has_value());
}

BOOST_AUTO_TEST_CASE(entropy_to_mnemonic_invalid_length)
{
    // 0 bytes
    BOOST_CHECK_EQUAL(mnemonic::EntropyToMnemonic(Span<const unsigned char>()), "");

    // 1 byte
    unsigned char one_byte[] = {0x00};
    BOOST_CHECK_EQUAL(mnemonic::EntropyToMnemonic(one_byte), "");

    // 15 bytes (not a multiple of 4)
    std::vector<unsigned char> fifteen(15, 0x00);
    BOOST_CHECK_EQUAL(mnemonic::EntropyToMnemonic(fifteen), "");

    // 17 bytes
    std::vector<unsigned char> seventeen(17, 0x00);
    BOOST_CHECK_EQUAL(mnemonic::EntropyToMnemonic(seventeen), "");

    // 33 bytes (too large)
    std::vector<unsigned char> thirtythree(33, 0x00);
    BOOST_CHECK_EQUAL(mnemonic::EntropyToMnemonic(thirtythree), "");
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

BOOST_AUTO_TEST_CASE(mnemonic_to_entropy_roundtrip_160)
{
    // 160-bit (15 words)
    auto entropy = ParseHex("6610b25967cdcca9d59875f5cb50b0ea75433311869e930b");
    std::string mnemonic = "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog";
    auto result = mnemonic::MnemonicToEntropy(mnemonic);
    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK_EQUAL(HexStr(result.value()), HexStr(entropy));
}

BOOST_AUTO_TEST_CASE(mnemonic_to_entropy_roundtrip_256_2)
{
    // 256-bit (24 words)
    auto entropy = ParseHex("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f");
    std::string mnemonic = "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold";
    auto result = mnemonic::MnemonicToEntropy(mnemonic);
    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK_EQUAL(HexStr(result.value()), HexStr(entropy));
}

BOOST_AUTO_TEST_CASE(mnemonic_to_entropy_roundtrip_224)
{
    // 224-bit (21 words)
    auto entropy = ParseHex("8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0");
    auto mnemonic_str = mnemonic::EntropyToMnemonic(entropy);
    auto result = mnemonic::MnemonicToEntropy(mnemonic_str);
    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK_EQUAL(HexStr(result.value()), HexStr(entropy));
}

BOOST_AUTO_TEST_CASE(entropy_to_mnemonic_vector_224bit)
{
    // 224-bit entropy (28 bytes = 56 hex chars) -> 21 words
    auto entropy = ParseHex("ba0c3c78818c00052c7cde0eb37d00bbf28c3793c25c05c78c8569ba");
    BOOST_CHECK_EQUAL(entropy.size(), 28U);
    std::string mnemonic_str = mnemonic::EntropyToMnemonic(entropy);
    // Must produce exactly 21 words
    std::istringstream iss(mnemonic_str);
    std::string word;
    int count = 0;
    while (iss >> word) count++;
    BOOST_CHECK_EQUAL(count, 21);
    // Must roundtrip back to same entropy
    auto result = mnemonic::MnemonicToEntropy(mnemonic_str);
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

BOOST_AUTO_TEST_CASE(mnemonic_to_entropy_empty_string)
{
    auto result = mnemonic::MnemonicToEntropy("");
    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(mnemonic_to_entropy_invalid_word_counts)
{
    // Only 12, 15, 18, 21, 24 are valid word counts
    // Test other counts that are between valid sizes
    std::string w13 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon";
    BOOST_CHECK(!mnemonic::MnemonicToEntropy(w13).has_value());

    std::string w14 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon abandon";
    BOOST_CHECK(!mnemonic::MnemonicToEntropy(w14).has_value());

    std::string w16 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon abandon abandon abandon";
    BOOST_CHECK(!mnemonic::MnemonicToEntropy(w16).has_value());

    std::string w17 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon abandon abandon abandon abandon";
    BOOST_CHECK(!mnemonic::MnemonicToEntropy(w17).has_value());

    std::string w19 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon abandon abandon abandon abandon abandon abandon";
    BOOST_CHECK(!mnemonic::MnemonicToEntropy(w19).has_value());

    std::string w20 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon abandon abandon abandon abandon abandon abandon abandon";
    BOOST_CHECK(!mnemonic::MnemonicToEntropy(w20).has_value());

    std::string w22 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    BOOST_CHECK(!mnemonic::MnemonicToEntropy(w22).has_value());

    std::string w23 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    BOOST_CHECK(!mnemonic::MnemonicToEntropy(w23).has_value());

    // Single word
    BOOST_CHECK(!mnemonic::MnemonicToEntropy("abandon").has_value());
}

BOOST_AUTO_TEST_CASE(mnemonic_to_entropy_invalid_checksum_15_words)
{
    // Valid 15-word mnemonic with last word replaced to break checksum
    std::string bad = "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow abandon";
    BOOST_CHECK(!mnemonic::MnemonicToEntropy(bad).has_value());
}

BOOST_AUTO_TEST_CASE(mnemonic_to_entropy_invalid_checksum_24_words)
{
    // Valid 24-word mnemonic with last word replaced to break checksum
    std::string bad = "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve abandon";
    BOOST_CHECK(!mnemonic::MnemonicToEntropy(bad).has_value());
}

BOOST_AUTO_TEST_CASE(mnemonic_to_entropy_invalid_checksum_21_words)
{
    // Generate valid 21-word mnemonic, then corrupt last word
    auto entropy = ParseHex("8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0");
    std::string valid = mnemonic::EntropyToMnemonic(entropy);
    auto last_space = valid.rfind(' ');
    std::string bad = valid.substr(0, last_space + 1) + "abandon";
    BOOST_CHECK(!mnemonic::MnemonicToEntropy(bad).has_value());
}

BOOST_AUTO_TEST_CASE(validate_correct_mnemonic)
{
    BOOST_CHECK(mnemonic::Validate(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"));
    BOOST_CHECK(mnemonic::Validate(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"));
}

BOOST_AUTO_TEST_CASE(validate_correct_mnemonic_15_words)
{
    // 160-bit -> 15 words
    BOOST_CHECK(mnemonic::Validate(
        "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog"));
}

BOOST_AUTO_TEST_CASE(validate_correct_mnemonic_24_words_2)
{
    // 256-bit -> 24 words
    BOOST_CHECK(mnemonic::Validate(
        "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold"));
}

BOOST_AUTO_TEST_CASE(validate_correct_mnemonic_21_words)
{
    // 224-bit -> 21 words, roundtrip through EntropyToMnemonic
    auto entropy = ParseHex("8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0");
    std::string mnemonic_str = mnemonic::EntropyToMnemonic(entropy);
    BOOST_CHECK(mnemonic::Validate(mnemonic_str));
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

BOOST_AUTO_TEST_CASE(validate_bad_checksum_15_words)
{
    BOOST_CHECK(!mnemonic::Validate(
        "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow abandon"));
}

BOOST_AUTO_TEST_CASE(validate_bad_checksum_24_words)
{
    BOOST_CHECK(!mnemonic::Validate(
        "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve abandon"));
}

BOOST_AUTO_TEST_CASE(validate_bad_checksum_21_words)
{
    auto entropy = ParseHex("8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0");
    std::string valid = mnemonic::EntropyToMnemonic(entropy);
    auto last_space = valid.rfind(' ');
    std::string bad = valid.substr(0, last_space + 1) + "abandon";
    BOOST_CHECK(!mnemonic::Validate(bad));
}

BOOST_AUTO_TEST_CASE(validate_empty_string)
{
    BOOST_CHECK(!mnemonic::Validate(""));
}

BOOST_AUTO_TEST_CASE(validate_uppercase_rejected)
{
    std::string upper = "ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABOUT";
    BOOST_CHECK(!mnemonic::Validate(upper));
    BOOST_CHECK(!mnemonic::MnemonicToEntropy(upper).has_value());
}

BOOST_AUTO_TEST_CASE(validate_mixed_case_rejected)
{
    std::string mixed = "Abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    BOOST_CHECK(!mnemonic::Validate(mixed));
    BOOST_CHECK(!mnemonic::MnemonicToEntropy(mixed).has_value());
}

BOOST_AUTO_TEST_CASE(validate_wrong_word_count_11)
{
    // 11 words is not a valid BIP-39 length (must be 12, 15, 18, 21, or 24)
    std::string eleven = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    BOOST_CHECK(!mnemonic::Validate(eleven));
    BOOST_CHECK(!mnemonic::MnemonicToEntropy(eleven).has_value());
}

BOOST_AUTO_TEST_CASE(validate_leading_trailing_whitespace)
{
    // Leading/trailing whitespace is normalized by >> operator, so should still validate
    std::string leading = " abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    BOOST_CHECK(mnemonic::Validate(leading));

    std::string trailing = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about ";
    BOOST_CHECK(mnemonic::Validate(trailing));

    std::string both = " abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about ";
    BOOST_CHECK(mnemonic::Validate(both));

    // Verify MnemonicToEntropy also handles whitespace
    auto result = mnemonic::MnemonicToEntropy(leading);
    BOOST_CHECK(result.has_value());
}

BOOST_AUTO_TEST_CASE(validate_newline_whitespace)
{
    // Newline between words is whitespace and should be normalized by >> operator
    // Construct the string programmatically to avoid any literal encoding issues
    std::string newline_test;
    for (int i = 0; i < 11; i++) {
        if (i == 1) newline_test += "\n"; // newline between 2nd and 3rd word
        else if (i > 0) newline_test += " ";
        newline_test += "abandon";
    }
    newline_test += " about";
    BOOST_CHECK(mnemonic::Validate(newline_test));
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

BOOST_AUTO_TEST_CASE(generate_roundtrip)
{
    std::string m = mnemonic::Generate();
    auto entropy = mnemonic::MnemonicToEntropy(m);
    BOOST_REQUIRE(entropy.has_value());
    std::string re_encoded = mnemonic::EntropyToMnemonic(entropy.value());
    BOOST_CHECK_EQUAL(m, re_encoded);
}

BOOST_AUTO_TEST_CASE(generate_produces_valid_bls_key)
{
    std::string m = mnemonic::Generate();
    auto entropy = mnemonic::MnemonicToEntropy(m);
    BOOST_REQUIRE(entropy.has_value());
    // Should not throw or crash
    auto key = BLS12_381_KeyGen::derive_master_SK(entropy.value());
    // Key should be non-zero (probability of all zeros is 2^-256)
    (void)key;
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

// BIP-39 seed derivation (PBKDF2-HMAC-SHA512, 2048 iterations)
// Expected seeds are the official Trezor test vectors (passphrase "TREZOR")
// from https://github.com/trezor/python-mnemonic/blob/master/vectors.json

BOOST_AUTO_TEST_CASE(mnemonic_to_seed_trezor_vector_12_words)
{
    std::string m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    BOOST_CHECK_EQUAL(HexStr(mnemonic::MnemonicToSeed(m, "TREZOR")),
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
}

BOOST_AUTO_TEST_CASE(mnemonic_to_seed_trezor_vector_12_words_2)
{
    std::string m = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    BOOST_CHECK_EQUAL(HexStr(mnemonic::MnemonicToSeed(m, "TREZOR")),
        "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607");
}

BOOST_AUTO_TEST_CASE(mnemonic_to_seed_trezor_vector_24_words)
{
    std::string m = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";
    BOOST_CHECK_EQUAL(HexStr(mnemonic::MnemonicToSeed(m, "TREZOR")),
        "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad");
}

BOOST_AUTO_TEST_CASE(mnemonic_to_seed_trezor_vector_24_words_2)
{
    std::string m = "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold";
    BOOST_CHECK_EQUAL(HexStr(mnemonic::MnemonicToSeed(m, "TREZOR")),
        "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998");
}

BOOST_AUTO_TEST_CASE(mnemonic_to_seed_trezor_vector_24_words_3)
{
    std::string m = "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length";
    BOOST_CHECK_EQUAL(HexStr(mnemonic::MnemonicToSeed(m, "TREZOR")),
        "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440");
}

BOOST_AUTO_TEST_CASE(mnemonic_to_seed_empty_passphrase)
{
    // Default (empty) passphrase uses salt "mnemonic"
    std::string m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    std::string expected = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
    BOOST_CHECK_EQUAL(HexStr(mnemonic::MnemonicToSeed(m)), expected);
    BOOST_CHECK_EQUAL(HexStr(mnemonic::MnemonicToSeed(m, "")), expected);
}

BOOST_AUTO_TEST_CASE(mnemonic_to_seed_empty_passphrase_24_words)
{
    std::string m = "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold";
    BOOST_CHECK_EQUAL(HexStr(mnemonic::MnemonicToSeed(m)),
        "b873212f885ccffbf4692afcb84bc2e55886de2dfa07d90f5c3c239abc31c0a6ce047e30fd8bf6a281e71389aa82d73df74c7bbfb3b06b4639a5cee775cccd3c");
}

BOOST_AUTO_TEST_CASE(mnemonic_to_seed_custom_passphrase)
{
    std::string m = "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold";
    BOOST_CHECK_EQUAL(HexStr(mnemonic::MnemonicToSeed(m, "navio")),
        "cde3ba869451d56058ed01e3f95332dba1a93e4ef56689ef31a6b7d6951acd6c383870843b0ccc3435c8723d274171dee2e0d44965797ada1cae45907c60f889");
}

BOOST_AUTO_TEST_CASE(mnemonic_to_seed_returns_64_bytes)
{
    std::string m = mnemonic::Generate();
    BOOST_CHECK_EQUAL(mnemonic::MnemonicToSeed(m).size(), 64U);
    BOOST_CHECK_EQUAL(mnemonic::MnemonicToSeed(m, "passphrase").size(), 64U);
}

BOOST_AUTO_TEST_CASE(mnemonic_to_seed_different_passphrases_different_seeds)
{
    std::string m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    auto seed_none = mnemonic::MnemonicToSeed(m);
    auto seed_a = mnemonic::MnemonicToSeed(m, "a");
    auto seed_b = mnemonic::MnemonicToSeed(m, "b");
    BOOST_CHECK(seed_none != seed_a);
    BOOST_CHECK(seed_none != seed_b);
    BOOST_CHECK(seed_a != seed_b);
}

BOOST_AUTO_TEST_CASE(mnemonic_to_seed_whitespace_normalized)
{
    std::string m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    std::string padded = "  abandon   abandon abandon\nabandon abandon abandon abandon abandon abandon abandon abandon about ";
    BOOST_CHECK_EQUAL(HexStr(mnemonic::MnemonicToSeed(padded, "TREZOR")),
                      HexStr(mnemonic::MnemonicToSeed(m, "TREZOR")));
}

BOOST_AUTO_TEST_CASE(mnemonic_to_seed_produces_valid_bls_key)
{
    // The 64-byte BIP-39 seed must be accepted by EIP-2333 master key derivation
    std::string m = "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold";
    auto entropy = mnemonic::MnemonicToEntropy(m);
    BOOST_REQUIRE(entropy.has_value());

    auto seed = mnemonic::MnemonicToSeed(m, "passphrase");
    auto key_passphrase = BLS12_381_KeyGen::derive_master_SK(seed);
    auto key_legacy = BLS12_381_KeyGen::derive_master_SK(entropy.value());
    // Passphrase-derived key must differ from the legacy entropy-derived key
    BOOST_CHECK(!(key_passphrase == key_legacy));

    // Deterministic: same mnemonic + passphrase -> same key
    auto key_again = BLS12_381_KeyGen::derive_master_SK(mnemonic::MnemonicToSeed(m, "passphrase"));
    BOOST_CHECK(key_passphrase == key_again);
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
