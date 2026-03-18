// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/strencodings.h>
#include <util/string.h>
#include <vector>

#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>

using namespace util;

BOOST_AUTO_TEST_SUITE(util_string_tests)

std::vector<std::byte> StringToBuffer(const std::string& str)
{
    auto span = std::as_bytes(std::span(str));
    return {span.begin(), span.end()};
}

BOOST_AUTO_TEST_CASE(ascii_case_insensitive_key_equal_test)
{
    AsciiCaseInsensitiveKeyEqual cmp;
    BOOST_CHECK(!cmp("A", "B"));
    BOOST_CHECK(!cmp("A", "b"));
    BOOST_CHECK(!cmp("a", "B"));
    BOOST_CHECK(!cmp("B", "A"));
    BOOST_CHECK(!cmp("B", "a"));
    BOOST_CHECK(!cmp("b", "A"));
    BOOST_CHECK(!cmp("A", "AA"));
    BOOST_CHECK(cmp("A-A", "a-a"));
    BOOST_CHECK(cmp("A", "A"));
    BOOST_CHECK(cmp("A", "a"));
    BOOST_CHECK(cmp("a", "a"));
    BOOST_CHECK(cmp("B", "b"));
    BOOST_CHECK(cmp("ab", "aB"));
    BOOST_CHECK(cmp("Ab", "aB"));
    BOOST_CHECK(cmp("AB", "ab"));

    // Use a character with value > 127
    // to ensure we don't trigger implicit-integer-sign-change
    BOOST_CHECK(!cmp("a", "\xe4"));
}

BOOST_AUTO_TEST_CASE(ascii_case_insensitive_hash_test)
{
    AsciiCaseInsensitiveHash hsh;
    BOOST_CHECK_NE(hsh("A"), hsh("B"));
    BOOST_CHECK_NE(hsh("AA"), hsh("A"));
    BOOST_CHECK_EQUAL(hsh("A"), hsh("a"));
    BOOST_CHECK_EQUAL(hsh("Ab"), hsh("aB"));
    BOOST_CHECK_EQUAL(hsh("A\xfe"), hsh("a\xfe"));
}

BOOST_AUTO_TEST_CASE(line_reader_test)
{
    {
        // Check three lines terminated by \n and \r\n, trimming whitespace
        const std::vector<std::byte> input{StringToBuffer("once upon a time\n there was a dog \r\nwho liked food\n")};
        LineReader reader(input, /*max_line_length=*/128);
        BOOST_CHECK_EQUAL(reader.Consumed(), 0);
        BOOST_CHECK_EQUAL(reader.Remaining(), 51);
        std::optional<std::string> line1{reader.ReadLine()};
        BOOST_CHECK_EQUAL(reader.Consumed(), 17);
        BOOST_CHECK_EQUAL(reader.Remaining(), 34);
        std::optional<std::string> line2{reader.ReadLine()};
        BOOST_CHECK_EQUAL(reader.Consumed(), 36);
        BOOST_CHECK_EQUAL(reader.Remaining(), 15);
        std::optional<std::string> line3{reader.ReadLine()};
        std::optional<std::string> line4{reader.ReadLine()};
        BOOST_CHECK(line1);
        BOOST_CHECK(line2);
        BOOST_CHECK(line3);
        BOOST_CHECK(!line4);
        BOOST_CHECK_EQUAL(line1.value(), "once upon a time");
        BOOST_CHECK_EQUAL(line2.value(), "there was a dog");
        BOOST_CHECK_EQUAL(line3.value(), "who liked food");
        BOOST_CHECK_EQUAL(reader.Consumed(), 51);
        BOOST_CHECK_EQUAL(reader.Remaining(), 0);
    }
    {
        // Do not exceed max_line_length + 1 while searching for \n
        // Test with 22-character line + \n + 23-character line + \n
        const std::vector<std::byte> input{StringToBuffer("once upon a time there\nwas a dog who liked tea\n")};

        LineReader reader1(input, /*max_line_length=*/22);
        // First line is exactly the length of max_line_length
        BOOST_CHECK_EQUAL(reader1.ReadLine(), "once upon a time there");
        // Second line is +1 character too long
        BOOST_CHECK_EXCEPTION(reader1.ReadLine(), std::runtime_error, HasReason{"max_line_length exceeded by LineReader"});

        // Increase max_line_length by 1
        LineReader reader2(input, /*max_line_length=*/23);
        // Both lines fit within limit
        BOOST_CHECK_EQUAL(reader2.ReadLine(), "once upon a time there");
        BOOST_CHECK_EQUAL(reader2.ReadLine(), "was a dog who liked tea");
        // End of buffer reached
        BOOST_CHECK(!reader2.ReadLine());
    }
    {
        // Empty lines are empty
        const std::vector<std::byte> input{StringToBuffer("\n")};
        LineReader reader(input, /*max_line_length=*/1024);
        BOOST_CHECK_EQUAL(reader.ReadLine(), "");
        BOOST_CHECK(!reader.ReadLine());
    }
    {
        // Empty buffers are null
        const std::vector<std::byte> input{StringToBuffer("")};
        LineReader reader(input, /*max_line_length=*/1024);
        BOOST_CHECK(!reader.ReadLine());
    }
    {
        // Even one character is too long, if it's not \n
        const std::vector<std::byte> input{StringToBuffer("ab\n")};
        LineReader reader(input, /*max_line_length=*/1);
        // First line is +1 character too long
        BOOST_CHECK_EXCEPTION(reader.ReadLine(), std::runtime_error, HasReason{"max_line_length exceeded by LineReader"});
    }
    {
        const std::vector<std::byte> input{StringToBuffer("a\nb\n")};
        LineReader reader(input, /*max_line_length=*/1);
        BOOST_CHECK_EQUAL(reader.ReadLine(), "a");
        BOOST_CHECK_EQUAL(reader.ReadLine(), "b");
        BOOST_CHECK(!reader.ReadLine());
    }
    {
        // If ReadLine fails, the iterator is reset and we can ReadLength instead
        const std::vector<std::byte> input{StringToBuffer("a\nbaboon\n")};
        LineReader reader(input, /*max_line_length=*/1);
        BOOST_CHECK_EQUAL(reader.ReadLine(), "a");
        // "baboon" is too long
        BOOST_CHECK_EXCEPTION(reader.ReadLine(), std::runtime_error, HasReason{"max_line_length exceeded by LineReader"});
        BOOST_CHECK_EQUAL(reader.ReadLength(1), "b");
        BOOST_CHECK_EQUAL(reader.ReadLength(1), "a");
        BOOST_CHECK_EQUAL(reader.ReadLength(2), "bo");
        // "on" is too long
        BOOST_CHECK_EXCEPTION(reader.ReadLine(), std::runtime_error, HasReason{"max_line_length exceeded by LineReader"});
        BOOST_CHECK_EQUAL(reader.ReadLength(1), "o");
        BOOST_CHECK_EQUAL(reader.ReadLine(), "n"); // now the remainder of the buffer fits in one line
        BOOST_CHECK(!reader.ReadLine());
    }
    {
        // The end of the buffer (EOB) does not count as end of line \n
        const std::vector<std::byte> input{StringToBuffer("once upon a time there")};

        LineReader reader(input, /*max_line_length=*/22);
        // First line is exactly the length of max_line_length, but that doesn't matter because \n is missing
        BOOST_CHECK(!reader.ReadLine());
        // Data can still be read using ReadLength
        BOOST_CHECK_EQUAL(reader.ReadLength(22), "once upon a time there");
        // End of buffer reached
        BOOST_CHECK_EQUAL(reader.Remaining(), 0);
    }
    {
        // Read specific number of bytes regardless of max_line_length or \n unless buffer is too short
        const std::vector<std::byte> input{StringToBuffer("once upon a time\n there was a dog \r\nwho liked food")};
        LineReader reader(input, /*max_line_length=*/1);
        BOOST_CHECK_EQUAL(reader.ReadLength(0), "");
        BOOST_CHECK_EQUAL(reader.ReadLength(3), "onc");
        BOOST_CHECK_EQUAL(reader.ReadLength(8), "e upon a");
        BOOST_CHECK_EQUAL(reader.ReadLength(8), " time\n t");
        BOOST_CHECK_EXCEPTION(reader.ReadLength(128), std::runtime_error, HasReason{"Not enough data in buffer"});
        // After the error the iterator is reset so we can try again
        BOOST_CHECK_EQUAL(reader.ReadLength(31), "here was a dog \r\nwho liked food");
        // End of buffer reached
        BOOST_CHECK_EQUAL(reader.Remaining(), 0);
    }
}

BOOST_AUTO_TEST_SUITE_END()
