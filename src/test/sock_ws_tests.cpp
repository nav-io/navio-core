// Copyright (c) 2024-present The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <compat/compat.h>
#include <test/util/setup_common.h>
#include <util/sock_ws.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace {

/**
 * A `WebSocketSock` whose raw transport is an in-memory buffer: whatever the
 * test puts in `m_input` is what the "client" sent, and everything the wrapper
 * writes ends up in `m_output`.
 */
class MockWsSock : public WebSocketSock
{
public:
    explicit MockWsSock(std::string input = "") : WebSocketSock{INVALID_SOCKET}, m_input{std::move(input)} {}

    ~MockWsSock() override { m_socket = INVALID_SOCKET; }

    /** Bytes the client "sent"; consumed by `RawRecv()`. */
    mutable std::string m_input;
    mutable size_t m_consumed{0};
    /** Return 0 (EOF) instead of EAGAIN once `m_input` is exhausted. */
    bool m_eof{false};
    /** Largest chunk a single `RawRecv()` returns. */
    size_t m_max_recv{std::numeric_limits<size_t>::max()};

    /** Everything the wrapper wrote to the wire. */
    mutable std::string m_output;
    /** Remaining bytes `RawSend()` accepts before reporting EAGAIN. */
    mutable size_t m_send_budget{std::numeric_limits<size_t>::max()};

    void Feed(const std::string& more) const { m_input += more; }

    /** Whether unread client bytes remain (a real socket would poll readable again). */
    bool HasInput() const { return m_consumed < m_input.size(); }

protected:
    ssize_t RawSend(const void* data, size_t len, int) const override
    {
        const size_t n{std::min(len, m_send_budget)};
        if (n == 0) {
            errno = EAGAIN;
            return -1;
        }
        m_output.append(static_cast<const char*>(data), n);
        if (m_send_budget != std::numeric_limits<size_t>::max()) m_send_budget -= n;
        return static_cast<ssize_t>(n);
    }

    ssize_t RawRecv(void* buf, size_t len, int) const override
    {
        const size_t available{m_input.size() - m_consumed};
        if (available == 0) {
            if (m_eof) return 0;
            errno = EAGAIN;
            return -1;
        }
        const size_t n{std::min({len, available, m_max_recv})};
        std::memcpy(buf, m_input.data() + m_consumed, n);
        m_consumed += n;
        return static_cast<ssize_t>(n);
    }
};

const std::string RFC_KEY{"dGhlIHNhbXBsZSBub25jZQ=="};
const std::string RFC_ACCEPT{"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="};

std::string Handshake(const std::string& extra_headers = "")
{
    return "GET /p2p HTTP/1.1\r\n"
           "Host: node.example\r\n"
           "Upgrade: websocket\r\n"
           "Connection: keep-alive, Upgrade\r\n"
           "Sec-WebSocket-Key: " + RFC_KEY + "\r\n"
           "Sec-WebSocket-Version: 13\r\n" + extra_headers + "\r\n";
}

/** Build a client->server frame. */
std::string Frame(uint8_t opcode, const std::string& payload, bool fin = true, bool masked = true, uint8_t rsv = 0)
{
    std::string f;
    f.push_back(static_cast<char>((fin ? 0x80 : 0) | (rsv << 4) | opcode));
    const uint8_t mask_bit{masked ? uint8_t{0x80} : uint8_t{0}};
    const size_t len{payload.size()};
    if (len < 126) {
        f.push_back(static_cast<char>(mask_bit | len));
    } else if (len <= 0xFFFF) {
        f.push_back(static_cast<char>(mask_bit | 126));
        f.push_back(static_cast<char>(len >> 8));
        f.push_back(static_cast<char>(len));
    } else {
        f.push_back(static_cast<char>(mask_bit | 127));
        for (int shift = 56; shift >= 0; shift -= 8) {
            f.push_back(static_cast<char>(static_cast<uint64_t>(len) >> shift));
        }
    }
    const uint8_t mask[4]{0x12, 0x34, 0x56, 0x78};
    if (masked) {
        f.append(reinterpret_cast<const char*>(mask), 4);
        for (size_t i = 0; i < len; ++i) {
            f.push_back(static_cast<char>(static_cast<uint8_t>(payload[i]) ^ mask[i & 3]));
        }
    } else {
        f += payload;
    }
    return f;
}

std::string BinaryFrame(const std::string& payload) { return Frame(0x2, payload); }

/** Server->client frame (unmasked) as the wrapper is expected to emit it. */
std::string ServerFrame(uint8_t opcode, const std::string& payload)
{
    return Frame(opcode, payload, /*fin=*/true, /*masked=*/false);
}

/**
 * Call `Recv()` with a `len`-byte buffer until it reports EAGAIN, EOF or an
 * error. Returns the collected application bytes and the final return value.
 */
std::pair<std::string, ssize_t> RecvAll(const MockWsSock& sock, size_t len = 65536)
{
    std::string out;
    std::vector<char> buf(len);
    while (true) {
        const ssize_t r{sock.Recv(buf.data(), buf.size(), MSG_DONTWAIT)};
        if (r > 0) {
            out.append(buf.data(), static_cast<size_t>(r));
            continue;
        }
        // EAGAIN with more bytes still on the "wire" just means the wrapper
        // consumed a partial handshake/header; poll again like CConnman would.
        if (r == -1 && errno == EAGAIN && (sock.HasInput() || sock.m_eof)) continue;
        return {out, r};
    }
}

bool StartsWith(const std::string& s, const std::string& prefix)
{
    return s.compare(0, prefix.size(), prefix) == 0;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(sock_ws_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(compute_accept)
{
    // Example from RFC 6455 section 1.3.
    BOOST_CHECK_EQUAL(WebSocketSock::ComputeAccept(RFC_KEY), RFC_ACCEPT);
}

BOOST_AUTO_TEST_CASE(handshake_ok)
{
    MockWsSock sock{Handshake("Sec-WebSocket-Extensions: permessage-deflate\r\nSec-WebSocket-Protocol: navio-p2p\r\n")};
    BOOST_CHECK(!sock.HandshakeComplete());
    const auto [data, r] = RecvAll(sock);
    BOOST_CHECK_EQUAL(r, -1);
    BOOST_CHECK_EQUAL(errno, EAGAIN);
    BOOST_CHECK(data.empty());
    BOOST_CHECK(sock.HandshakeComplete());
    BOOST_CHECK_EQUAL(sock.m_output,
                      "HTTP/1.1 101 Switching Protocols\r\n"
                      "Upgrade: websocket\r\n"
                      "Connection: Upgrade\r\n"
                      "Sec-WebSocket-Accept: " + RFC_ACCEPT + "\r\n\r\n");
    // No extension or subprotocol is ever negotiated.
    BOOST_CHECK(sock.m_output.find("Sec-WebSocket-Extensions") == std::string::npos);
    BOOST_CHECK(sock.m_output.find("Sec-WebSocket-Protocol") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(handshake_split_across_reads)
{
    MockWsSock sock{Handshake() + BinaryFrame("abc")};
    sock.m_max_recv = 7; // the terminator and frame header straddle reads
    const auto [data, r] = RecvAll(sock);
    BOOST_CHECK_EQUAL(data, "abc");
    BOOST_CHECK_EQUAL(r, -1);
    BOOST_CHECK_EQUAL(errno, EAGAIN);
    BOOST_CHECK(StartsWith(sock.m_output, "HTTP/1.1 101"));
}

BOOST_AUTO_TEST_CASE(handshake_bad)
{
    const std::vector<std::string> bad_requests{
        // Not an upgrade at all.
        "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        // Wrong method.
        "POST /p2p HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + RFC_KEY + "\r\nSec-WebSocket-Version: 13\r\n\r\n",
        // HTTP/1.0.
        "GET /p2p HTTP/1.0\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + RFC_KEY + "\r\nSec-WebSocket-Version: 13\r\n\r\n",
        // Missing Connection: Upgrade.
        "GET /p2p HTTP/1.1\r\nUpgrade: websocket\r\nSec-WebSocket-Key: " + RFC_KEY + "\r\nSec-WebSocket-Version: 13\r\n\r\n",
        // Wrong version.
        "GET /p2p HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + RFC_KEY + "\r\nSec-WebSocket-Version: 8\r\n\r\n",
        // Missing key.
        "GET /p2p HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n",
        // Malformed header line.
        "GET /p2p HTTP/1.1\r\nUpgrade websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + RFC_KEY + "\r\nSec-WebSocket-Version: 13\r\n\r\n",
    };
    for (const auto& request : bad_requests) {
        MockWsSock sock{request};
        const auto [data, r] = RecvAll(sock);
        BOOST_CHECK_EQUAL(r, -1);
        BOOST_CHECK_EQUAL(errno, EPROTO);
        BOOST_CHECK(data.empty());
        BOOST_CHECK(!sock.HandshakeComplete());
        BOOST_CHECK(StartsWith(sock.m_output, "HTTP/1.1 400 Bad Request\r\n"));
        // The error is sticky.
        char c;
        BOOST_CHECK_EQUAL(sock.Recv(&c, 1, 0), -1);
        BOOST_CHECK_EQUAL(errno, EPROTO);
    }
}

BOOST_AUTO_TEST_CASE(handshake_too_large)
{
    MockWsSock sock{"GET /p2p HTTP/1.1\r\nX-Padding: " + std::string(WebSocketSock::MAX_HANDSHAKE_BYTES, 'a') + "\r\n"};
    const auto [data, r] = RecvAll(sock);
    BOOST_CHECK_EQUAL(r, -1);
    BOOST_CHECK_EQUAL(errno, EPROTO);
    BOOST_CHECK(StartsWith(sock.m_output, "HTTP/1.1 400"));
}

BOOST_AUTO_TEST_CASE(handshake_eof)
{
    MockWsSock sock{"GET /p2p HTTP/1.1\r\n"};
    sock.m_eof = true;
    const auto [data, r] = RecvAll(sock);
    BOOST_CHECK_EQUAL(r, 0);
    BOOST_CHECK(data.empty());
}

BOOST_AUTO_TEST_CASE(binary_frames_are_a_byte_stream)
{
    MockWsSock sock{Handshake() + BinaryFrame("hello") + BinaryFrame(" ") + BinaryFrame("") + BinaryFrame("world")};
    const auto [data, r] = RecvAll(sock);
    BOOST_CHECK_EQUAL(data, "hello world");
    BOOST_CHECK_EQUAL(r, -1);
    BOOST_CHECK_EQUAL(errno, EAGAIN);

    // More data arriving later is decoded as well.
    sock.Feed(BinaryFrame("!"));
    const auto [data2, r2] = RecvAll(sock);
    BOOST_CHECK_EQUAL(data2, "!");
    BOOST_CHECK_EQUAL(r2, -1);
}

BOOST_AUTO_TEST_CASE(small_caller_buffer)
{
    // The caller never gets more bytes than it asked for and never loses any.
    MockWsSock sock{Handshake() + BinaryFrame("0123456789abcdef")};
    const auto [data, r] = RecvAll(sock, /*len=*/3);
    BOOST_CHECK_EQUAL(data, "0123456789abcdef");
    BOOST_CHECK_EQUAL(r, -1);
    BOOST_CHECK_EQUAL(errno, EAGAIN);
}

BOOST_AUTO_TEST_CASE(fragmented_message)
{
    MockWsSock sock{Handshake() +
                    Frame(0x2, "frag", /*fin=*/false) +
                    Frame(0x0, "ment", /*fin=*/false) +
                    Frame(0x0, "ed")};
    sock.m_max_recv = 5;
    const auto [data, r] = RecvAll(sock);
    BOOST_CHECK_EQUAL(data, "fragmented");
    BOOST_CHECK_EQUAL(r, -1);
}

BOOST_AUTO_TEST_CASE(extended_payload_lengths)
{
    const std::string medium(300, 'm');
    const std::string large(70000, 'L');
    MockWsSock sock{Handshake() + BinaryFrame(medium) + BinaryFrame(large)};
    const auto [data, r] = RecvAll(sock);
    BOOST_CHECK_EQUAL(data.size(), medium.size() + large.size());
    BOOST_CHECK(data == medium + large);
    BOOST_CHECK_EQUAL(r, -1);
}

BOOST_AUTO_TEST_CASE(ping_pong_and_close)
{
    MockWsSock sock{Handshake() + Frame(0x9, "ping!") + BinaryFrame("data") + Frame(0xA, "pong?")};
    const auto [data, r] = RecvAll(sock);
    BOOST_CHECK_EQUAL(data, "data");
    BOOST_CHECK_EQUAL(r, -1);
    const std::string expected_pong{ServerFrame(0xA, "ping!")};
    BOOST_CHECK(sock.m_output.find(expected_pong) != std::string::npos);
    // An unsolicited pong is ignored and answered with nothing.
    BOOST_CHECK(sock.m_output.find(ServerFrame(0xA, "pong?")) == std::string::npos);

    // Close with a status code: answered with a close echoing the code, then EOF.
    const std::string close_payload{"\x03\xe8" "bye"};
    sock.Feed(Frame(0x8, close_payload) + BinaryFrame("ignored"));
    const auto [data2, r2] = RecvAll(sock);
    BOOST_CHECK(data2.empty());
    BOOST_CHECK_EQUAL(r2, 0);
    BOOST_CHECK(sock.m_output.find(ServerFrame(0x8, "\x03\xe8")) != std::string::npos);
    // EOF is sticky.
    char c;
    BOOST_CHECK_EQUAL(sock.Recv(&c, 1, 0), 0);
}

BOOST_AUTO_TEST_CASE(close_without_status)
{
    MockWsSock sock{Handshake() + Frame(0x8, "")};
    const auto [data, r] = RecvAll(sock);
    BOOST_CHECK(data.empty());
    BOOST_CHECK_EQUAL(r, 0);
    BOOST_CHECK(sock.m_output.find(ServerFrame(0x8, "")) != std::string::npos);
}

BOOST_AUTO_TEST_CASE(protocol_errors)
{
    const std::vector<std::pair<std::string, std::string>> cases{
        {"unmasked frame", Frame(0x2, "abc", true, /*masked=*/false)},
        {"text frame", Frame(0x1, "abc")},
        {"rsv bits", Frame(0x2, "abc", true, true, /*rsv=*/0x4)},
        {"unknown opcode", Frame(0x3, "abc")},
        {"fragmented control frame", Frame(0x9, "abc", /*fin=*/false)},
        {"oversized control frame", Frame(0x9, std::string(126, 'p'))},
    };
    for (const auto& [name, frame] : cases) {
        MockWsSock sock{Handshake() + BinaryFrame("ok") + frame};
        const auto [data, r] = RecvAll(sock);
        BOOST_CHECK_MESSAGE(data == "ok", name);
        BOOST_CHECK_MESSAGE(r == -1, name);
        BOOST_CHECK_MESSAGE(errno == EPROTO, name);
        char c;
        BOOST_CHECK_MESSAGE(sock.Recv(&c, 1, 0) == -1, name);
        BOOST_CHECK_MESSAGE(errno == EPROTO, name);
    }
}

BOOST_AUTO_TEST_CASE(oversized_frame_rejected_from_header)
{
    // Only the header is needed to reject: claim MAX_FRAME_PAYLOAD + 1 bytes.
    std::string hdr;
    hdr.push_back(static_cast<char>(0x82));
    hdr.push_back(static_cast<char>(0x80 | 127));
    const uint64_t len{WebSocketSock::MAX_FRAME_PAYLOAD + 1};
    for (int shift = 56; shift >= 0; shift -= 8) hdr.push_back(static_cast<char>(len >> shift));
    hdr += std::string("\x01\x02\x03\x04", 4);
    MockWsSock sock{Handshake() + hdr};
    const auto [data, r] = RecvAll(sock);
    BOOST_CHECK(data.empty());
    BOOST_CHECK_EQUAL(r, -1);
    BOOST_CHECK_EQUAL(errno, EPROTO);

    // Exactly the maximum is accepted (header only, payload pending).
    std::string ok_hdr;
    ok_hdr.push_back(static_cast<char>(0x82));
    ok_hdr.push_back(static_cast<char>(0x80 | 127));
    const uint64_t ok_len{WebSocketSock::MAX_FRAME_PAYLOAD};
    for (int shift = 56; shift >= 0; shift -= 8) ok_hdr.push_back(static_cast<char>(ok_len >> shift));
    ok_hdr += std::string("\x01\x02\x03\x04", 4);
    MockWsSock sock2{Handshake() + ok_hdr};
    const auto [data2, r2] = RecvAll(sock2);
    BOOST_CHECK(data2.empty());
    BOOST_CHECK_EQUAL(r2, -1);
    BOOST_CHECK_EQUAL(errno, EAGAIN);
}

BOOST_AUTO_TEST_CASE(send_frames)
{
    MockWsSock sock{Handshake()};

    // Nothing may be sent before the handshake completed.
    BOOST_CHECK_EQUAL(sock.Send("x", 1, 0), -1);
    BOOST_CHECK_EQUAL(errno, EAGAIN);
    BOOST_CHECK(sock.m_output.empty());

    (void)RecvAll(sock);
    BOOST_REQUIRE(sock.HandshakeComplete());
    sock.m_output.clear();

    BOOST_CHECK_EQUAL(sock.Send("abc", 3, 0), 3);
    BOOST_CHECK_EQUAL(sock.m_output, ServerFrame(0x2, "abc"));
    sock.m_output.clear();

    // Zero-length sends produce nothing.
    BOOST_CHECK_EQUAL(sock.Send("", 0, 0), 0);
    BOOST_CHECK(sock.m_output.empty());

    const std::string medium(1000, 'm');
    BOOST_CHECK_EQUAL(sock.Send(medium.data(), medium.size(), 0), 1000);
    BOOST_CHECK(sock.m_output == ServerFrame(0x2, medium));
    sock.m_output.clear();

    // Larger than MAX_SEND_FRAME: split into two frames across two calls.
    const std::string big(WebSocketSock::MAX_SEND_FRAME + 10, 'b');
    ssize_t sent{sock.Send(big.data(), big.size(), 0)};
    BOOST_CHECK_EQUAL(sent, static_cast<ssize_t>(WebSocketSock::MAX_SEND_FRAME));
    sent = sock.Send(big.data() + sent, big.size() - sent, 0);
    BOOST_CHECK_EQUAL(sent, 10);
    BOOST_CHECK(sock.m_output == ServerFrame(0x2, big.substr(0, WebSocketSock::MAX_SEND_FRAME)) + ServerFrame(0x2, big.substr(WebSocketSock::MAX_SEND_FRAME)));
}

BOOST_AUTO_TEST_CASE(send_partial_writes)
{
    MockWsSock sock{Handshake()};
    (void)RecvAll(sock);
    sock.m_output.clear();

    const std::string msg{"0123456789"};
    // Only one byte of the header goes out: nothing is reported as sent.
    sock.m_send_budget = 1;
    BOOST_CHECK_EQUAL(sock.Send(msg.data(), msg.size(), 0), -1);
    BOOST_CHECK_EQUAL(errno, EAGAIN);
    BOOST_CHECK_EQUAL(sock.m_output.size(), 1U);

    // Rest of the header plus 4 payload bytes.
    sock.m_send_budget = 5;
    BOOST_CHECK_EQUAL(sock.Send(msg.data(), msg.size(), 0), 4);
    // The caller re-offers the unsent tail; it continues the same frame.
    sock.m_send_budget = 3;
    BOOST_CHECK_EQUAL(sock.Send(msg.data() + 4, msg.size() - 4, 0), 3);
    sock.m_send_budget = 0;
    BOOST_CHECK_EQUAL(sock.Send(msg.data() + 7, msg.size() - 7, 0), -1);
    BOOST_CHECK_EQUAL(errno, EAGAIN);
    sock.m_send_budget = std::numeric_limits<size_t>::max();
    BOOST_CHECK_EQUAL(sock.Send(msg.data() + 7, msg.size() - 7, 0), 3);
    BOOST_CHECK_EQUAL(sock.m_output, ServerFrame(0x2, msg));
    sock.m_output.clear();

    // A ping received mid-frame is answered only once the frame is complete.
    sock.m_send_budget = 2 + 4;
    BOOST_CHECK_EQUAL(sock.Send(msg.data(), msg.size(), 0), 4);
    sock.Feed(Frame(0x9, "hi"));
    (void)RecvAll(sock);
    BOOST_CHECK_EQUAL(sock.m_output, ServerFrame(0x2, msg).substr(0, 6));
    sock.m_send_budget = std::numeric_limits<size_t>::max();
    BOOST_CHECK_EQUAL(sock.Send(msg.data() + 4, msg.size() - 4, 0), 6);
    BOOST_CHECK_EQUAL(sock.Send("z", 1, 0), 1);
    BOOST_CHECK_EQUAL(sock.m_output, ServerFrame(0x2, msg) + ServerFrame(0xA, "hi") + ServerFrame(0x2, "z"));
}

BOOST_AUTO_TEST_CASE(ping_flood_with_stuck_send_fails_not_grows)
{
    // A peer that completes the handshake then streams pings while never
    // reading (send budget 0 after the 101 reply) must NOT make us buffer a
    // pong per ping without bound: past MAX_CONTROL_QUEUE_BYTES the connection
    // fails instead. Recv() reports the error and the buffered protocol bytes
    // stay bounded.
    std::string input{Handshake()};
    // Enough 125-byte pings to blow well past the 4 KiB control-queue cap.
    for (int i = 0; i < 200; ++i) input += Frame(0x9, std::string(125, 'x'));
    MockWsSock sock{input};
    // Let the handshake 101 flush, then wedge the send side.
    (void)RecvAll(sock);
    sock.m_send_budget = 0;
    sock.m_output.clear();

    char buf[4096];
    ssize_t r{0};
    for (int i = 0; i < 500 && r >= 0; ++i) {
        r = sock.Recv(buf, sizeof(buf), MSG_DONTWAIT);
        if (r == 0) break; // clean close never expected here
    }
    // The flood ends in a reported error (protocol/queue failure), not an
    // endlessly-growing buffer that returns EWOULDBLOCK forever.
    BOOST_CHECK_EQUAL(r, -1);
    BOOST_CHECK(sock.PendingSendBytes() <= WebSocketSock::MAX_CONTROL_QUEUE_BYTES + 256);
}

BOOST_AUTO_TEST_SUITE_END()
