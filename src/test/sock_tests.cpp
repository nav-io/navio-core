// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/system.h>
#include <compat/compat.h>
#include <test/util/setup_common.h>
#include <util/sock.h>
#include <util/threadinterrupt.h>

#include <boost/test/unit_test.hpp>

#include <cassert>
#include <thread>

using namespace std::chrono_literals;

BOOST_FIXTURE_TEST_SUITE(sock_tests, BasicTestingSetup)

static bool SocketIsClosed(const SOCKET& s)
{
    // Notice that if another thread is running and creates its own socket after `s` has been
    // closed, it may be assigned the same file descriptor number. In this case, our test will
    // wrongly pretend that the socket is not closed.
    int type;
    socklen_t len = sizeof(type);
    return getsockopt(s, SOL_SOCKET, SO_TYPE, (sockopt_arg_type)&type, &len) == SOCKET_ERROR;
}

static SOCKET CreateSocket()
{
    const SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    BOOST_REQUIRE(s != static_cast<SOCKET>(SOCKET_ERROR));
    return s;
}

BOOST_AUTO_TEST_CASE(constructor_and_destructor)
{
    const SOCKET s = CreateSocket();
    Sock* sock = new Sock(s);
    BOOST_CHECK(*sock == s);
    BOOST_CHECK(!SocketIsClosed(s));
    delete sock;
    BOOST_CHECK(SocketIsClosed(s));
}

BOOST_AUTO_TEST_CASE(move_constructor)
{
    const SOCKET s = CreateSocket();
    Sock* sock1 = new Sock(s);
    Sock* sock2 = new Sock(std::move(*sock1));
    delete sock1;
    BOOST_CHECK(!SocketIsClosed(s));
    BOOST_CHECK(*sock2 == s);
    delete sock2;
    BOOST_CHECK(SocketIsClosed(s));
}

BOOST_AUTO_TEST_CASE(move_assignment)
{
    const SOCKET s1 = CreateSocket();
    const SOCKET s2 = CreateSocket();
    Sock* sock1 = new Sock(s1);
    Sock* sock2 = new Sock(s2);

    BOOST_CHECK(!SocketIsClosed(s1));
    BOOST_CHECK(!SocketIsClosed(s2));

    *sock2 = std::move(*sock1);
    BOOST_CHECK(!SocketIsClosed(s1));
    BOOST_CHECK(SocketIsClosed(s2));
    BOOST_CHECK(*sock2 == s1);

    delete sock1;
    BOOST_CHECK(!SocketIsClosed(s1));
    BOOST_CHECK(SocketIsClosed(s2));
    BOOST_CHECK(*sock2 == s1);

    delete sock2;
    BOOST_CHECK(SocketIsClosed(s1));
    BOOST_CHECK(SocketIsClosed(s2));
}

#ifndef WIN32 // Windows does not have socketpair(2).

static void CreateSocketPair(int s[2])
{
    BOOST_REQUIRE_EQUAL(socketpair(AF_UNIX, SOCK_STREAM, 0, s), 0);
}

static void SendAndRecvMessage(const Sock& sender, const Sock& receiver)
{
    const char* msg = "abcd";
    constexpr ssize_t msg_len = 4;
    char recv_buf[10];

    BOOST_CHECK_EQUAL(sender.Send(msg, msg_len, 0), msg_len);
    BOOST_CHECK_EQUAL(receiver.Recv(recv_buf, sizeof(recv_buf), 0), msg_len);
    BOOST_CHECK_EQUAL(strncmp(msg, recv_buf, msg_len), 0);
}

BOOST_AUTO_TEST_CASE(send_and_receive)
{
    int s[2];
    CreateSocketPair(s);

    Sock* sock0 = new Sock(s[0]);
    Sock* sock1 = new Sock(s[1]);

    SendAndRecvMessage(*sock0, *sock1);

    Sock* sock0moved = new Sock(std::move(*sock0));
    Sock* sock1moved = new Sock(INVALID_SOCKET);
    *sock1moved = std::move(*sock1);

    delete sock0;
    delete sock1;

    SendAndRecvMessage(*sock1moved, *sock0moved);

    delete sock0moved;
    delete sock1moved;

    BOOST_CHECK(SocketIsClosed(s[0]));
    BOOST_CHECK(SocketIsClosed(s[1]));
}

BOOST_AUTO_TEST_CASE(wait)
{
    int s[2];
    CreateSocketPair(s);

    Sock sock0(s[0]);
    Sock sock1(s[1]);

    std::thread waiter([&sock0]() { (void)sock0.Wait(24h, Sock::RECV); });

    BOOST_REQUIRE_EQUAL(sock1.Send("a", 1, 0), 1);

    waiter.join();
}

BOOST_AUTO_TEST_CASE(wait_many_no_error_event_when_not_reading)
{
    // A socket we wait on only to send must not report an error event for
    // pending urgent (out-of-band) data: the socket handler receives on an
    // error event, which would read from a peer whose receiving is paused.
    const SOCKET listen_fd{CreateSocket()};
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t addr_len{sizeof(addr)};
    BOOST_REQUIRE_EQUAL(bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), addr_len), 0);
    BOOST_REQUIRE_EQUAL(listen(listen_fd, 1), 0);
    BOOST_REQUIRE_EQUAL(getsockname(listen_fd, reinterpret_cast<sockaddr*>(&addr), &addr_len), 0);
    const Sock listener{listen_fd};

    const Sock client{CreateSocket()};
    BOOST_REQUIRE_EQUAL(client.Connect(reinterpret_cast<sockaddr*>(&addr), addr_len), 0);
    const SOCKET server_fd = accept(listen_fd, nullptr, nullptr);
    BOOST_REQUIRE(server_fd != INVALID_SOCKET);

    BOOST_REQUIRE_EQUAL(client.Send("u", 1, MSG_OOB), 1);
    // Wait until the urgent byte has arrived, so the check below sees it.
    fd_set except;
    FD_ZERO(&except);
    FD_SET(server_fd, &except);
    timeval tv{/*tv_sec=*/60, /*tv_usec=*/0};
    BOOST_REQUIRE_EQUAL(select(server_fd + 1, nullptr, nullptr, &except, &tv), 1);

    const auto server{std::make_shared<const Sock>(server_fd)};
    Sock::EventsPerSock events{{server, Sock::Events{Sock::SEND}}};
    BOOST_REQUIRE(server->WaitMany(0ms, events));
    BOOST_CHECK(events.at(server).occurred & Sock::SEND);
    BOOST_CHECK(!(events.at(server).occurred & Sock::ERR));
}

BOOST_AUTO_TEST_CASE(recv_until_terminator_limit)
{
    constexpr auto timeout = 1min; // High enough so that it is never hit.
    CThreadInterrupt interrupt;
    int s[2];
    CreateSocketPair(s);

    Sock sock_send(s[0]);
    Sock sock_recv(s[1]);

    std::thread receiver([&sock_recv, &timeout, &interrupt]() {
        constexpr size_t max_data{10};
        bool threw_as_expected{false};
        // BOOST_CHECK_EXCEPTION() writes to some variables shared with the main thread which
        // creates a data race. So mimic it manually.
        try {
            (void)sock_recv.RecvUntilTerminator('\n', timeout, interrupt, max_data);
        } catch (const std::runtime_error& e) {
            threw_as_expected = HasReason("too many bytes without a terminator")(e);
        }
        assert(threw_as_expected);
    });

    BOOST_REQUIRE_NO_THROW(sock_send.SendComplete("1234567", timeout, interrupt));
    BOOST_REQUIRE_NO_THROW(sock_send.SendComplete("89a\n", timeout, interrupt));

    receiver.join();
}

#endif /* WIN32 */

BOOST_AUTO_TEST_SUITE_END()
