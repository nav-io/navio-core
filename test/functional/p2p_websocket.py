#!/usr/bin/env python3
# Copyright (c) 2024-present The Navio Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the optional WebSocket P2P listener (-p2pwsbind).

A browser-style client is emulated with a plain TCP socket, a hand-rolled
RFC 6455 client handshake and masked binary frames carrying the ordinary v1
P2P byte stream. No third-party WebSocket library is used.
"""

import base64
import hashlib
from io import BytesIO
import os
import socket
import struct

from test_framework.messages import (
    msg_ping,
    msg_verack,
    msg_version,
    sha256,
)
from test_framework.p2p import (
    MAGIC_BYTES,
    MESSAGEMAP,
    P2P_SERVICES,
    P2P_SUBVERSION,
    P2P_VERSION,
    P2P_VERSION_RELAY,
    P2PInterface,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import (
    assert_equal,
    p2p_port,
)

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OPCODE_CONT = 0x0
OPCODE_TEXT = 0x1
OPCODE_BINARY = 0x2
OPCODE_CLOSE = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA


def recv_exact(sock, n):
    """Read exactly n bytes from a blocking socket (b'' on EOF)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf


def expect_closed(sock):
    """Assert that the server closed the connection without sending more data."""
    try:
        assert_equal(recv_exact(sock, 1), b"")
    except ConnectionResetError:
        pass


def recv_until(sock, terminator, limit=16384):
    buf = b""
    while terminator not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        assert len(buf) <= limit, "response too large"
    return buf


class WsClient:
    """Minimal RFC 6455 client over a blocking TCP socket."""

    def __init__(self, host, port, timeout):
        self.host = host
        self.port = port
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.stream = b""  # decoded application bytes not yet consumed

    def close(self):
        self.sock.close()

    # -- HTTP upgrade -------------------------------------------------------

    def raw_handshake(self, request):
        """Send a raw HTTP request and return the response head (bytes)."""
        self.sock.sendall(request)
        return recv_until(self.sock, b"\r\n\r\n")

    def handshake(self):
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET /p2p HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: keep-alive, Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Extensions: permessage-deflate\r\n"
            f"\r\n"
        ).encode()
        response = self.raw_handshake(request)
        head, _, rest = response.partition(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        assert lines[0] == "HTTP/1.1 101 Switching Protocols", lines[0]
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        expected = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        assert_equal(headers["sec-websocket-accept"], expected)
        assert_equal(headers["upgrade"].lower(), "websocket")
        assert "sec-websocket-extensions" not in headers
        # Anything after the header block is already framed data.
        self._pending_raw = rest

    # -- framing ------------------------------------------------------------

    def send_frame(self, opcode, payload, fin=True, masked=True):
        header = bytes([(0x80 if fin else 0x00) | opcode])
        mask_bit = 0x80 if masked else 0x00
        n = len(payload)
        if n < 126:
            header += bytes([mask_bit | n])
        elif n <= 0xFFFF:
            header += bytes([mask_bit | 126]) + struct.pack(">H", n)
        else:
            header += bytes([mask_bit | 127]) + struct.pack(">Q", n)
        if masked:
            mask = os.urandom(4)
            payload = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
            header += mask
        self.sock.sendall(header + payload)

    def _raw_recv(self, n):
        # Serve bytes that arrived together with the handshake response first.
        buf = b""
        if self._pending_raw:
            buf = self._pending_raw[:n]
            self._pending_raw = self._pending_raw[n:]
        if len(buf) < n:
            more = recv_exact(self.sock, n - len(buf))
            buf += more
        return buf

    def recv_frame(self):
        """Return (opcode, payload) of the next frame from the server, or None on EOF."""
        hdr = self._raw_recv(2)
        if len(hdr) < 2:
            return None
        fin = hdr[0] & 0x80
        assert fin, "server must not fragment"
        assert hdr[0] & 0x70 == 0, "no extensions negotiated"
        opcode = hdr[0] & 0x0F
        assert hdr[1] & 0x80 == 0, "server frames must not be masked"
        n = hdr[1] & 0x7F
        if n == 126:
            n = struct.unpack(">H", self._raw_recv(2))[0]
        elif n == 127:
            n = struct.unpack(">Q", self._raw_recv(8))[0]
        payload = self._raw_recv(n)
        assert_equal(len(payload), n)
        return opcode, payload

    # -- P2P byte stream ----------------------------------------------------

    def send_bytes(self, data):
        self.send_frame(OPCODE_BINARY, data)

    def send_msg(self, magic, message):
        self.send_bytes(build_message(magic, message))

    def recv_control_or_fill(self):
        """Read one frame; return a control (opcode, payload) or None after appending data."""
        frame = self.recv_frame()
        assert frame is not None, "unexpected EOF"
        opcode, payload = frame
        if opcode in (OPCODE_BINARY, OPCODE_CONT):
            self.stream += payload
            return None
        return opcode, payload

    def recv_msg(self, magic):
        """Return (msgtype, message) of the next P2P message, skipping control frames."""
        while True:
            if len(self.stream) >= 24:
                assert_equal(self.stream[:4], magic)
                msgtype = self.stream[4:16].split(b"\x00", 1)[0]
                length = struct.unpack("<I", self.stream[16:20])[0]
                checksum = self.stream[20:24]
                if len(self.stream) >= 24 + length:
                    payload = self.stream[24:24 + length]
                    self.stream = self.stream[24 + length:]
                    assert_equal(checksum, sha256(sha256(payload))[:4])
                    if msgtype in MESSAGEMAP:
                        msg = MESSAGEMAP[msgtype]()
                        msg.deserialize(BytesIO(payload))
                    else:
                        msg = None
                    return msgtype, msg
            control = self.recv_control_or_fill()
            assert control is None, f"unexpected control frame {control}"

    def wait_for_msg(self, magic, wanted):
        while True:
            msgtype, msg = self.recv_msg(magic)
            if msgtype == wanted:
                return msg


def build_message(magic, message):
    """Serialize a P2P message with the v1 header (same as P2PConnection.build_message)."""
    msgtype = message.msgtype
    data = message.serialize()
    tmsg = magic
    tmsg += msgtype
    tmsg += b"\x00" * (12 - len(msgtype))
    tmsg += struct.pack("<I", len(data))
    tmsg += sha256(sha256(data))[:4]
    tmsg += data
    return tmsg


class P2PWebSocketTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def run_test(self):
        node = self.nodes[0]
        magic = MAGIC_BYTES[self.chain]
        host = "127.0.0.1"
        # Port index num_nodes is reserved for this test process but unused by any node.
        ws_port = p2p_port(self.num_nodes)
        timeout = 60 * self.options.timeout_factor

        self.log.info("Restart node with -p2pwsbind")
        with node.assert_debug_log([f"Bound to {host}:{ws_port} (websocket)"]):
            self.restart_node(0, extra_args=[f"-p2pwsbind={host}:{ws_port}"])
        assert_equal(node.getpeerinfo(), [])

        self.log.info("A plain TCP peer on the regular port still works")
        node.add_p2p_connection(P2PInterface())
        assert_equal(len(node.getpeerinfo()), 1)
        assert_equal(node.getpeerinfo()[0]["websocket"], False)
        node.disconnect_p2ps()
        self.wait_until(lambda: node.getpeerinfo() == [])

        self.log.info("A malformed upgrade request is answered with 400 and closed")
        with node.assert_debug_log(["websocket: handshake missing 'Upgrade: websocket'"]):
            bad = WsClient(host, ws_port, timeout)
            response = bad.raw_handshake(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            assert response.startswith(b"HTTP/1.1 400 Bad Request\r\n"), response
            # Server closes after the 400.
            expect_closed(bad.sock)
            bad.close()
        self.wait_until(lambda: node.getpeerinfo() == [])

        self.log.info("Complete the WebSocket handshake and the P2P version handshake")
        client = WsClient(host, ws_port, timeout)
        client.handshake()

        version = msg_version()
        version.nVersion = P2P_VERSION
        version.strSubVer = P2P_SUBVERSION
        version.relay = P2P_VERSION_RELAY
        version.nServices = P2P_SERVICES
        version.addrTo.ip = host
        version.addrTo.port = ws_port
        version.addrFrom.ip = "0.0.0.0"
        version.addrFrom.port = 0
        # Send the header and the payload in separate, fragmented frames to
        # show that frame boundaries carry no meaning.
        raw = build_message(magic, version)
        client.send_frame(OPCODE_BINARY, raw[:10], fin=False)
        client.send_frame(OPCODE_CONT, raw[10:24], fin=False)
        client.send_frame(OPCODE_CONT, raw[24:], fin=True)

        their_version = client.wait_for_msg(magic, b"version")
        assert their_version.nVersion >= P2P_VERSION
        client.wait_for_msg(magic, b"verack")
        client.send_msg(magic, msg_verack())

        self.wait_until(lambda: len(node.getpeerinfo()) == 1 and node.getpeerinfo()[0]["version"] == P2P_VERSION)
        peer = node.getpeerinfo()[0]
        assert_equal(peer["inbound"], True)
        assert_equal(peer["websocket"], True)
        assert_equal(peer["connection_type"], "inbound")
        assert_equal(peer["transport_protocol_type"], "v1")
        assert_equal(peer["subver"], P2P_SUBVERSION)
        assert_equal(peer["addrbind"], f"{host}:{ws_port}")
        assert_equal(peer["permissions"], [])

        self.log.info("P2P ping/pong over the WebSocket byte stream")
        nonce = 0x1234567890ABCDEF
        client.send_msg(magic, msg_ping(nonce))
        pong = client.wait_for_msg(magic, b"pong")
        assert_equal(pong.nonce, nonce)

        self.log.info("WebSocket ping control frame is answered with pong")
        client.send_frame(OPCODE_PING, b"hello")
        # A P2P ping makes the node send something, which gives the deferred
        # pong (if any) a chance to be flushed even on an otherwise idle link.
        client.send_msg(magic, msg_ping(nonce + 1))
        while True:
            control = client.recv_control_or_fill()
            if control is not None:
                break
        assert_equal(control, (OPCODE_PONG, b"hello"))
        pong = client.wait_for_msg(magic, b"pong")
        assert_equal(pong.nonce, nonce + 1)

        self.log.info("An unsolicited pong is ignored")
        client.send_frame(OPCODE_PONG, b"whatever")
        client.send_msg(magic, msg_ping(nonce + 2))
        pong = client.wait_for_msg(magic, b"pong")
        assert_equal(pong.nonce, nonce + 2)
        assert_equal(len(node.getpeerinfo()), 1)

        self.log.info("Close frame is answered with close and the peer is disconnected")
        client.send_frame(OPCODE_CLOSE, struct.pack(">H", 1000))
        while True:
            frame = client.recv_frame()
            assert frame is not None, "EOF before close frame"
            if frame[0] == OPCODE_CLOSE:
                assert_equal(frame[1], struct.pack(">H", 1000))
                break
        expect_closed(client.sock)
        client.close()
        self.wait_until(lambda: node.getpeerinfo() == [])

        self.log.info("A text frame is a protocol error and disconnects the peer")
        client = WsClient(host, ws_port, timeout)
        client.handshake()
        client.send_msg(magic, version)
        client.wait_for_msg(magic, b"verack")
        client.send_msg(magic, msg_verack())
        self.wait_until(lambda: len(node.getpeerinfo()) == 1)
        with node.assert_debug_log(["websocket: text frames are not allowed"]):
            client.send_frame(OPCODE_TEXT, b"nope")
            self.wait_until(lambda: node.getpeerinfo() == [])
        client.close()

        self.log.info("An unmasked client frame is a protocol error")
        client = WsClient(host, ws_port, timeout)
        client.handshake()
        with node.assert_debug_log(["websocket: unmasked client frame"]):
            client.send_frame(OPCODE_BINARY, build_message(magic, version), masked=False)
            # The server drops the connection without any application data.
            expect_closed(client.sock)
        client.close()
        self.wait_until(lambda: node.getpeerinfo() == [])

        self.log.info("-p2pwsbind requires -listen")
        self.stop_node(0)
        node.assert_start_raises_init_error(
            [f"-p2pwsbind={host}:{ws_port}", "-listen=0"],
            "Cannot set -bind or -whitebind together with -listen=0",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        node.assert_start_raises_init_error(
            ["-p2pwsbind=127.0.0.1:notaport"],
            "Invalid port specified in -p2pwsbind: '127.0.0.1:notaport'",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        self.start_node(0)


if __name__ == "__main__":
    P2PWebSocketTest(__file__).main()
