// Copyright (c) 2024-present The Navio Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/sock_ws.h>

#include <compat/compat.h>
#include <crypto/sha1.h>
#include <logging.h>
#include <span.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <map>
#include <string>
#include <string_view>

namespace {

constexpr uint8_t OPCODE_CONTINUATION{0x0};
constexpr uint8_t OPCODE_TEXT{0x1};
constexpr uint8_t OPCODE_BINARY{0x2};
constexpr uint8_t OPCODE_CLOSE{0x8};
constexpr uint8_t OPCODE_PING{0x9};
constexpr uint8_t OPCODE_PONG{0xA};

constexpr size_t MAX_CONTROL_PAYLOAD{125};

constexpr std::string_view WS_GUID{"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"};

constexpr std::string_view HTTP_400_RESPONSE{
    "HTTP/1.1 400 Bad Request\r\n"
    "Connection: close\r\n"
    "Content-Length: 0\r\n"
    "\r\n"};

void SetLastNetError(int err)
{
#ifdef WIN32
    WSASetLastError(err);
#else
    errno = err;
#endif
}

int ProtocolErrorCode()
{
#ifdef WIN32
    return WSAECONNABORTED;
#else
    return EPROTO;
#endif
}

bool IsWouldBlock(int err)
{
    return err == WSAEWOULDBLOCK || err == WSAEAGAIN || err == WSAEINTR || err == WSAEINPROGRESS;
}

/** Whether a comma separated header value contains `token` (case-insensitive). */
bool HeaderHasToken(std::string_view value, std::string_view token)
{
    for (const auto& part : SplitString(value, ',')) {
        if (ToLower(TrimStringView(part)) == token) return true;
    }
    return false;
}

/** Encode a WebSocket frame header (server side: never masked). */
std::vector<uint8_t> EncodeFrameHeader(uint8_t opcode, uint64_t payload_len)
{
    std::vector<uint8_t> hdr;
    hdr.push_back(0x80 | (opcode & 0x0F)); // FIN + opcode
    if (payload_len < 126) {
        hdr.push_back(static_cast<uint8_t>(payload_len));
    } else if (payload_len <= 0xFFFF) {
        hdr.push_back(126);
        hdr.push_back(static_cast<uint8_t>(payload_len >> 8));
        hdr.push_back(static_cast<uint8_t>(payload_len));
    } else {
        hdr.push_back(127);
        for (int shift = 56; shift >= 0; shift -= 8) {
            hdr.push_back(static_cast<uint8_t>(payload_len >> shift));
        }
    }
    return hdr;
}

} // namespace

WebSocketSock::WebSocketSock(std::unique_ptr<Sock>&& inner) : Sock{std::move(*inner)} {}

WebSocketSock::WebSocketSock(SOCKET s) : Sock{s} {}

WebSocketSock& WebSocketSock::operator=(Sock&& other)
{
    assert(false && "Move of Sock into WebSocketSock not allowed.");
    return *this;
}

std::string WebSocketSock::ComputeAccept(const std::string& key)
{
    const std::string material{key + std::string{WS_GUID}};
    unsigned char hash[CSHA1::OUTPUT_SIZE];
    CSHA1().Write(reinterpret_cast<const unsigned char*>(material.data()), material.size()).Finalize(hash);
    return EncodeBase64(Span<const unsigned char>{hash, CSHA1::OUTPUT_SIZE});
}

// ---------------------------------------------------------------------------
// Send side
// ---------------------------------------------------------------------------

void WebSocketSock::QueueRaw(Span<const uint8_t> bytes) const
{
    m_send_pending.insert(m_send_pending.end(), bytes.begin(), bytes.end());
}

void WebSocketSock::CompactSendPrefix() const
{
    if (m_send_pending_pos == 0) return;
    m_send_pending.erase(m_send_pending.begin(), m_send_pending.begin() + m_send_pending_pos);
    m_send_pending_pos = 0;
}

bool WebSocketSock::QueueControlFrame(uint8_t opcode, Span<const uint8_t> payload) const
{
    // Bound the protocol-frame bytes we will buffer for a peer that has
    // stopped reading. Pings decode to zero application bytes, so the node's
    // normal backpressure (fPauseRecv/fPauseSend, both driven by app-byte
    // accounting) never sees them; without a cap a peer streaming pings makes
    // us queue a pong each and buffer heap without bound. One outstanding
    // control frame's worth is plenty; past the budget, signal the caller to
    // fail the connection instead of queueing more.
    const size_t queued{(m_send_pending.size() - m_send_pending_pos) + m_control_out.size()};
    if (queued > MAX_CONTROL_QUEUE_BYTES) {
        LogPrint(BCLog::NET, "websocket: control-frame send queue over %u bytes; failing peer\n", MAX_CONTROL_QUEUE_BYTES);
        return false;
    }
    const std::vector<uint8_t> hdr{EncodeFrameHeader(opcode, payload.size())};
    std::vector<uint8_t>& dest{m_frame_remaining == 0 ? m_send_pending : m_control_out};
    dest.insert(dest.end(), hdr.begin(), hdr.end());
    dest.insert(dest.end(), payload.begin(), payload.end());
    return true;
}

bool WebSocketSock::FlushPending(int flags) const
{
    while (m_send_pending_pos < m_send_pending.size()) {
        const ssize_t sent{RawSend(m_send_pending.data() + m_send_pending_pos,
                                   m_send_pending.size() - m_send_pending_pos,
                                   flags)};
        if (sent < 0) {
            const int err{WSAGetLastError()};
            if (IsWouldBlock(err)) SetLastNetError(WSAEWOULDBLOCK);
            CompactSendPrefix();
            return false;
        }
        if (sent == 0) {
            SetLastNetError(WSAEWOULDBLOCK);
            CompactSendPrefix();
            return false;
        }
        m_send_pending_pos += static_cast<size_t>(sent);
    }
    m_send_pending.clear();
    m_send_pending.shrink_to_fit();
    m_send_pending_pos = 0;
    return true;
}

ssize_t WebSocketSock::Send(const void* data, size_t len, int flags) const
{
    if (!HandshakeComplete()) {
        // Nothing may go out before the 101 reply; the P2P protocol never
        // makes an inbound peer's server speak first so this is only a guard.
        SetLastNetError(WSAEWOULDBLOCK);
        return -1;
    }

    if (!FlushPending(flags)) return -1;

    if (m_frame_remaining == 0) {
        // Between data frames: first let out any control frames that were
        // deferred while the previous frame was in flight.
        if (!m_control_out.empty()) {
            QueueRaw(m_control_out);
            m_control_out.clear();
            if (!FlushPending(flags)) return -1;
        }
        if (len == 0) return 0;
        const size_t chunk{std::min(len, MAX_SEND_FRAME)};
        const std::vector<uint8_t> hdr{EncodeFrameHeader(OPCODE_BINARY, chunk)};
        QueueRaw(hdr);
        m_frame_remaining = chunk;
        if (!FlushPending(flags)) return -1;
    }

    const size_t to_send{std::min(len, m_frame_remaining)};
    const ssize_t sent{RawSend(data, to_send, flags)};
    if (sent > 0) {
        m_frame_remaining -= static_cast<size_t>(sent);
    }
    return sent;
}

// ---------------------------------------------------------------------------
// Receive side
// ---------------------------------------------------------------------------

ssize_t WebSocketSock::DrainAppBytes(void* buf, size_t len) const
{
    const size_t n{std::min(len, m_app_out.size() - m_app_out_pos)};
    std::memcpy(buf, m_app_out.data() + m_app_out_pos, n);
    m_app_out_pos += n;
    if (m_app_out_pos == m_app_out.size()) {
        m_app_out.clear();
        m_app_out_pos = 0;
    }
    return static_cast<ssize_t>(n);
}

ssize_t WebSocketSock::Recv(void* buf, size_t len, int flags) const
{
    if (m_recv_state == RecvState::FAILED) {
        SetLastNetError(ProtocolErrorCode());
        return -1;
    }
    if (m_recv_state == RecvState::CLOSED) return 0;
    if (len == 0) return 0;

    if (m_app_out_pos < m_app_out.size()) return DrainAppBytes(buf, len);

    // Opportunistically push out protocol-generated bytes (e.g. a pong or a
    // handshake reply that could not be written completely earlier).
    if (m_frame_remaining == 0 && !m_control_out.empty()) {
        QueueRaw(m_control_out);
        m_control_out.clear();
    }
    if (!FlushPending(MSG_NOSIGNAL | MSG_DONTWAIT) && !IsWouldBlock(WSAGetLastError())) {
        return -1;
    }

    // Never read more raw bytes than the caller can take back as payload, so
    // that no decoded application bytes are left behind in `m_app_out` (which
    // `Wait()` on the file descriptor could not report as readable).
    static constexpr size_t MAX_RAW_READ{64 * 1024};
    const size_t raw_len{std::min(len, MAX_RAW_READ)};
    if (m_raw_buf.size() < raw_len) m_raw_buf.resize(raw_len);
    const ssize_t got{RawRecv(m_raw_buf.data(), raw_len, flags)};
    if (got < 0) return -1;
    if (got == 0) {
        if (!HandshakeComplete()) {
            LogPrint(BCLog::NET, "websocket: connection closed before the handshake completed\n");
        }
        m_recv_state = RecvState::CLOSED;
        return 0;
    }

    const bool ok{Consume(m_raw_buf.data(), static_cast<size_t>(got))};
    if (!ok) m_recv_state = RecvState::FAILED;

    // Hand over whatever was decoded before an error or close; the error/EOF
    // is sticky and will be reported on the next call.
    if (m_app_out_pos < m_app_out.size()) return DrainAppBytes(buf, len);
    if (!ok) {
        SetLastNetError(ProtocolErrorCode());
        return -1;
    }
    if (m_recv_state == RecvState::CLOSED) return 0;
    SetLastNetError(WSAEWOULDBLOCK);
    return -1;
}

bool WebSocketSock::Consume(const uint8_t* data, size_t len) const
{
    // Iterative, not recursive: when the handshake completes, bytes that
    // arrived in the same read are the first frame(s). Rather than recurse
    // into Consume() for them (which clang-tidy flags, misc-no-recursion),
    // swap the work buffer to those leftover bytes and keep looping.
    std::vector<uint8_t> work(data, data + len);
    size_t pos{0};
    while (pos < work.size()) {
        switch (m_recv_state) {
        case RecvState::HANDSHAKE: {
            // Look for the end of the HTTP header block; it may straddle reads.
            const size_t search_from{m_hs_buf.size() >= 3 ? m_hs_buf.size() - 3 : 0};
            m_hs_buf.insert(m_hs_buf.end(), work.begin() + pos, work.end());
            pos = work.size();
            static constexpr std::string_view TERMINATOR{"\r\n\r\n"};
            const auto it{std::search(m_hs_buf.begin() + search_from, m_hs_buf.end(),
                                      TERMINATOR.begin(), TERMINATOR.end())};
            const size_t request_len{it == m_hs_buf.end() ? 0 : static_cast<size_t>(it - m_hs_buf.begin()) + TERMINATOR.size()};
            if (request_len == 0 && m_hs_buf.size() <= MAX_HANDSHAKE_BYTES) break; // need more bytes
            if (request_len == 0 || request_len > MAX_HANDSHAKE_BYTES) {
                LogPrint(BCLog::NET, "websocket: handshake request exceeds %u bytes\n", MAX_HANDSHAKE_BYTES);
                QueueRaw(MakeUCharSpan(HTTP_400_RESPONSE));
                (void)FlushPending(MSG_NOSIGNAL | MSG_DONTWAIT);
                return false;
            }
            const std::string_view request{reinterpret_cast<const char*>(m_hs_buf.data()), request_len};
            if (!ProcessHandshake(request)) {
                QueueRaw(MakeUCharSpan(HTTP_400_RESPONSE));
                (void)FlushPending(MSG_NOSIGNAL | MSG_DONTWAIT);
                return false;
            }
            m_hs_ok = true;
            m_recv_state = RecvState::FRAME_HEADER;
            // Bytes that arrived together with the request are the first
            // frame(s): continue the loop over them instead of recursing.
            work.assign(m_hs_buf.begin() + request_len, m_hs_buf.end());
            pos = 0;
            m_hs_buf.clear();
            m_hs_buf.shrink_to_fit();
            continue;
        }
        case RecvState::FRAME_HEADER: {
            // Collect bytes one at a time until the (variable size) header is complete.
            m_hdr_buf.push_back(work[pos++]);
            if (m_hdr_buf.size() < 2) break;
            const uint8_t len7{static_cast<uint8_t>(m_hdr_buf[1] & 0x7F)};
            const bool masked{(m_hdr_buf[1] & 0x80) != 0};
            const size_t hdr_len{2 + (len7 == 126 ? 2u : len7 == 127 ? 8u : 0u) + (masked ? 4u : 0u)};
            if (m_hdr_buf.size() < hdr_len) break;
            if (!ProcessFrameHeader()) return false;
            break;
        }
        case RecvState::DATA_PAYLOAD: {
            const size_t n{static_cast<size_t>(std::min<uint64_t>(m_payload_remaining, work.size() - pos))};
            const size_t out_start{m_app_out.size()};
            m_app_out.resize(out_start + n);
            for (size_t i = 0; i < n; ++i) {
                m_app_out[out_start + i] = work[pos + i] ^ m_mask[m_mask_idx];
                m_mask_idx = (m_mask_idx + 1) & 3;
            }
            pos += n;
            m_payload_remaining -= n;
            if (m_payload_remaining == 0) m_recv_state = RecvState::FRAME_HEADER;
            break;
        }
        case RecvState::CONTROL_PAYLOAD: {
            const size_t n{static_cast<size_t>(std::min<uint64_t>(m_payload_remaining, work.size() - pos))};
            m_hdr_buf.insert(m_hdr_buf.end(), work.begin() + pos, work.begin() + pos + n);
            pos += n;
            m_payload_remaining -= n;
            if (m_payload_remaining == 0 && !ProcessControlFrame()) return false;
            break;
        }
        case RecvState::CLOSED:
            // Ignore anything after a close frame.
            return true;
        case RecvState::FAILED:
            return false;
        }
    }
    return true;
}

bool WebSocketSock::ProcessHandshake(std::string_view request) const
{
    const std::vector<std::string> lines{SplitString(request, "\r\n")};
    if (lines.empty()) return false;

    // Request line: "GET <target> HTTP/1.1"
    const std::string& request_line{lines[0]};
    if (request_line.rfind("GET ", 0) != 0 || request_line.size() < 4 + 1 + 9 ||
        request_line.compare(request_line.size() - 9, 9, " HTTP/1.1") != 0) {
        LogPrint(BCLog::NET, "websocket: bad handshake request line\n");
        return false;
    }

    std::map<std::string, std::string> headers;
    for (size_t i = 1; i < lines.size(); ++i) {
        const std::string& line{lines[i]};
        if (line.empty()) continue;
        const size_t colon{line.find(':')};
        if (colon == std::string::npos) {
            LogPrint(BCLog::NET, "websocket: malformed handshake header line\n");
            return false;
        }
        const std::string name{ToLower(TrimStringView(std::string_view{line}.substr(0, colon)))};
        const std::string value{TrimString(std::string_view{line}.substr(colon + 1))};
        auto [it, inserted] = headers.emplace(name, value);
        if (!inserted) it->second += ", " + value; // repeated header: treat as list
    }

    const auto get{[&headers](const std::string& name) -> std::string_view {
        const auto it{headers.find(name)};
        return it == headers.end() ? std::string_view{} : std::string_view{it->second};
    }};

    if (ToLower(get("upgrade")) != "websocket") {
        LogPrint(BCLog::NET, "websocket: handshake missing 'Upgrade: websocket'\n");
        return false;
    }
    if (!HeaderHasToken(get("connection"), "upgrade")) {
        LogPrint(BCLog::NET, "websocket: handshake missing 'Connection: Upgrade'\n");
        return false;
    }
    if (get("sec-websocket-version") != "13") {
        LogPrint(BCLog::NET, "websocket: unsupported Sec-WebSocket-Version\n");
        return false;
    }
    const std::string key{get("sec-websocket-key")};
    if (key.empty()) {
        LogPrint(BCLog::NET, "websocket: handshake missing Sec-WebSocket-Key\n");
        return false;
    }
    // Sec-WebSocket-Extensions and Sec-WebSocket-Protocol are deliberately
    // ignored: no extension is ever negotiated and no subprotocol is required.

    const std::string response{
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + ComputeAccept(key) + "\r\n"
        "\r\n"};
    QueueRaw(MakeUCharSpan(response));
    // Best effort: a partially written reply is completed by the next
    // Send()/Recv() call.
    if (!FlushPending(MSG_NOSIGNAL | MSG_DONTWAIT) && !IsWouldBlock(WSAGetLastError())) {
        LogPrint(BCLog::NET, "websocket: failed to send handshake response: %s\n", NetworkErrorString(WSAGetLastError()));
        return false;
    }
    return true;
}

bool WebSocketSock::ProcessFrameHeader() const
{
    const uint8_t b0{m_hdr_buf[0]};
    const uint8_t b1{m_hdr_buf[1]};
    const bool fin{(b0 & 0x80) != 0};
    const uint8_t opcode{static_cast<uint8_t>(b0 & 0x0F)};
    const bool masked{(b1 & 0x80) != 0};
    const uint8_t len7{static_cast<uint8_t>(b1 & 0x7F)};

    if ((b0 & 0x70) != 0) {
        LogPrint(BCLog::NET, "websocket: frame with RSV bits set (no extensions negotiated)\n");
        return false;
    }
    if (!masked) {
        LogPrint(BCLog::NET, "websocket: unmasked client frame\n");
        return false;
    }

    size_t off{2};
    uint64_t payload_len{len7};
    if (len7 == 126) {
        payload_len = (static_cast<uint64_t>(m_hdr_buf[2]) << 8) | m_hdr_buf[3];
        off = 4;
    } else if (len7 == 127) {
        payload_len = 0;
        for (size_t i = 0; i < 8; ++i) {
            payload_len = (payload_len << 8) | m_hdr_buf[2 + i];
        }
        off = 10;
        if (payload_len >> 63) {
            LogPrint(BCLog::NET, "websocket: invalid 64-bit payload length\n");
            return false;
        }
    }
    std::memcpy(m_mask, m_hdr_buf.data() + off, 4);
    m_mask_idx = 0;
    m_hdr_buf.clear();

    if (payload_len > MAX_FRAME_PAYLOAD) {
        LogPrint(BCLog::NET, "websocket: frame payload of %u bytes exceeds limit of %u\n", payload_len, MAX_FRAME_PAYLOAD);
        return false;
    }

    switch (opcode) {
    case OPCODE_CONTINUATION:
    case OPCODE_BINARY:
        // Frame boundaries carry no meaning for the byte stream, so FIN and
        // continuation are only accepted, not tracked.
        m_opcode = opcode;
        m_payload_remaining = payload_len;
        m_recv_state = payload_len == 0 ? RecvState::FRAME_HEADER : RecvState::DATA_PAYLOAD;
        return true;
    case OPCODE_TEXT:
        LogPrint(BCLog::NET, "websocket: text frames are not allowed\n");
        return false;
    case OPCODE_CLOSE:
    case OPCODE_PING:
    case OPCODE_PONG:
        if (!fin || payload_len > MAX_CONTROL_PAYLOAD) {
            LogPrint(BCLog::NET, "websocket: fragmented or oversized control frame\n");
            return false;
        }
        m_opcode = opcode;
        m_payload_remaining = payload_len;
        m_recv_state = RecvState::CONTROL_PAYLOAD;
        return payload_len == 0 ? ProcessControlFrame() : true;
    default:
        LogPrint(BCLog::NET, "websocket: unknown opcode %u\n", opcode);
        return false;
    }
}

bool WebSocketSock::ProcessControlFrame() const
{
    std::vector<uint8_t> payload{std::move(m_hdr_buf)};
    m_hdr_buf.clear();
    for (size_t i = 0; i < payload.size(); ++i) {
        payload[i] ^= m_mask[i & 3];
    }

    switch (m_opcode) {
    case OPCODE_PING:
        // A peer that pings without draining our pongs is a memory-DoS; a
        // full control queue fails the connection rather than buffering more.
        if (!QueueControlFrame(OPCODE_PONG, payload)) return false;
        break;
    case OPCODE_PONG:
        break;
    case OPCODE_CLOSE: {
        // Echo the status code (if any) back and report EOF to the caller.
        const Span<const uint8_t> status{payload.data(), payload.size() >= 2 ? size_t{2} : size_t{0}};
        (void)QueueControlFrame(OPCODE_CLOSE, status); // best-effort; we are closing regardless
        m_recv_state = RecvState::CLOSED;
        (void)FlushPending(MSG_NOSIGNAL | MSG_DONTWAIT);
        return true;
    }
    }
    m_recv_state = RecvState::FRAME_HEADER;
    (void)FlushPending(MSG_NOSIGNAL | MSG_DONTWAIT);
    return true;
}
