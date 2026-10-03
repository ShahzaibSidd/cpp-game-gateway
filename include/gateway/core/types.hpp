#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace gateway::core {

// ---------------------------------------------------------------------------
// Handle types & aliases
// ---------------------------------------------------------------------------

/// Index into the flat SessionPool arena (O(1) slot mapping).
using SessionId = std::uint32_t;

inline constexpr SessionId kInvalidSessionId = UINT32_MAX;

// ---------------------------------------------------------------------------
// Wire protocol limits (architecture.md §5.1)
// ---------------------------------------------------------------------------

inline constexpr std::uint16_t kFrameMagic = 0xAA55;  // Big Endian on the wire
inline constexpr std::size_t kMaxPayloadSize = 2048;

// magic(2) + payload_len(2) + opcode(2) + sequence_id(4)
inline constexpr std::size_t kFrameHeaderSize = 10;
inline constexpr std::size_t kFrameChecksumSize = 2;
inline constexpr std::size_t kFrameOverhead = kFrameHeaderSize + kFrameChecksumSize;
inline constexpr std::size_t kMaxFrameSize = kFrameOverhead + kMaxPayloadSize;

static_assert(kFrameOverhead == 12, "Framing overhead must be 12 bytes");
static_assert(kMaxFrameSize == 2060, "Max frame size must be 2060 bytes");

// ---------------------------------------------------------------------------
// Status & result enums
// ---------------------------------------------------------------------------

/// Generic operation result. No exceptions on hot paths.
enum class StatusCode : std::uint8_t {
    Ok = 0,
    BufferOverflow,
    ChecksumMismatch,
    InvalidMagic,
    PayloadTooLarge,
    InvalidArgument,
    InvalidState,
    NotInitialized,
    AlreadyRunning,
    SessionNotFound,
    SessionPoolExhausted,
    RateLimited,
    WouldBlock,
    SocketError,
    SystemError,
};

/// Outcome of a single IPacketCodec::parse_frame() call.
enum class ParseResult : std::uint8_t {
    FrameReady = 0,    // out_frame is valid; buffer advanced past the frame
    NeedMoreData,      // Partial frame; buffer left untouched
    InvalidMagic,      // Sync marker mismatch; resync or terminate
    PayloadTooLarge,   // payload_len > kMaxPayloadSize
    ChecksumMismatch,  // CRC16-CCITT verification failed
};

/// Why a session was (or is being) torn down. See §5.2 state machine.
enum class DisconnectReason : std::uint8_t {
    ClientClosed = 0,
    DisconnectFrame,
    HandshakeTimeout,
    InvalidAuth,
    RateLimitViolation,
    ProtocolError,
    IoError,
    ServerShutdown,
};

enum class TransportType : std::uint8_t {
    Tcp = 0,
    Udp,
};

// ---------------------------------------------------------------------------
// Frame structures
// ---------------------------------------------------------------------------

/// Logical (host-order) frame header. NOT a wire-layout overlay; the codec
/// is responsible for Big Endian (de)serialization.
struct FrameHeader {
    std::uint16_t magic = kFrameMagic;
    std::uint16_t payload_len = 0;
    std::uint16_t opcode = 0;
    std::uint32_t sequence_id = 0;
};

/// Zero-copy view of a decoded frame. `payload` references the caller's
/// receive buffer and is only valid while that buffer is alive and unmodified.
struct FrameView {
    FrameHeader header{};
    std::span<const std::uint8_t> payload{};
    std::uint16_t checksum = 0;
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

inline constexpr std::size_t kMaxBindAddressLen = 46;  // INET6_ADDRSTRLEN

/// Startup-time network configuration. Fixed-size; no dynamic allocation.
struct NetworkConfig {
    std::array<char, kMaxBindAddressLen> bind_address{'0', '.', '0', '.', '0', '.', '0', '\0'};
    std::uint16_t port = 0;
    TransportType transport = TransportType::Tcp;
    std::uint32_t max_sessions = 0;
    std::uint32_t max_events_per_poll = 0;
    std::uint32_t recv_buffer_size = 0;
    std::uint32_t send_buffer_size = 0;
    int listen_backlog = 0;
};

}  // namespace gateway::core
