#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "gateway/core/types.hpp"

// Binary frame layouts, magic bytes and wire constants (architecture.md §5.1).
//
// Wire layout (all multi-byte integers Big Endian):
//
//   offset  size  field
//   ------  ----  -----------------------------------------------
//        0     2  magic        0xAA55
//        2     2  payload_len  0..2048
//        4     2  opcode
//        6     4  sequence_id
//       10     N  payload      N = payload_len
//     10+N     2  checksum     CRC16-CCITT over bytes [0, 10+N)
//
// The codec reads/writes fields byte-by-byte at these offsets. No struct in
// this file is ever memcpy'd or reinterpret_cast onto raw wire bytes.

namespace gateway::protocol {

// ---------------------------------------------------------------------------
// Size limits (single source of truth lives in core/types.hpp)
// ---------------------------------------------------------------------------

using core::kFrameChecksumSize;
using core::kFrameHeaderSize;
using core::kFrameMagic;
using core::kFrameOverhead;
using core::kMaxFrameSize;
using core::kMaxPayloadSize;

/// Minimum bytes required before the header can be decoded.
inline constexpr std::size_t kMinFrameSize = kFrameOverhead;  // empty payload

// ---------------------------------------------------------------------------
// Magic bytes (as they appear on the wire, in order)
// ---------------------------------------------------------------------------

inline constexpr std::uint8_t kMagicByte0 = 0xAA;
inline constexpr std::uint8_t kMagicByte1 = 0x55;

static_assert(((kMagicByte0 << 8) | kMagicByte1) == kFrameMagic,
              "Magic bytes must match kFrameMagic in Big Endian order");

// ---------------------------------------------------------------------------
// Header field offsets & sizes (bytes from start of frame)
// ---------------------------------------------------------------------------

namespace wire {

inline constexpr std::size_t kMagicOffset = 0;
inline constexpr std::size_t kMagicSize = 2;

inline constexpr std::size_t kPayloadLenOffset = 2;
inline constexpr std::size_t kPayloadLenSize = 2;

inline constexpr std::size_t kOpcodeOffset = 4;
inline constexpr std::size_t kOpcodeSize = 2;

inline constexpr std::size_t kSequenceIdOffset = 6;
inline constexpr std::size_t kSequenceIdSize = 4;

inline constexpr std::size_t kPayloadOffset = 10;
// Checksum offset is dynamic: kPayloadOffset + payload_len.

static_assert(kPayloadLenOffset == kMagicOffset + kMagicSize);
static_assert(kOpcodeOffset == kPayloadLenOffset + kPayloadLenSize);
static_assert(kSequenceIdOffset == kOpcodeOffset + kOpcodeSize);
static_assert(kPayloadOffset == kSequenceIdOffset + kSequenceIdSize);
static_assert(kPayloadOffset == kFrameHeaderSize);

}  // namespace wire

// ---------------------------------------------------------------------------
// Checksum parameters: CRC16-CCITT ("CCITT-FALSE" variant)
// ---------------------------------------------------------------------------

namespace crc16 {

inline constexpr std::uint16_t kPolynomial = 0x1021;
inline constexpr std::uint16_t kInitialValue = 0xFFFF;
inline constexpr std::uint16_t kFinalXor = 0x0000;
inline constexpr bool kReflectInput = false;
inline constexpr bool kReflectOutput = false;

/// Standard check value: CRC of ASCII "123456789" with the params above.
inline constexpr std::uint16_t kCheckValue = 0x29B1;

}  // namespace crc16

// ---------------------------------------------------------------------------
// Opcodes
// ---------------------------------------------------------------------------

/// Gateway-level control opcodes the session layer must recognise to drive
/// the §5.2 state machine. All other opcode values are opaque application
/// messages forwarded downstream.
enum class ControlOpcode : std::uint16_t {
  HandshakeAuth = 0x0001,  // Handshaking -> Active on success
  Disconnect = 0x0002,     // Active -> Terminating
};

/// Opcodes below this value are reserved for gateway control frames.
inline constexpr std::uint16_t kFirstApplicationOpcode = 0x0100;

// ---------------------------------------------------------------------------
// Buffers & downstream message
// ---------------------------------------------------------------------------

/// Fixed-capacity buffer able to hold exactly one maximum-size wire frame.
using FrameBuffer = std::array<std::uint8_t, kMaxFrameSize>;

/// Fixed-capacity payload storage.
using PayloadBuffer = std::array<std::uint8_t, kMaxPayloadSize>;

/// Owning, validated frame enqueued into the SPSC ring buffer for downstream
/// dispatch (§4). Unlike core::FrameView, it copies the payload so it stays
/// valid after the receive buffer is reused. Only the first
/// `header.payload_len` bytes of `payload` are meaningful.
struct FramedMessage {
  core::SessionId session_id = core::kInvalidSessionId;
  core::FrameHeader header{};
  PayloadBuffer payload{};
};

static_assert(std::is_trivially_copyable_v<FramedMessage>,
              "FramedMessage must be trivially copyable for ring buffer slots");

}  // namespace gateway::protocol
