#include "gateway/protocol/codec.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

// Zero-copy frame codec (architecture.md §5.1). No heap allocation and no
// exceptions: every path returns a ParseResult / StatusCode, and all scratch
// state is either on the stack or in the compile-time CRC table below.

namespace gateway::protocol {

namespace {

using ConstBytes = std::span<const std::uint8_t>;
using MutableBytes = std::span<std::uint8_t>;

// ---------------------------------------------------------------------------
// CRC16-CCITT (parameters from protocol::crc16), table-driven.
// The table is generated at compile time, so it costs no runtime init and
// lives in read-only memory.
// ---------------------------------------------------------------------------

static_assert(!crc16::kReflectInput && !crc16::kReflectOutput,
              "Table below implements the non-reflected (MSB-first) variant");

constexpr std::array<std::uint16_t, 256> make_crc_table() {
  std::array<std::uint16_t, 256> table{};
  for (std::size_t i = 0; i < table.size(); ++i) {
    auto crc = static_cast<std::uint16_t>(i << 8);
    for (int bit = 0; bit < 8; ++bit) {
      crc = static_cast<std::uint16_t>(
          (crc & 0x8000U) ? ((crc << 1) ^ crc16::kPolynomial) : (crc << 1));
    }
    table[i] = crc;
  }
  return table;
}

constexpr std::array<std::uint16_t, 256> kCrcTable = make_crc_table();

constexpr std::uint16_t crc16_ccitt(ConstBytes data) {
  std::uint16_t crc = crc16::kInitialValue;
  for (const std::uint8_t byte : data) {
    const auto index = static_cast<std::uint8_t>((crc >> 8) ^ byte);
    crc = static_cast<std::uint16_t>((crc << 8) ^ kCrcTable[index]);
  }
  return static_cast<std::uint16_t>(crc ^ crc16::kFinalXor);
}

// Compile-time proof the implementation matches the documented variant.
constexpr std::array<std::uint8_t, 9> kCheckInput{'1', '2', '3', '4', '5',
                                                  '6', '7', '8', '9'};
static_assert(crc16_ccitt(kCheckInput) == crc16::kCheckValue,
              "CRC16 implementation does not match crc16::kCheckValue");

// ---------------------------------------------------------------------------
// Big Endian field access. Callers guarantee bounds before calling.
// ---------------------------------------------------------------------------

std::uint16_t read_u16_be(ConstBytes bytes, std::size_t offset) {
  return static_cast<std::uint16_t>((bytes[offset] << 8) | bytes[offset + 1]);
}

std::uint32_t read_u32_be(ConstBytes bytes, std::size_t offset) {
  return (std::uint32_t{bytes[offset]} << 24) |
         (std::uint32_t{bytes[offset + 1]} << 16) |
         (std::uint32_t{bytes[offset + 2]} << 8) |
         std::uint32_t{bytes[offset + 3]};
}

void write_u16_be(MutableBytes bytes, std::size_t offset, std::uint16_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value >> 8);
  bytes[offset + 1] = static_cast<std::uint8_t>(value & 0xFFU);
}

void write_u32_be(MutableBytes bytes, std::size_t offset, std::uint32_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value >> 24);
  bytes[offset + 1] = static_cast<std::uint8_t>((value >> 16) & 0xFFU);
  bytes[offset + 2] = static_cast<std::uint8_t>((value >> 8) & 0xFFU);
  bytes[offset + 3] = static_cast<std::uint8_t>(value & 0xFFU);
}

/// Checks whatever magic bytes are present. A mismatch is reported as soon as
/// the first wrong byte arrives (§5.1: immediate resync/termination).
bool magic_prefix_valid(ConstBytes buffer) {
  if (!buffer.empty() && buffer[wire::kMagicOffset] != kMagicByte0) {
    return false;
  }
  if (buffer.size() > 1 && buffer[wire::kMagicOffset + 1] != kMagicByte1) {
    return false;
  }
  return true;
}

} // namespace

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

core::ParseResult PacketCodec::parse_frame(std::span<const std::uint8_t> &buffer,
                                           core::FrameView &out_frame) {
  // Validation order: magic -> header complete -> length -> frame complete ->
  // CRC. Cheap, early rejections never wait on bytes a hostile peer may never
  // send. On any non-FrameReady result, neither `buffer` nor `out_frame` is
  // modified.
  if (!magic_prefix_valid(buffer)) {
    return core::ParseResult::InvalidMagic;
  }
  if (buffer.size() < kFrameHeaderSize) {
    return core::ParseResult::NeedMoreData;
  }

  const std::uint16_t payload_len = read_u16_be(buffer, wire::kPayloadLenOffset);
  if (payload_len > kMaxPayloadSize) {
    return core:: ParseResult::PayloadTooLarge;
  }

  const std::size_t checksum_offset = kFrameHeaderSize + payload_len;
  const std::size_t frame_size = checksum_offset + kFrameChecksumSize;
  if (buffer.size() < frame_size) {
    return core::ParseResult::NeedMoreData;
  }

  const std::uint16_t received_crc = read_u16_be(buffer, checksum_offset);
  if (crc16_ccitt(buffer.first(checksum_offset)) != received_crc) {
    return core::ParseResult::ChecksumMismatch;
  }

  out_frame.header.magic = read_u16_be(buffer, wire::kMagicOffset);
  out_frame.header.payload_len = payload_len;
  out_frame.header.opcode = read_u16_be(buffer, wire::kOpcodeOffset);
  out_frame.header.sequence_id = read_u32_be(buffer, wire::kSequenceIdOffset);
  out_frame.payload = buffer.subspan(wire::kPayloadOffset, payload_len);
  out_frame.checksum = received_crc;

  buffer = buffer.subspan(frame_size);
  return core::ParseResult::FrameReady;
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

core::StatusCode PacketCodec::encode_frame(const core::FrameHeader &header,
                                           std::span<const std::uint8_t> payload,
                                           std::span<std::uint8_t> out_buffer,
                                           std::size_t &bytes_written) {
  bytes_written = 0;

  if (payload.size() > kMaxPayloadSize) {
    return core::StatusCode::PayloadTooLarge;
  }
  // The header must describe the payload actually supplied; refusing a
  // mismatch avoids emitting a frame whose length field lies.
  if (header.magic != kFrameMagic || header.payload_len != payload.size()) {
    return core::StatusCode::InvalidArgument;
  }

  const std::size_t checksum_offset = kFrameHeaderSize + payload.size();
  const std::size_t frame_size = checksum_offset + kFrameChecksumSize;
  if (out_buffer.size() < frame_size) {
    return core::StatusCode::BufferOverflow;
  }

  write_u16_be(out_buffer, wire::kMagicOffset, kFrameMagic);
  write_u16_be(out_buffer, wire::kPayloadLenOffset, header.payload_len);
  write_u16_be(out_buffer, wire::kOpcodeOffset, header.opcode);
  write_u32_be(out_buffer, wire::kSequenceIdOffset, header.sequence_id);
  std::copy(payload.begin(), payload.end(),
            out_buffer.begin() + static_cast<std::ptrdiff_t>(wire::kPayloadOffset));

  const std::uint16_t crc = crc16_ccitt(out_buffer.first(checksum_offset));
  write_u16_be(out_buffer, checksum_offset, crc);

  bytes_written = frame_size;
  return core::StatusCode::Ok;
}

} // namespace gateway::protocol
