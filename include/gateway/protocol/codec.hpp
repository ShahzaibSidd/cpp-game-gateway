#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "gateway/core/interfaces.hpp"
#include "gateway/core/types.hpp"
#include "gateway/protocol/frame.hpp"

namespace gateway::protocol {

/// Zero-copy frame packing and streaming parser (architecture.md §5.1).
/// Stateless: all stream state lives in the caller's buffer, so one instance
/// may be shared across sessions on the same thread.
class PacketCodec final : public core::IPacketCodec {
public:
  PacketCodec() = default;
  ~PacketCodec() override = default;

  /// FrameReady:    out_frame valid, `buffer` advanced past the frame.
  /// NeedMoreData:  `buffer` untouched; retry once more bytes arrive.
  /// InvalidMagic / PayloadTooLarge: reported as soon as the offending header
  ///                bytes are available, without waiting for the payload.
  /// ChecksumMismatch: CRC16 over header + payload does not match.
  core::ParseResult parse_frame(std::span<const std::uint8_t> &buffer,
                                core::FrameView &out_frame) override;

  /// Writes header (Big Endian) + payload + CRC16 into `out_buffer`.
  /// PayloadTooLarge if payload exceeds kMaxPayloadSize; BufferOverflow if
  /// `out_buffer` cannot hold the whole frame.
  core::StatusCode encode_frame(const core::FrameHeader &header,
                                std::span<const std::uint8_t> payload,
                                std::span<std::uint8_t> out_buffer,
                                std::size_t &bytes_written) override;
};

} // namespace gateway::protocol
