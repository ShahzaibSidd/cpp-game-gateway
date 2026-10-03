#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "gateway/core/types.hpp"

namespace gateway::core {

/// Callback sink for transport-level events, invoked from the reactor thread.
class INetworkEventHandler {
public:
  virtual ~INetworkEventHandler() = default;
  virtual void on_client_connected(SessionId session_id) = 0;
  virtual void on_data_received(SessionId session_id,
                                std::span<const std::uint8_t> data) = 0;
  virtual void on_client_disconnected(SessionId session_id,
                                      DisconnectReason reason) = 0;
};

/// Abstract non-blocking transport (e.g. EpollEventLoop).
class INetworkDriver {
public:
  virtual ~INetworkDriver() = default;
  virtual StatusCode init(const NetworkConfig &config) = 0;
  virtual StatusCode start() = 0;
  virtual void poll(int timeout_ms) = 0;
  virtual StatusCode send(SessionId session_id,
                          std::span<const std::uint8_t> data) = 0;
  virtual void disconnect(SessionId session_id, DisconnectReason reason) = 0;
  virtual void stop() = 0;
};

/// Zero-copy binary frame parser / encoder.
class IPacketCodec {
public:
  virtual ~IPacketCodec() = default;

  /// On FrameReady, `buffer` is advanced past the consumed frame.
  virtual ParseResult parse_frame(std::span<const std::uint8_t> &buffer,
                                  FrameView &out_frame) = 0;

  virtual StatusCode encode_frame(const FrameHeader &header,
                                  std::span<const std::uint8_t> payload,
                                  std::span<std::uint8_t> out_buffer,
                                  std::size_t &bytes_written) = 0;
};

} // namespace gateway::core
