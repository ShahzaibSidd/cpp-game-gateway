# Architecture Specification: Real-Time Game Gateway

## 1. System Overview & Scope
The Real-Time Game Gateway is a high-throughput, low-latency edge service acting as the primary termination and ingress point for game client network connections. It provides:
* Non-blocking client connection termination (TCP/UDP).
* Binary packet framing, decoding, and checksum verification.
* Ingress connection state tracking, handshake sequencing, and token-bucket rate limiting.
* Multiplexing valid framed messages into bounded ring buffers for downstream backend dispatch.

---

## 2. Core Architectural Principles
1. **Separation of Concerns:** The networking transport layer (`net`), packet framing engine (`protocol`), and connection tracking (`session`) must remain strictly isolated through abstract interfaces.
2. **Deterministic Memory Footprint:** Zero dynamic memory allocations (`malloc`, `new`, dynamic `std::vector` resizing, dynamic `std::string`) once connections enter the active frame loop. All buffers, slot arenas, and queues must be bounded and pre-allocated at startup.
3. **Explicit Threading & Zero Unsynchronized Shared State:** No ad-hoc mutexes or global shared state across threads. I/O workers and worker threads communicate strictly via Single-Producer Single-Consumer (SPSC) or Multi-Producer Single-Consumer (MPSC) bounded lock-free ring buffers.
4. **Interface-Driven Decoupling:** Concrete OS driver implementations (e.g., POSIX `epoll`) must strictly implement abstract C++20 interface contracts.
5. **No File Exceeding 250 Lines:** Hard limit for code generators and AI agents. Any module exceeding this threshold must be refactored into distinct cohesive components.

---    

## 3. Directory Layout & Boundaries

```
├── CMakeLists.txt
├── docs/
│   ├── architecture.md
│   └── interfaces.md
├── include/gateway/
│   ├── core/
│   │   ├── types.hpp              # Common status codes, handle types, aliases
│   │   ├── ring_buffer.hpp        # Fixed-capacity bounded lock-free ring buffer
│   │   └── interfaces.hpp         # Abstract base interfaces (INetworkDriver, etc.)
│   ├── net/
│   │   ├── socket.hpp             # Non-blocking POSIX socket wrapper (RAII)
│   │   └── epoll_event_loop.hpp   # epoll-based reactor event loop definition
│   ├── protocol/
│   │   ├── frame.hpp              # Binary frame layouts, magic bytes, constants
│   │   └── codec.hpp              # Zero-copy frame packing and streaming parser
│   └── session/
│       ├── session.hpp            # Session state machine, statistics, rate limiter
│       └── session_pool.hpp       # Contiguous flat arena for O(1) slot mapping
├── src/
│   ├── net/
│   │   ├── socket.cpp
│   │   └── epoll_event_loop.cpp
│   ├── protocol/
│   │   └── codec.cpp
│   ├── session/
│   │   ├── session.cpp
│   │   └── session_pool.cpp
│   └── main.cpp                   # Startup configuration, bootstrap, signal wiring
└── tests/
    ├── test_ring_buffer.cpp
    ├── test_protocol_codec.cpp
    ├── test_session_pool.cpp
    └── test_epoll_event_loop.cpp
```

---

## 4. End-to-End Ingress Data Flow

```
  [ Game Client ]
         │  (Raw byte stream over TCP / Datagrams over UDP)
         ▼
  [ INetworkDriver / EpollEventLoop ]
         │  Reads raw bytes into pre-allocated static chunk buffer
         ▼
  [ IPacketCodec ]
         │  Validates 2-byte Magic (0xAA55)
         │  Validates Payload Length <= 2048 bytes
         │  Verifies CRC16 checksum
         ▼
  [ ISessionManager / SessionPool ]
         │  Validates session state (Active vs Handshake)
         │  Enforces token-bucket rate limiter per Session ID
         ▼
  [ Bounded SPSC Ring Buffer ]
         │  Non-blocking enqueue of validated FramedMessage
         ▼
  [ Downstream Dispatcher / Backend Bus ]
```

---

## 5. Technical Specifications & Wire Protocol

### 5.1 Binary Wire Protocol Layout
All frames transmitted on the wire follow a fixed 12-byte framing overhead with a bounded payload:

| Field | Type | Size | Description |
|---|---|---|---|
| `magic` | `uint16_t` | 2 Bytes | Fixed synchronization marker: `0xAA55` (Big Endian) |
| `payload_len` | `uint16_t` | 2 Bytes | Length of payload in bytes (Max `2048`) |
| `opcode` | `uint16_t` | 2 Bytes | Application message identifier |
| `sequence_id` | `uint32_t` | 4 Bytes | Monotonically increasing packet sequence counter |
| `payload` | `uint8_t[]` | `payload_len` Bytes | Variable payload body (0 to 2048 bytes) |
| `checksum` | `uint16_t` | 2 Bytes | CRC16-CCITT computed over header fields + payload |

* **Total Max Frame Size:** 12 bytes header + 2048 bytes payload = 2060 bytes.
* Frames failing magic byte alignment or exceeding max payload length must trigger immediate stream resynchronization or connection termination.

### 5.2 Session State Machine
Each client session moves strictly through the following finite state transitions:

```
[ Disconnected ] 
       │ (Socket Accepted)
       ▼
 [ Handshaking ] ──(Handshake Timeout / Invalid Auth)──► [ Terminating ]
       │                                                        ▲
       │ (Successful Auth Frame)                                │
       ▼                                                        │
   [ Active ] ────(Rate Limit Violation / Disconnect Frame)─────┘
```

* **Storage:** Stored in a flat, contiguous pre-allocated array (`SessionPool`) indexed by `uint32_t session_id` to guarantee cache locality and $O(1)$ lookups with zero pointer chasing.

### 5.3 Core Interface Contracts (`include/gateway/core/interfaces.hpp`)

```cpp
#pragma once
#include <cstdint>
#include <span>
#include "gateway/core/types.hpp"

namespace gateway::core {

class INetworkEventHandler {
public:
    virtual ~INetworkEventHandler() = default;
    virtual void on_client_connected(SessionId session_id) = 0;
    virtual void on_data_received(SessionId session_id, std::span<const uint8_t> data) = 0;
    virtual void on_client_disconnected(SessionId session_id, DisconnectReason reason) = 0;
};

class INetworkDriver {
public:
    virtual ~INetworkDriver() = default;
    virtual StatusCode init(const NetworkConfig& config) = 0;
    virtual StatusCode start() = 0;
    virtual void poll(int timeout_ms) = 0;
    virtual StatusCode send(SessionId session_id, std::span<const uint8_t> data) = 0;
    virtual void disconnect(SessionId session_id, DisconnectReason reason) = 0;
    virtual void stop() = 0;
};

class IPacketCodec {
public:
    virtual ~IPacketCodec() = default;
    virtual ParseResult parse_frame(std::span<const uint8_t>& buffer, FrameView& out_frame) = 0;
    virtual StatusCode encode_frame(const FrameHeader& header, std::span<const uint8_t> payload, std::span<uint8_t> out_buffer, size_t& bytes_written) = 0;
};

} // namespace gateway::core
```

---

## 6. Implementation Guardrails for AI Generation (`kiro-cli`)
* **Standard:** ISO C++20 (`-std=c++20`).
* **Compiler Flags:** Compiles cleanly with `-Wall -Wextra -Wpedantic -Wconversion -Werror` on GCC 13+ and Clang 17+.
* **Memory & Allocation Rules:**
  * No heap allocations (`new`, `malloc`, `std::vector::push_back` beyond pre-reserved capacity) inside packet processing loops or connection handlers.
  * Pass buffer slices and payload references using `std::span<const uint8_t>` or `std::string_view` rather than allocating copies.
* **Error Handling Strategy:**
  * No C++ exceptions in network parsing or event loop hot paths.
  * Return explicit status codes (`StatusCode::Ok`, `StatusCode::BufferOverflow`, `StatusCode::ChecksumMismatch`) or `std::optional`/`std::expected` idioms.
* **Concurrency Rules:**
  * No blocking I/O calls (`read`, `write`, `accept`) on worker or reactor threads. All descriptors must have `O_NONBLOCK` configured.
  * Inter-thread message passing must use lock-free ring buffers (`gateway::core::RingBuffer<T, Capacity>`).
