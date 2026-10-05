// Tests for the IPacketCodec contract (core/interfaces.hpp) against the wire
// format in protocol/frame.hpp. Input frames come from an independent
// reference encoder below, never from the codec under test.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "gateway/core/interfaces.hpp"
#include "gateway/protocol/codec.hpp"
#include "gateway/protocol/frame.hpp"

namespace core = gateway::core;
namespace proto = gateway::protocol;
using core::ParseResult;

using CodecUnderTest = proto::PacketCodec;
using Bytes = std::vector<std::uint8_t>;
using ConstSpan = std::span<const std::uint8_t>;

// ===========================================================================
// Minimal test harness (exit code 0 only if every test passes, for CTest)
// ===========================================================================

namespace harness {

using TestFn = void (*)();
struct TestCase {
  const char *name = nullptr;
  TestFn fn = nullptr;
};

inline constexpr std::size_t kMaxTests = 128;
std::array<TestCase, kMaxTests> g_tests{};
std::size_t g_test_count = 0;
bool g_current_failed = false;

struct Registrar {
  Registrar(const char *name, TestFn fn) {
    if (g_test_count < kMaxTests) {
      g_tests[g_test_count] = TestCase{name, fn};
    }
    ++g_test_count; // over-count is detected in run_all()
  }
};

void report_failure(const char *file, int line, const char *expr) {
  g_current_failed = true;
  std::fprintf(stderr, "    %s:%d: check failed: %s\n", file, line, expr);
}

int run_all() {
  if (g_test_count > kMaxTests) {
    std::fprintf(stderr, "error: more than %zu tests registered\n", kMaxTests);
    return 1;
  }
  std::size_t failed = 0;
  for (std::size_t i = 0; i < g_test_count; ++i) {
    g_current_failed = false;
    g_tests[i].fn();
    std::printf("[%s] %s\n", g_current_failed ? "FAIL" : " OK ", g_tests[i].name);
    failed += g_current_failed ? 1U : 0U;
  }
  std::printf("\n%zu/%zu tests passed\n", g_test_count - failed, g_test_count);
  return failed == 0 ? 0 : 1;
}

} // namespace harness

#define TEST_CASE(name)                                                        \
  static void name();                                                          \
  [[maybe_unused]] static const harness::Registrar name##_reg{#name, &name};   \
  static void name()

// Records a failure and continues the current test.
#define CHECK(cond)                                                            \
  do {                                                                         \
    if (!(cond)) harness::report_failure(__FILE__, __LINE__, #cond);           \
  } while (false)

// Records a failure and aborts the current test.
#define REQUIRE(cond)                                                          \
  do {                                                                         \
    if (!(cond)) {                                                             \
      harness::report_failure(__FILE__, __LINE__, #cond);                      \
      return;                                                                  \
    }                                                                          \
  } while (false)

// ===========================================================================
// Reference encoder (Big Endian, CRC16-CCITT-FALSE per protocol::crc16)
// ===========================================================================

namespace {

void put_u16(Bytes &out, std::uint16_t v) {
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v & 0xFFU));
}

void put_u32(Bytes &out, std::uint32_t v) {
  for (int shift = 24; shift >= 0; shift -= 8) {
    out.push_back(static_cast<std::uint8_t>(v >> shift));
  }
}

std::uint16_t crc16_ref(ConstSpan data) {
  std::uint16_t crc = proto::crc16::kInitialValue;
  for (std::uint8_t byte : data) {
    crc = static_cast<std::uint16_t>(crc ^ (byte << 8));
    for (int bit = 0; bit < 8; ++bit) {
      crc = static_cast<std::uint16_t>(
          (crc & 0x8000U) ? ((crc << 1) ^ proto::crc16::kPolynomial)
                          : (crc << 1));
    }
  }
  return static_cast<std::uint16_t>(crc ^ proto::crc16::kFinalXor);
}

struct FrameSpec {
  std::uint16_t magic = core::kFrameMagic;
  std::uint16_t opcode = proto::kFirstApplicationOpcode;
  std::uint32_t sequence_id = 1;
  Bytes payload{};
  std::optional<std::uint16_t> payload_len_override{}; // forge bad headers
};

// The checksum is always computed over the bytes actually emitted, so a frame
// with corrupted magic still carries a *valid* CRC: only a magic check can
// reject it.
Bytes build_frame(const FrameSpec &s) {
  Bytes out;
  put_u16(out, s.magic);
  put_u16(out, s.payload_len_override.value_or(
                   static_cast<std::uint16_t>(s.payload.size())));
  put_u16(out, s.opcode);
  put_u32(out, s.sequence_id);
  out.insert(out.end(), s.payload.begin(), s.payload.end());
  put_u16(out, crc16_ref(out));
  return out;
}

Bytes make_payload(std::size_t n) {
  Bytes p(n);
  for (std::size_t i = 0; i < n; ++i) {
    p[i] = static_cast<std::uint8_t>(i * 31U + 7U);
  }
  return p;
}

std::uint16_t trailing_checksum(const Bytes &frame) {
  const std::size_t n = frame.size();
  return static_cast<std::uint16_t>((frame[n - 2] << 8) | frame[n - 1]);
}

// One shared instance: parse_frame() takes all state via its arguments, so
// reusing the codec across tests also checks that it holds no hidden state.
CodecUnderTest g_codec;
core::IPacketCodec &codec() { return g_codec; }

// Expects `bytes` to be rejected with `expected`, never reported as a frame,
// and the buffer never advanced past its end.
void expect_rejected(const Bytes &bytes, ParseResult expected) {
  ConstSpan buf(bytes);
  core::FrameView frame{};
  CHECK(codec().parse_frame(buf, frame) == expected);
  CHECK(buf.size() <= bytes.size());
}

} // namespace

// --- Reference sanity -------------------------------------------------------

TEST_CASE(reference_crc_matches_published_check_value) {
  constexpr std::string_view kInput = "123456789";
  const Bytes data(kInput.begin(), kInput.end());
  CHECK(crc16_ref(data) == proto::crc16::kCheckValue);
}

// --- 1) Perfect valid frames ------------------------------------------------

TEST_CASE(valid_frame_decodes_every_header_field) {
  // Distinct byte values in each field catch byte-order bugs.
  const Bytes bytes = build_frame(
      {.opcode = 0x0A0B, .sequence_id = 0x01020304, .payload = make_payload(64)});
  ConstSpan buf(bytes);
  core::FrameView frame{};
  REQUIRE(codec().parse_frame(buf, frame) == ParseResult::FrameReady);
  CHECK(frame.header.magic == core::kFrameMagic);
  CHECK(frame.header.payload_len == 64);
  CHECK(frame.header.opcode == 0x0A0B);
  CHECK(frame.header.sequence_id == 0x01020304U);
  CHECK(frame.checksum == trailing_checksum(bytes));
  CHECK(buf.empty()); // whole frame consumed
}

TEST_CASE(valid_frame_payload_is_zero_copy_view_into_input) {
  const Bytes payload = make_payload(100);
  const Bytes bytes = build_frame({.payload = payload});
  ConstSpan buf(bytes);
  core::FrameView frame{};
  REQUIRE(codec().parse_frame(buf, frame) == ParseResult::FrameReady);
  REQUIRE(frame.payload.size() == payload.size());
  CHECK(frame.payload.data() == bytes.data() + proto::wire::kPayloadOffset);
  CHECK(std::equal(payload.begin(), payload.end(), frame.payload.begin()));
}

TEST_CASE(valid_frame_with_empty_payload) {
  const Bytes bytes = build_frame({});
  REQUIRE(bytes.size() == proto::kMinFrameSize);
  ConstSpan buf(bytes);
  core::FrameView frame{};
  REQUIRE(codec().parse_frame(buf, frame) == ParseResult::FrameReady);
  CHECK(frame.header.payload_len == 0);
  CHECK(frame.payload.empty());
  CHECK(buf.empty());
}

TEST_CASE(valid_frame_with_max_payload) {
  const Bytes bytes = build_frame({.payload = make_payload(proto::kMaxPayloadSize)});
  REQUIRE(bytes.size() == proto::kMaxFrameSize);
  ConstSpan buf(bytes);
  core::FrameView frame{};
  REQUIRE(codec().parse_frame(buf, frame) == ParseResult::FrameReady);
  CHECK(frame.payload.size() == proto::kMaxPayloadSize);
  CHECK(buf.empty());
}

TEST_CASE(back_to_back_frames_in_one_read_parse_sequentially) {
  Bytes bytes = build_frame({.sequence_id = 7, .payload = make_payload(5)});
  const Bytes second = build_frame({.sequence_id = 8, .payload = make_payload(9)});
  bytes.insert(bytes.end(), second.begin(), second.end());
  ConstSpan buf(bytes);
  core::FrameView frame{};
  REQUIRE(codec().parse_frame(buf, frame) == ParseResult::FrameReady);
  CHECK(frame.header.sequence_id == 7);
  CHECK(buf.size() == second.size());
  REQUIRE(codec().parse_frame(buf, frame) == ParseResult::FrameReady);
  CHECK(frame.header.sequence_id == 8);
  CHECK(frame.payload.size() == 9);
  CHECK(buf.empty());
}

// --- 2) Fragmented TCP stream -----------------------------------------------

TEST_CASE(empty_buffer_needs_more_data) {
  ConstSpan buf{};
  core::FrameView frame{};
  CHECK(codec().parse_frame(buf, frame) == ParseResult::NeedMoreData);
  CHECK(buf.empty());
}

TEST_CASE(half_a_frame_needs_more_data_and_leaves_buffer_untouched) {
  const Bytes bytes = build_frame({.payload = make_payload(200)});
  ConstSpan buf(bytes.data(), bytes.size() / 2);
  const ConstSpan before = buf;
  core::FrameView frame{};
  CHECK(codec().parse_frame(buf, frame) == ParseResult::NeedMoreData);
  CHECK(buf.data() == before.data());
  CHECK(buf.size() == before.size());
}

TEST_CASE(partial_header_needs_more_data) {
  const Bytes bytes = build_frame({.payload = make_payload(16)});
  for (std::size_t len = 1; len < proto::kFrameHeaderSize; ++len) {
    ConstSpan buf(bytes.data(), len);
    core::FrameView frame{};
    CHECK(codec().parse_frame(buf, frame) == ParseResult::NeedMoreData);
    CHECK(buf.size() == len);
  }
}

TEST_CASE(missing_final_checksum_byte_needs_more_data) {
  const Bytes bytes = build_frame({.payload = make_payload(32)});
  ConstSpan buf(bytes.data(), bytes.size() - 1);
  core::FrameView frame{};
  CHECK(codec().parse_frame(buf, frame) == ParseResult::NeedMoreData);
  CHECK(buf.size() == bytes.size() - 1);
}

TEST_CASE(frame_split_at_every_byte_boundary_completes_once_reassembled) {
  // Simulates a TCP read ending at each possible offset: the first chunk must
  // wait, and the caller's reassembled buffer must then parse fully.
  const Bytes bytes = build_frame({.sequence_id = 42, .payload = make_payload(24)});
  for (std::size_t split = 0; split < bytes.size(); ++split) {
    ConstSpan first(bytes.data(), split);
    core::FrameView frame{};
    CHECK(codec().parse_frame(first, frame) == ParseResult::NeedMoreData);
    CHECK(first.size() == split);

    ConstSpan reassembled(bytes);
    REQUIRE(codec().parse_frame(reassembled, frame) == ParseResult::FrameReady);
    CHECK(frame.header.sequence_id == 42);
    CHECK(reassembled.empty());
  }
}

// --- 3) Corrupted magic bytes -----------------------------------------------

TEST_CASE(corrupted_first_magic_byte_is_invalid_magic) {
  expect_rejected(build_frame({.magic = 0x0055, .payload = make_payload(8)}),
                  ParseResult::InvalidMagic);
}

TEST_CASE(corrupted_second_magic_byte_is_invalid_magic) {
  expect_rejected(build_frame({.magic = 0xAA00, .payload = make_payload(8)}),
                  ParseResult::InvalidMagic);
}

TEST_CASE(byte_swapped_magic_is_invalid_magic) {
  // 0x55 0xAA on the wire: what a little-endian decoding bug would accept.
  expect_rejected(build_frame({.magic = 0x55AA, .payload = make_payload(8)}),
                  ParseResult::InvalidMagic);
}

TEST_CASE(bad_magic_is_rejected_before_the_rest_of_the_frame_arrives) {
  // §5.1 demands immediate resync/termination, so the codec must not wait
  // for the payload of a frame whose magic is already known to be wrong.
  const Bytes full = build_frame({.magic = 0xDEAD, .payload = make_payload(500)});
  const auto header_end = full.begin() + static_cast<std::ptrdiff_t>(proto::kFrameHeaderSize);
  expect_rejected(Bytes(full.begin(), header_end), ParseResult::InvalidMagic);
}

// --- Other validation -------------------------------------------------------

TEST_CASE(oversized_payload_len_is_rejected_from_header_alone) {
  // Must not wait for 2049+ bytes that a malicious client may never send.
  constexpr auto kTooLarge = static_cast<std::uint16_t>(proto::kMaxPayloadSize + 1);
  expect_rejected(build_frame({.payload_len_override = kTooLarge}),
                  ParseResult::PayloadTooLarge);
}

TEST_CASE(flipped_payload_bit_is_checksum_mismatch) {
  Bytes bytes = build_frame({.payload = make_payload(32)});
  bytes[proto::wire::kPayloadOffset + 5] ^= 0x01U;
  expect_rejected(bytes, ParseResult::ChecksumMismatch);
}

TEST_CASE(flipped_header_bit_is_checksum_mismatch) {
  Bytes bytes = build_frame({.payload = make_payload(32)});
  bytes[proto::wire::kSequenceIdOffset] ^= 0x80U; // CRC must cover the header
  expect_rejected(bytes, ParseResult::ChecksumMismatch);
}

// --- Encoding ---------------------------------------------------------------

TEST_CASE(encode_produces_reference_wire_bytes) {
  const Bytes payload = make_payload(48);
  const Bytes expected = build_frame(
      {.opcode = 0x0A0B, .sequence_id = 0x01020304, .payload = payload});
  const core::FrameHeader header{.magic = core::kFrameMagic, .payload_len = 48,
                                 .opcode = 0x0A0B, .sequence_id = 0x01020304};
  proto::FrameBuffer out{};
  std::size_t written = 0;
  REQUIRE(codec().encode_frame(header, payload, out, written) == core::StatusCode::Ok);
  REQUIRE(written == expected.size());
  CHECK(std::equal(expected.begin(), expected.end(), out.begin()));
}

TEST_CASE(encode_reports_buffer_overflow_when_output_too_small) {
  const Bytes payload = make_payload(48);
  const core::FrameHeader header{.payload_len = 48};
  Bytes out(proto::kFrameOverhead + payload.size() - 1);
  std::size_t written = 0;
  CHECK(codec().encode_frame(header, payload, out, written) ==
        core::StatusCode::BufferOverflow);
}

TEST_CASE(encode_rejects_oversized_payload) {
  const Bytes payload = make_payload(proto::kMaxPayloadSize + 1);
  const core::FrameHeader header{
      .payload_len = static_cast<std::uint16_t>(payload.size())};
  Bytes out(proto::kFrameOverhead + payload.size());
  std::size_t written = 0;
  CHECK(codec().encode_frame(header, payload, out, written) ==
        core::StatusCode::PayloadTooLarge);
}

int main() { return harness::run_all(); }
