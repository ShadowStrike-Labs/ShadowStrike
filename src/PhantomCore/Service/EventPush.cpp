#include "pch.h"
/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - SERVICE-SIDE PUSH-EVENT BUILDER IMPLEMENTATION
 * ============================================================================
 *
 * @file EventPush.cpp
 * @brief Builds pre-serialised push-event envelopes for delivery via
 *        ServiceCommunicator::BroadcastEvent().
 *
 * Serialisation is performed inline here (no Qt, no UI-tier headers).
 * The wire format matches ShadowStrike::PhantomHome::IPC::Envelope::Serialize()
 * defined in Messages.hpp — any change to that format MUST be reflected here.
 *
 * Wire layout (little-endian):
 *   offset  0  [uint32] magic       = 0x53534156 ("SSAV")
 *   offset  4  [uint16] version     = 1
 *   offset  6  [uint16] reserved    = 0
 *   offset  8  [uint32] type        = CommandType raw uint32
 *   offset 12  [uint64] requestId   = 0  (push events are unsolicited)
 *   offset 20  [uint32] payloadSize = JSON byte count
 *   offset 24  [uint8…] JSON bytes
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * ============================================================================
 */

#include "EventPush.hpp"
#include "ServiceCommunicator.hpp"
#include <PhantomCore/Utils/Logger.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace ShadowStrike::Service::Events {

// ============================================================================
// MODULE-PRIVATE CONSTANTS (mirrors Messages.hpp — keep in sync)
// ============================================================================

namespace {

constexpr std::uint32_t kIpcMagic       = 0x53534156u; // "SSAV"
constexpr std::uint16_t kProtocolVersion = 1u;
constexpr std::uint32_t kMaxPayloadBytes = 1u << 20;    // 1 MiB
constexpr std::uint32_t kHeaderSize      = 24u;

constexpr const wchar_t* kLog = L"EventPush";

// LE helpers — avoids UB from reinterpret_cast on misaligned buffers.
inline void WriteU16LE(std::uint8_t* dst, std::uint16_t v) noexcept {
    dst[0] = static_cast<std::uint8_t>(v);
    dst[1] = static_cast<std::uint8_t>(v >> 8);
}
inline void WriteU32LE(std::uint8_t* dst, std::uint32_t v) noexcept {
    dst[0] = static_cast<std::uint8_t>(v);
    dst[1] = static_cast<std::uint8_t>(v >> 8);
    dst[2] = static_cast<std::uint8_t>(v >> 16);
    dst[3] = static_cast<std::uint8_t>(v >> 24);
}
inline void WriteU64LE(std::uint8_t* dst, std::uint64_t v) noexcept {
    dst[0] = static_cast<std::uint8_t>(v);
    dst[1] = static_cast<std::uint8_t>(v >>  8);
    dst[2] = static_cast<std::uint8_t>(v >> 16);
    dst[3] = static_cast<std::uint8_t>(v >> 24);
    dst[4] = static_cast<std::uint8_t>(v >> 32);
    dst[5] = static_cast<std::uint8_t>(v >> 40);
    dst[6] = static_cast<std::uint8_t>(v >> 48);
    dst[7] = static_cast<std::uint8_t>(v >> 56);
}

/**
 * @brief Serialise a CommandType + JSON body into the 24-byte-header wire format.
 *
 * Mirrors Envelope::Serialize() in Messages.hpp — any format change must be
 * reflected in both places.
 *
 * requestId is always 0 for push events (server-initiated, no correlation).
 */
[[nodiscard]] std::vector<std::uint8_t>
SerializeEnvelope(ShadowStrike::Service::CommandType type, const nlohmann::json& payload)
{
    std::string jsonStr;
    try {
        jsonStr = payload.dump();
    } catch (const std::exception& ex) {
        SS_LOG_ERROR(kLog, L"nlohmann::json::dump failed: %hs", ex.what());
        return {};
    }

    if (jsonStr.size() > kMaxPayloadBytes) {
        SS_LOG_ERROR(kLog,
            L"Push-event JSON payload exceeds kMaxPayloadBytes (%u bytes, limit %u).",
            static_cast<unsigned>(jsonStr.size()), kMaxPayloadBytes);
        return {};
    }

    const std::uint32_t payloadSize = static_cast<std::uint32_t>(jsonStr.size());
    const std::size_t   totalSize   = static_cast<std::size_t>(kHeaderSize) + payloadSize;

    std::vector<std::uint8_t> buf(totalSize, std::uint8_t{0});

    WriteU32LE(buf.data() +  0, kIpcMagic);
    WriteU16LE(buf.data() +  4, kProtocolVersion);
    WriteU16LE(buf.data() +  6, 0u);                           // reserved
    WriteU32LE(buf.data() +  8, static_cast<std::uint32_t>(type));
    WriteU64LE(buf.data() + 12, 0ull);                         // requestId = 0
    WriteU32LE(buf.data() + 20, payloadSize);

    if (payloadSize > 0) {
        std::memcpy(buf.data() + kHeaderSize, jsonStr.data(), payloadSize);
    }

    return buf;
}

} // anonymous namespace

// ============================================================================
// PUBLIC API
// ============================================================================

std::vector<std::uint8_t>
BuildProtectionStateChanged(std::string_view newState, std::string_view reason)
{
    if (newState.empty()) {
        SS_LOG_WARN(kLog, L"BuildProtectionStateChanged called with empty newState.");
    }

    nlohmann::json payload = {
        { "newState", std::string(newState) },
        { "reason",   std::string(reason)   }
    };

    return SerializeEnvelope(CommandType::ProtectionStateChanged, payload);
}

std::vector<std::uint8_t>
BuildHeadlineStateChanged(std::string_view state)
{
    if (state.empty()) {
        SS_LOG_WARN(kLog, L"BuildHeadlineStateChanged called with empty state.");
    }

    nlohmann::json payload = {
        { "state", std::string(state) }
    };

    return SerializeEnvelope(CommandType::HeadlineStateChanged, payload);
}

std::vector<std::uint8_t>
BuildScanProgressEvent(std::uint64_t scanId,
                       int           percent,
                       std::uint64_t itemsScanned,
                       std::uint64_t threatsFound)
{
    // Clamp percent to [0, 100].
    const int clampedPct = std::clamp(percent, 0, 100);
    if (clampedPct != percent) {
        SS_LOG_WARN(kLog, L"BuildScanProgressEvent: percent %d clamped to %d.",
                    percent, clampedPct);
    }

    // nlohmann stores integers as signed int64 by default; cast uint64 explicitly
    // so the JSON "scanId" field round-trips correctly on the UI side.
    nlohmann::json payload = {
        { "scanId",       static_cast<std::int64_t>(scanId)       },
        { "percent",      clampedPct                               },
        { "itemsScanned", static_cast<std::int64_t>(itemsScanned) },
        { "threatsFound", static_cast<std::int64_t>(threatsFound) }
    };

    return SerializeEnvelope(CommandType::ScanProgressEvent, payload);
}

} // namespace ShadowStrike::Service::Events
