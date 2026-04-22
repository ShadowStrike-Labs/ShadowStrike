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
 * ShadowStrike NGAV - UI/IPC WIRE MESSAGE IMPLEMENTATION
 * ============================================================================
 *
 * @file Messages.cpp
 * @brief Serialise / Deserialise Envelope frames and JSON validation helpers.
 *
 * Wire format (all fields little-endian):
 *   Offset  0 — magic       (4 bytes): 0x53534156 ("SSAV")
 *   Offset  4 — version     (2 bytes): kProtocolVersion
 *   Offset  6 — reserved    (2 bytes): 0x0000
 *   Offset  8 — type        (4 bytes): CommandType cast to uint32
 *   Offset 12 — requestId   (8 bytes): caller correlation ID
 *   Offset 20 — payloadSize (4 bytes): byte length of the JSON block
 *   Offset 24 — json        (payloadSize bytes): UTF-8 JSON
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

// This translation unit belongs to ShadowStrikePhantomUI which does NOT use a
// precompiled header — do not add #include "pch.h" here.

#include "Messages.hpp"

#include <cstring>
#include <stdexcept>

namespace ShadowStrike::PhantomHome::IPC {

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

namespace {

constexpr std::size_t kWireHeaderSize = 24; // bytes — see file header

/// Write an integer (or enum) value T in little-endian byte order into buf.
template<typename T>
static void WriteLe(std::vector<std::uint8_t>& buf, T val) noexcept
{
    // Use if constexpr to avoid instantiating std::underlying_type_t<T> when T
    // is not an enum — both branches of std::conditional_t are always evaluated
    // by the compiler even when only one is selected.
    if constexpr (std::is_enum_v<T>) {
        using U = std::make_unsigned_t<std::underlying_type_t<T>>;
        U uval = static_cast<U>(val);
        for (std::size_t i = 0; i < sizeof(U); ++i) {
            buf.push_back(static_cast<std::uint8_t>(uval & 0xFFu));
            uval >>= 8;
        }
    } else {
        static_assert(std::is_integral_v<T>, "WriteLe requires an integral or enum type");
        using U = std::make_unsigned_t<T>;
        U uval = static_cast<U>(val);
        for (std::size_t i = 0; i < sizeof(U); ++i) {
            buf.push_back(static_cast<std::uint8_t>(uval & 0xFFu));
            uval >>= 8;
        }
    }
}

/// Read sizeof(T) bytes from src in little-endian order and return as T.
template<typename T>
static T ReadLe(const std::uint8_t* src) noexcept
{
    static_assert(std::is_integral_v<T>);
    using U = std::make_unsigned_t<T>;
    U val = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        val |= static_cast<U>(src[i]) << (i * 8u);
    }
    return static_cast<T>(val);
}

} // anonymous namespace

// ============================================================================
// Envelope::Serialize
// ============================================================================

std::vector<std::uint8_t> Envelope::Serialize() const
{
    // Dump the JSON payload to a compact UTF-8 string.
    // json::dump(-1) produces compact output without indentation.
    // We call it in a try-catch because an ill-formed json value (e.g. NaN
    // doubles) can produce an exception from nlohmann in some configurations.
    std::string jsonStr;
    try {
        jsonStr = payload.dump(-1, ' ', false,
                               nlohmann::detail::error_handler_t::replace);
    } catch (...) {
        return {}; // Caller must handle an empty result as a serialisation error.
    }

    if (jsonStr.size() > kMaxPayloadBytes) {
        return {}; // Refuse to produce frames exceeding the agreed-upon cap.
    }

    const auto payloadBytes = static_cast<std::uint32_t>(jsonStr.size());

    std::vector<std::uint8_t> buf;
    buf.reserve(kWireHeaderSize + payloadBytes);

    // Header
    WriteLe(buf, kIpcMagic);                                  //  4 — magic
    WriteLe(buf, static_cast<std::uint16_t>(kProtocolVersion)); //  2 — version
    WriteLe(buf, static_cast<std::uint16_t>(0u));             //  2 — reserved
    WriteLe(buf, static_cast<std::uint32_t>(type));           //  4 — command type
    WriteLe(buf, requestId);                                   //  8 — requestId
    WriteLe(buf, payloadBytes);                               //  4 — payloadSize

    // Payload
    buf.insert(buf.end(), jsonStr.cbegin(), jsonStr.cend());

    return buf;
}

// ============================================================================
// Envelope::Deserialize
// ============================================================================

std::optional<Envelope>
Envelope::Deserialize(std::span<const std::uint8_t> data) noexcept
{
    // Minimum frame: header only with zero-length payload.
    if (data.size() < kWireHeaderSize) {
        return std::nullopt;
    }

    const std::uint8_t* hdr = data.data();

    // --- Field extraction ---
    const auto magic       = ReadLe<std::uint32_t>(hdr +  0);
    const auto version     = ReadLe<std::uint16_t>(hdr +  4);
    // reserved 2 bytes at offset 6 — accepted regardless of value for
    // forward-compatibility, but we verify it is zero for protocol v1.
    const auto reserved    = ReadLe<std::uint16_t>(hdr +  6);
    const auto typeRaw     = ReadLe<std::uint32_t>(hdr +  8);
    const auto requestId   = ReadLe<std::uint64_t>(hdr + 12);
    const auto payloadSize = ReadLe<std::uint32_t>(hdr + 20);

    // --- Validation ---
    if (magic != kIpcMagic) {
        return std::nullopt;
    }
    if (version != static_cast<std::uint16_t>(kProtocolVersion)) {
        return std::nullopt;
    }
    if (reserved != 0u) {
        // Reserved field must be zero to prevent covert channels.
        return std::nullopt;
    }
    if (payloadSize > kMaxPayloadBytes) {
        return std::nullopt;
    }
    if (data.size() < kWireHeaderSize + static_cast<std::size_t>(payloadSize)) {
        return std::nullopt; // Buffer is shorter than the declared payload.
    }

    // --- Parse JSON with exceptions disabled ---
    const auto jsonSpan = data.subspan(kWireHeaderSize,
                                       static_cast<std::size_t>(payloadSize));

    nlohmann::json parsed = nlohmann::json::parse(
        jsonSpan.begin(),
        jsonSpan.end(),
        /*cb=*/nullptr,
        /*allow_exceptions=*/false
    );

    if (parsed.is_discarded()) {
        return std::nullopt; // Malformed JSON — reject the frame.
    }

    // --- Depth and type validation ---
    if (!ValidateJson(parsed, kMaxJsonDepth)) {
        return std::nullopt;
    }

    Envelope env;
    env.type      = static_cast<ShadowStrike::Service::CommandType>(typeRaw);
    env.requestId = requestId;
    env.payload   = std::move(parsed);
    return env;
}

// ============================================================================
// MakeErrorResponse
// ============================================================================

nlohmann::json
MakeErrorResponse(std::string_view code, std::string_view message)
{
    return nlohmann::json{
        {"ok",    false},
        {"error", {
            {"code",    std::string(code)},
            {"message", std::string(message)}
        }}
    };
}

// ============================================================================
// ValidateJson
// ============================================================================

bool ValidateJson(const nlohmann::json& j, std::uint32_t maxDepth) noexcept
{
    // Depth limit: if we've exhausted the budget and the value is a container,
    // reject it; primitives at depth == 0 are fine.
    if (j.is_binary()) {
        // Binary blobs are a nlohmann extension not part of the JSON standard.
        // Reject them unconditionally to prevent binary-injection attacks.
        return false;
    }

    if (j.is_object()) {
        if (maxDepth == 0) return false; // Container at limit — too deep.
        for (const auto& [/*key*/_, val] : j.items()) {
            if (!ValidateJson(val, maxDepth - 1u)) return false;
        }
    } else if (j.is_array()) {
        if (maxDepth == 0) return false;
        for (const auto& elem : j) {
            if (!ValidateJson(elem, maxDepth - 1u)) return false;
        }
    }
    // Primitives (null, boolean, number, string) consume no additional depth.

    return true;
}

} // namespace ShadowStrike::PhantomHome::IPC
