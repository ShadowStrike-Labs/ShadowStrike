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
 * ShadowStrike NGAV - UI/IPC WIRE MESSAGE DEFINITIONS
 * ============================================================================
 *
 * @file Messages.hpp
 * @brief Envelope struct, wire constants, and JSON helper templates for
 *        the client-side IPC layer.
 *
 * Wire format (all fields little-endian):
 *   Offset  0 — magic       (4 bytes): kIpcMagic = 0x53534156 ("SSAV")
 *   Offset  4 — version     (2 bytes): kProtocolVersion
 *   Offset  6 — reserved    (2 bytes): 0x0000
 *   Offset  8 — type        (4 bytes): CommandType cast to uint32
 *   Offset 12 — requestId   (8 bytes): caller correlation ID (0 = push event)
 *   Offset 20 — payloadSize (4 bytes): byte length of the JSON block
 *   Offset 24 — json        (payloadSize bytes): UTF-8 JSON payload
 *
 * This header is UI-tier only; it depends on nlohmann/json and
 * ServiceCommunicator (for CommandType). Do NOT include from service code.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#pragma once

// Standard library
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

// nlohmann/json — always available in this codebase.
#include <nlohmann/json.hpp>

// ShadowStrike — CommandType enum definition.
#include <PhantomCore/Service/ServiceCommunicator.hpp>

namespace ShadowStrike::PhantomHome::IPC {

// ============================================================================
// PROTOCOL CONSTANTS
// ============================================================================

/** Four-byte magic ("SSAV" in ASCII, stored little-endian). */
constexpr std::uint32_t kIpcMagic       = 0x53534156u;

/** Protocol version embedded in the wire header. */
constexpr std::uint32_t kProtocolVersion = 1u;

/** Maximum allowed JSON payload size per frame (1 MiB). */
constexpr std::uint32_t kMaxPayloadBytes = 1u << 20;  // 1 MiB

/** Maximum JSON nesting depth accepted by ValidateJson(). */
constexpr std::uint32_t kMaxJsonDepth   = 8u;

/**
 * @brief Maximum number of JSON nodes traversed by ValidateJson().
 *
 * Guards against O(N) denial-of-service on wide flat JSON arrays.
 */
constexpr std::uint32_t kMaxJsonNodes   = 4096u;

// ============================================================================
// ENVELOPE
// ============================================================================

/**
 * @struct Envelope
 * @brief In-memory representation of one IPC frame.
 *
 * Callers build an Envelope with a CommandType, optional requestId, and
 * a JSON payload, then call Serialize() to obtain the wire bytes.
 *
 * The service responds with a frame that has the same requestId; the client
 * uses requestId to correlate responses with pending SendAndExpect() calls.
 * Push events from the service always carry requestId == 0.
 */
struct Envelope {
    ShadowStrike::Service::CommandType type{ ShadowStrike::Service::CommandType::Unknown };
    std::uint64_t                      requestId{ 0 };
    nlohmann::json                     payload{ nlohmann::json::object() };

    /**
     * @brief Produce the canonical 24-byte-header wire representation.
     *
     * @return Serialised bytes, or empty() if JSON serialisation failed or
     *         the payload exceeds kMaxPayloadBytes.
     */
    [[nodiscard]] std::vector<std::uint8_t> Serialize() const;

    /**
     * @brief Deserialise a wire frame received from the pipe.
     *
     * Validates magic, version, reserved field, payload cap, JSON structure
     * (depth, node count, no binary blobs) and returns std::nullopt on any
     * validation failure — callers must treat std::nullopt as a protocol error.
     *
     * @param data  The full frame bytes (header + payload).
     * @return Populated Envelope on success, std::nullopt on any failure.
     */
    [[nodiscard]] static std::optional<Envelope>
    Deserialize(std::span<const std::uint8_t> data) noexcept;
};

// ============================================================================
// JSON HELPERS
// ============================================================================

/**
 * @brief Build a JSON error-response object.
 *
 * Returned object:
 * @code
 * {
 *   "ok": false,
 *   "error": {
 *     "code":    "<code>",
 *     "message": "<message>"
 *   }
 * }
 * @endcode
 */
[[nodiscard]] nlohmann::json
MakeErrorResponse(std::string_view code, std::string_view message);

/**
 * @brief Recursively validate a JSON value against depth and node limits.
 *
 * Rejects:
 *   - Binary blobs (nlohmann extension, not standard JSON).
 *   - Objects/arrays whose nesting exceeds @p maxDepth.
 *   - Trees with more than kMaxJsonNodes total nodes.
 *
 * @param j         JSON value to validate.
 * @param maxDepth  Maximum nesting depth allowed.
 * @return true if the value passes all checks.
 */
[[nodiscard]] bool ValidateJson(const nlohmann::json& j,
                                std::uint32_t         maxDepth) noexcept;

/**
 * @brief Safely extract a typed field from a JSON object.
 *
 * @tparam T     Target type; must be supported by nlohmann::get<T>().
 * @param  obj   JSON object to search.
 * @param  key   Field name.
 * @return The field value if it exists, is of type T, and conversion succeeds;
 *         std::nullopt otherwise (no exception thrown).
 *
 * Example:
 * @code
 *   auto name = GetField<std::string>(env.payload, "name");
 *   if (name) { use(*name); }
 * @endcode
 */
template<typename T>
[[nodiscard]] std::optional<T>
GetField(const nlohmann::json& obj, std::string_view key) noexcept
{
    try {
        const auto it = obj.find(key);
        if (it == obj.end()) return std::nullopt;
        return it->template get<T>();
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace ShadowStrike::PhantomHome::IPC
