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
 * ShadowStrike NGAV - UI/IPC WIRE MESSAGE TYPES
 * ============================================================================
 *
 * @file Messages.hpp
 * @brief Shared wire types and JSON helpers for the PhantomHome IPC protocol.
 *
 * Wire format (little-endian):
 *   [magic:       4 bytes]  0x53534156 ("SSAV")
 *   [version:     2 bytes]  kProtocolVersion
 *   [reserved:    2 bytes]  must be zero
 *   [type:        4 bytes]  CommandType (uint32)
 *   [requestId:   8 bytes]  caller-assigned request correlation ID
 *   [payloadSize: 4 bytes]  JSON byte count (must not exceed kMaxPayloadBytes)
 *   [json:   payloadSize]   UTF-8 JSON payload
 *
 * Total header size: 24 bytes.
 *
 * Security invariants:
 *   - payloadSize capped at kMaxPayloadBytes (1 MiB)
 *   - JSON depth limited to kMaxJsonDepth (8)
 *   - Binary blobs rejected on Deserialize
 *   - Discarded (malformed) JSON rejected
 *   - Protocol magic and version checked before any further parsing
 *
 * @note Duplicate-key detection at root is not achievable post-parse with
 *       nlohmann::json (last value wins silently). Callers requiring strict
 *       duplicate rejection must use a custom SAX handler at parse time.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include <nlohmann/json.hpp>

// ServiceCommunicator.hpp provides CommandType. Include via the solution-root
// "src" directory which is on the include path for both PhantomCoreLib and
// ShadowStrikePhantomUI projects.
#include <PhantomCore/Service/ServiceCommunicator.hpp>

namespace ShadowStrike::PhantomHome::IPC {

// ============================================================================
// PROTOCOL CONSTANTS
// ============================================================================

/// Wire magic: "SSAV" — must match CommunicationConstants::PROTOCOL_MAGIC.
inline constexpr std::uint32_t kIpcMagic        = 0x53534156u;

/// Maximum allowed payload (JSON) size in bytes — enforced on both serialize
/// and deserialize paths to prevent denial-of-service via oversized frames.
inline constexpr std::uint32_t kMaxPayloadBytes  = 1u << 20;   // 1 MiB

/// Maximum permitted JSON nesting depth. Checked recursively after parse.
inline constexpr std::uint32_t kMaxJsonDepth     = 8u;

/// Maximum total number of JSON nodes (values) allowed across the entire tree.
/// Prevents algorithmic complexity DoS: an attacker cannot send a shallow (≤8
/// levels) but enormously wide JSON array/object that triggers O(N) traversal.
/// 4096 nodes comfortably covers all legitimate UI payloads.
inline constexpr std::uint32_t kMaxJsonNodes     = 4096u;

/// Bump this when the wire format changes in a backward-incompatible way.
inline constexpr std::uint32_t kProtocolVersion  = 1u;

// ============================================================================
// ENVELOPE
// ============================================================================

/**
 * @brief A single framed IPC message with a strongly-typed command, a
 *        caller-assigned correlation ID, and a structured JSON payload.
 *
 * Thread Safety: Envelope instances are NOT thread-safe; callers are
 *                responsible for external synchronisation.
 */
struct Envelope {
    ShadowStrike::Service::CommandType type      = ShadowStrike::Service::CommandType::Unknown;
    std::uint64_t                      requestId = 0;
    nlohmann::json                     payload;

    /**
     * @brief Serialise this envelope to a wire-format byte buffer.
     *
     * @return Populated buffer on success. Returns an EMPTY vector if the
     *         serialised JSON payload exceeds kMaxPayloadBytes or if JSON
     *         dump raises an exception (treated as empty).
     */
    [[nodiscard]] std::vector<std::uint8_t> Serialize() const;

    /**
     * @brief Deserialise a wire-format buffer into an Envelope.
     *
     * Validates:
     *   - Minimum header length (24 bytes)
     *   - Magic and version fields
     *   - payloadSize does not exceed kMaxPayloadBytes
     *   - Total buffer length is consistent with payloadSize
     *   - JSON is well-formed (not discarded)
     *   - JSON passes ValidateJson (depth cap, binary rejection)
     *
     * @param data  Raw wire bytes (caller retains ownership).
     * @return Populated Envelope on success, std::nullopt on any failure.
     *         No exceptions are propagated.
     */
    [[nodiscard]] static std::optional<Envelope>
    Deserialize(std::span<const std::uint8_t> data) noexcept;
};

// ============================================================================
// HELPERS
// ============================================================================

/**
 * @brief Build a canonical error-response JSON object.
 *
 * Produces:
 *   { "ok": false, "error": { "code": "<code>", "message": "<message>" } }
 *
 * @param code    Machine-readable error token (e.g. "AUTH_FAILED").
 * @param message Human-readable description (not exposed to end-users).
 */
[[nodiscard]] nlohmann::json
MakeErrorResponse(std::string_view code, std::string_view message);

/**
 * @brief Recursively validate a parsed JSON value.
 *
 * Checks:
 *   - Nesting depth does not exceed maxDepth.
 *   - No binary-blob values (nlohmann binary extension).
 *
 * @param j         JSON value to validate.
 * @param maxDepth  Maximum permitted recursion depth (default: kMaxJsonDepth).
 * @return true if the value passes all checks, false otherwise.
 *
 * @note Does NOT detect duplicate keys at root — see file-level note.
 */
[[nodiscard]] bool
ValidateJson(const nlohmann::json& j, std::uint32_t maxDepth = kMaxJsonDepth) noexcept;

// ============================================================================
// TYPED FIELD ACCESSOR
// ============================================================================

/**
 * @brief Extract a named field from a JSON object with type checking.
 *
 * Instantiated for: std::string, std::int64_t, std::uint64_t, bool, double.
 * For unsupported T, a static_assert fires at compile time.
 *
 * @param j    JSON object to query.
 * @param key  Field name. Treated as a null-terminated string internally.
 * @return The field value wrapped in std::optional, or std::nullopt if:
 *           - j is not an object
 *           - the key is absent
 *           - the value's type does not match T
 *           - any internal exception occurs
 */
template<typename T>
[[nodiscard]] std::optional<T>
GetField(const nlohmann::json& j, std::string_view key) noexcept
{
    static_assert(
        std::is_same_v<T, std::string>   ||
        std::is_same_v<T, std::int64_t>  ||
        std::is_same_v<T, std::uint64_t> ||
        std::is_same_v<T, bool>          ||
        std::is_same_v<T, double>,
        "GetField<T>: unsupported type T — add a specialisation or use one of the "
        "five supported types: string, int64_t, uint64_t, bool, double."
    );

    if (!j.is_object()) return std::nullopt;

    // nlohmann::json::find requires a string; construct one from the view.
    const std::string keyStr(key);
    const auto it = j.find(keyStr);
    if (it == j.end()) return std::nullopt;

    try {
        if constexpr (std::is_same_v<T, std::string>) {
            if (!it->is_string()) return std::nullopt;
            return it->get<std::string>();
        } else if constexpr (std::is_same_v<T, bool>) {
            if (!it->is_boolean()) return std::nullopt;
            return it->get<bool>();
        } else if constexpr (std::is_same_v<T, std::int64_t>) {
            if (!it->is_number_integer()) return std::nullopt;
            return it->get<std::int64_t>();
        } else if constexpr (std::is_same_v<T, std::uint64_t>) {
            if (!it->is_number_unsigned()) return std::nullopt;
            return it->get<std::uint64_t>();
        } else if constexpr (std::is_same_v<T, double>) {
            if (!it->is_number()) return std::nullopt;
            return it->get<double>();
        }
    } catch (...) {
        // Defensive: nlohmann should not throw after the type guard above,
        // but we never let exceptions escape this utility on the hot path.
        return std::nullopt;
    }

    return std::nullopt;
}

} // namespace ShadowStrike::PhantomHome::IPC
