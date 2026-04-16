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
 * ShadowStrike NGAV - WEB PROTECTION COMMON TYPES
 * ============================================================================
 *
 * @file WebProtectionCommon.hpp
 * @brief Unified shared types for the WebProtection sub-system.
 *
 * Each WebProtection module (AdBlocker, BrowserProtection, ChromeExtensionScanner,
 * FirefoxAddonScanner, MaliciousDownloadBlocker, PhishingDetector, SafeBrowsingAPI,
 * TrackerBlocker) historically declared its own ModuleStatus / RequestType
 * enumerations. When the BrowserProtection orchestrator includes every sub-module
 * header in a single translation unit, those duplicates collide. This header
 * exposes the canonical definitions used by all modules so that one definition
 * exists per type per program.
 *
 * The unified ModuleStatus is a strict superset of every per-module variant.
 * The unified RequestType is a strict superset of the AdBlocker and
 * TrackerBlocker variants and exposes both the AdBlocker spelling
 * (XMLHTTPRequest, None) and the TrackerBlocker spelling (XMLHttpRequest,
 * Unknown) as enumerator aliases sharing the same numeric value.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_WEBBROWSER_WEBPROTECTIONCOMMON_HPP
#define SHADOWSTRIKE_WEBBROWSER_WEBPROTECTIONCOMMON_HPP

#include <cstdint>
#include <chrono>
#include <filesystem>

namespace ShadowStrike {
namespace WebBrowser {

// ============================================================================
// SHARED TYPE ALIASES
// ============================================================================

using Clock           = std::chrono::steady_clock;
using TimePoint       = Clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;

namespace fs = std::filesystem;

// ============================================================================
// UNIFIED MODULE STATUS
// ============================================================================

/**
 * @brief Lifecycle / runtime status for every WebProtection module.
 *
 * The values are a strict superset of every per-module status variant so
 * existing call sites like `m_status == ModuleStatus::Running` continue
 * to compile unchanged regardless of which module they originate in.
 */
enum class ModuleStatus : uint8_t {
    Uninitialized = 0,
    Initializing  = 1,
    Running       = 2,
    Processing    = 3,
    Filtering     = 4,
    Scanning      = 5,
    Updating      = 6,
    Analyzing     = 7,
    Degraded      = 8,
    Paused        = 9,
    Stopping      = 10,
    Stopped       = 11,
    Error         = 12
};

// ============================================================================
// UNIFIED REQUEST TYPE
// ============================================================================

/**
 * @brief Network request type, used by AdBlocker and TrackerBlocker.
 *
 * Bit-flag enum so callers can combine multiple request types in a single
 * filter mask. Both the "None" (AdBlocker) and "Unknown" (TrackerBlocker)
 * spellings of the zero value are exposed; both the "XMLHTTPRequest"
 * (AdBlocker) and "XMLHttpRequest" (TrackerBlocker) spellings are exposed
 * as aliases sharing the same bit position.
 */
enum class RequestType : uint32_t {
    Unknown          = 0,
    None             = 0,

    Document         = 1u << 0,
    SubDocument      = 1u << 1,
    Subdocument      = 1u << 1,
    Stylesheet       = 1u << 2,
    Script           = 1u << 3,
    Image            = 1u << 4,
    Font             = 1u << 5,
    Object           = 1u << 6,
    XMLHttpRequest   = 1u << 7,
    XMLHTTPRequest   = 1u << 7,
    Ping             = 1u << 8,
    Media            = 1u << 9,
    WebSocket        = 1u << 10,
    CSPReport        = 1u << 11,
    ObjectSubrequest = 1u << 12,
    Other            = 1u << 13,
    Popup            = 1u << 14,
    WebRTC           = 1u << 15,

    All              = 0xFFFFFFFFu
};

inline constexpr RequestType operator|(RequestType a, RequestType b) noexcept {
    return static_cast<RequestType>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline constexpr RequestType operator&(RequestType a, RequestType b) noexcept {
    return static_cast<RequestType>(
        static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline constexpr RequestType operator^(RequestType a, RequestType b) noexcept {
    return static_cast<RequestType>(
        static_cast<uint32_t>(a) ^ static_cast<uint32_t>(b));
}

inline constexpr RequestType operator~(RequestType a) noexcept {
    return static_cast<RequestType>(~static_cast<uint32_t>(a));
}

inline constexpr RequestType& operator|=(RequestType& a, RequestType b) noexcept {
    a = a | b;
    return a;
}

inline constexpr RequestType& operator&=(RequestType& a, RequestType b) noexcept {
    a = a & b;
    return a;
}

inline constexpr RequestType& operator^=(RequestType& a, RequestType b) noexcept {
    a = a ^ b;
    return a;
}

[[nodiscard]] inline constexpr bool HasRequestType(RequestType value, RequestType check) noexcept {
    return (static_cast<uint32_t>(value) & static_cast<uint32_t>(check)) != 0;
}

}  // namespace WebBrowser
}  // namespace ShadowStrike

#endif  // SHADOWSTRIKE_WEBBROWSER_WEBPROTECTIONCOMMON_HPP
