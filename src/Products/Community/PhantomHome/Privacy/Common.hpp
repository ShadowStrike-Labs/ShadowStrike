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
 * ShadowStrike NGAV - PRIVACY MODULE COMMON DEFINITIONS
 * ============================================================================
 *
 * @file Common.hpp
 * @brief Shared enumerations, type aliases, and utility functions used across
 *        all Privacy sub-modules to prevent ODR violations and ensure
 *        consistent type definitions.
 *
 * IMPORTANT: All Privacy modules MUST include this header instead of
 *            redefining ModuleStatus, BrowserType, or shared type aliases.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <optional>
#include <chrono>
#include <filesystem>
#include <algorithm>
#include <cctype>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <shlobj.h>
#endif

namespace ShadowStrike {
namespace Privacy {

// ============================================================================
// TYPE ALIASES (single definition for all Privacy modules)
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
namespace fs = std::filesystem;

// ============================================================================
// SHARED ENUMERATIONS
// ============================================================================

/**
 * @brief Module lifecycle status — shared across all Privacy modules.
 *
 * Previously each module defined its own identical enum, causing ODR
 * violations when linked into the same translation unit.
 */
enum class ModuleStatus : uint8_t {
    Uninitialized    = 0,
    Initializing     = 1,
    Running          = 2,
    Monitoring       = 3,
    Scanning         = 4,
    Ready            = 5,
    Cleaning         = 6,
    KillSwitchActive = 7,
    Paused           = 8,
    Stopping         = 9,
    Stopped          = 10,
    Error            = 11
};

/**
 * @brief Browser type — shared across CookieManager, PrivacyCleaner, and
 *        any module that enumerates browser profiles.
 */
enum class BrowserType : uint8_t {
    Unknown         = 0,
    Chrome          = 1,
    Firefox         = 2,
    Edge            = 3,
    Opera           = 4,
    Brave           = 5,
    Vivaldi         = 6,
    IE              = 7,
    Chromium        = 8,
    // Sentinel — keep this as the count of real browser types for array sizing
    _BrowserCount   = 9,
    All             = 255
};

/// @brief Safe array size for per-browser statistics
inline constexpr size_t BROWSER_ARRAY_SIZE = static_cast<size_t>(BrowserType::_BrowserCount);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get module status display name.
 */
[[nodiscard]] inline std::string_view GetModuleStatusName(ModuleStatus status) noexcept {
    switch (status) {
        case ModuleStatus::Uninitialized:    return "Uninitialized";
        case ModuleStatus::Initializing:     return "Initializing";
        case ModuleStatus::Running:          return "Running";
        case ModuleStatus::Monitoring:       return "Monitoring";
        case ModuleStatus::Scanning:         return "Scanning";
        case ModuleStatus::Ready:            return "Ready";
        case ModuleStatus::Cleaning:         return "Cleaning";
        case ModuleStatus::KillSwitchActive: return "KillSwitchActive";
        case ModuleStatus::Paused:           return "Paused";
        case ModuleStatus::Stopping:         return "Stopping";
        case ModuleStatus::Stopped:          return "Stopped";
        case ModuleStatus::Error:            return "Error";
        default:                          return "Unknown";
    }
}

/**
 * @brief Get browser type display name.
 */
[[nodiscard]] inline std::string_view GetBrowserTypeName(BrowserType browser) noexcept {
    switch (browser) {
        case BrowserType::Chrome:   return "Chrome";
        case BrowserType::Firefox:  return "Firefox";
        case BrowserType::Edge:     return "Edge";
        case BrowserType::Opera:    return "Opera";
        case BrowserType::Brave:    return "Brave";
        case BrowserType::Vivaldi:  return "Vivaldi";
        case BrowserType::IE:       return "Internet Explorer";
        case BrowserType::Chromium: return "Chromium";
        case BrowserType::All:      return "All";
        default:                    return "Unknown";
    }
}

/**
 * @brief Safe index for BrowserType into fixed-size arrays.
 * @return Index in [0, BROWSER_ARRAY_SIZE), or nullopt if out of range.
 */
[[nodiscard]] inline std::optional<size_t> BrowserTypeToIndex(BrowserType browser) noexcept {
    auto idx = static_cast<size_t>(browser);
    if (idx < BROWSER_ARRAY_SIZE) {
        return idx;
    }
    return std::nullopt;
}

// ============================================================================
// SECURE MEMORY HELPERS
// ============================================================================

/**
 * @brief Securely clear a string's contents before destruction.
 *        Uses volatile write to prevent compiler optimization.
 */
inline void SecureClearString(std::string& str) noexcept {
    if (!str.empty()) {
#ifdef _WIN32
        SecureZeroMemory(str.data(), str.size());
#else
        volatile char* p = str.data();
        for (size_t i = 0; i < str.size(); ++i) {
            p[i] = '\0';
        }
#endif
        str.clear();
    }
}

// ============================================================================
// DOMAIN UTILITIES
// ============================================================================

/**
 * @brief Sanitize a domain string: lowercase, strip leading dots,
 *        reject embedded null bytes or path traversal.
 * @return Sanitized domain, or empty string if invalid.
 */
[[nodiscard]] inline std::string SanitizeDomain(const std::string& domain) noexcept {
    if (domain.empty() || domain.size() > 253) {
        return {};
    }

    // Reject null bytes
    if (domain.find('\0') != std::string::npos) {
        return {};
    }

    // Reject path traversal
    if (domain.find("..") != std::string::npos ||
        domain.find('/') != std::string::npos ||
        domain.find('\\') != std::string::npos) {
        return {};
    }

    std::string result = domain;

    // Lowercase
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    // Strip leading dot
    while (!result.empty() && result[0] == '.') {
        result = result.substr(1);
    }

    // Strip trailing dot
    while (!result.empty() && result.back() == '.') {
        result.pop_back();
    }

    return result;
}

/**
 * @brief Escape regex metacharacters in a user-supplied string.
 */
[[nodiscard]] inline std::string EscapeRegex(const std::string& str) {
    static const std::string_view metacharacters = R"(\.^$|()[]{}*+?)";
    std::string escaped;
    escaped.reserve(str.size() * 2);

    for (char c : str) {
        if (metacharacters.find(c) != std::string_view::npos) {
            escaped += '\\';
        }
        escaped += c;
    }
    return escaped;
}

/**
 * @brief Convert a simple glob pattern (with * wildcards) to a regex pattern.
 *        Escapes all regex metacharacters except *, which becomes ".*".
 */
[[nodiscard]] inline std::string GlobToRegex(const std::string& glob) {
    std::string regex = "^";
    for (char c : glob) {
        if (c == '*') {
            regex += ".*";
        } else if (c == '?') {
            regex += '.';
        } else {
            // Escape metacharacters
            static const std::string_view meta = R"(\.^$|()[]{}+?)";
            if (meta.find(c) != std::string_view::npos) {
                regex += '\\';
            }
            regex += c;
        }
    }
    regex += '$';
    return regex;
}

// ============================================================================
// WIN32 SAFE HELPERS
// ============================================================================

#ifdef _WIN32

/**
 * @brief Safely retrieve a known folder path with error checking.
 * @return The path, or empty path on failure.
 */
[[nodiscard]] inline fs::path GetKnownFolderSafe(int csidl) noexcept {
    wchar_t buffer[MAX_PATH]{};
    HRESULT hr = SHGetFolderPathW(nullptr, csidl, nullptr, 0, buffer);
    if (FAILED(hr)) {
        return {};
    }
    return fs::path(buffer);
}

#endif // _WIN32

}  // namespace Privacy
}  // namespace ShadowStrike
