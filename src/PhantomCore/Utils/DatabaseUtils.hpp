/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 *
 * Stub header — full DatabaseUtils implementation is planned.
 * Provides minimal wrappers used by Forensics/IncidentRecorder.
 */
#pragma once

#include <string>
#include <string_view>

namespace ShadowStrike::Utils {
namespace DatabaseUtils {

/// @brief Escapes a string for safe SQL literal interpolation.
[[nodiscard]] inline std::string EscapeSql(std::string_view input) {
    std::string out;
    out.reserve(input.size());
    for (char c : input) {
        if (c == '\'') out += '\'';
        out += c;
    }
    return out;
}

/// @brief Validates a table name contains only safe characters.
[[nodiscard]] inline bool IsValidTableName(std::string_view name) {
    if (name.empty() || name.size() > 128) return false;
    for (char c : name) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_'))
            return false;
    }
    return true;
}

} // namespace DatabaseUtils
} // namespace ShadowStrike::Utils
