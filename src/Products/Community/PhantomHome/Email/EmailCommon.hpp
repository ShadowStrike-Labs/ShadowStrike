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
 * ShadowStrike NGAV - EMAIL COMMON TYPES
 * ============================================================================
 *
 * @file EmailCommon.hpp
 * @brief Shared type definitions for all Email subsystem modules.
 *
 * Centralizes types that were previously duplicated across EmailProtection,
 * AttachmentScanner, PhishingEmailDetector, SpamDetector, OutlookScanner,
 * and ThunderbirdScanner headers. This eliminates ODR violations caused by
 * multiple definitions of the same enum/alias in the ShadowStrike::Email
 * namespace.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <chrono>

namespace ShadowStrike {
namespace Email {

// ============================================================================
// SHARED TYPE ALIASES
// ============================================================================

using Clock           = std::chrono::steady_clock;
using TimePoint       = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// SHARED ENUMERATIONS
// ============================================================================

/**
 * @brief Unified module lifecycle status.
 *
 * Superset of all status values used across Email subsystem modules.
 * Individual modules may only transition through a subset of these states.
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Scanning        = 3,    ///< Actively scanning content
    Analyzing       = 4,    ///< Performing analysis (phishing/spam)
    Training        = 5,    ///< Training classifier (spam detector)
    Paused          = 6,
    Stopping        = 7,
    Stopped         = 8,
    Error           = 9
};

}  // namespace Email
}  // namespace ShadowStrike
